-- CyberVeylix — R4 : commandes envoyées au capteur, adresses bloquées, origine des attaques.
-- Idempotent. À exécuter dans Supabase > SQL Editor, après schema_r1_results.sql.
-- N'ajoute que des colonnes, deux tables et leurs politiques : aucune donnée existante n'est modifiée ni supprimée,
-- aucune politique existante n'est touchée.
--
-- Principe : la page web n'exécute RIEN sur le réseau. Elle écrit une demande dans sensor_commands ;
-- le capteur installé sur le PC permanent la lit, l'exécute lui-même et écrit le résultat.
-- Les types de commande sont fermés (liste blanche ci-dessous) : aucune commande libre n'est possible.

-- 1) alerts : adresse de l'appareil fautif (pour « bloquer cette adresse ») ---------------------------------
alter table public.alerts add column if not exists source_ip text;
alter table public.alerts add column if not exists source_mac text;
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'alerts_source_ip_check') then
    alter table public.alerts add constraint alerts_source_ip_check
      check (source_ip is null or source_ip ~ '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$');
  end if;
  if not exists (select 1 from pg_constraint where conname = 'alerts_source_mac_check') then
    alter table public.alerts add constraint alerts_source_mac_check
      check (source_mac is null or source_mac ~ '^([0-9a-f]{2}:){5}[0-9a-f]{2}$');
  end if;
end $$;
create index if not exists alerts_source_ip_idx on public.alerts(user_id, source_ip) where source_ip is not null;

-- 2) sensors : réglages pilotés depuis la page « Paramètres » -----------------------------------------------
alter table public.sensors add column if not exists auto_block boolean not null default false;  -- blocage automatique des attaquants
alter table public.sensors add column if not exists trusted_ips text[];                          -- adresses à ne jamais bloquer
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'sensors_trusted_ips_check') then
    alter table public.sensors add constraint sensors_trusted_ips_check
      check (trusted_ips is null or coalesce(array_length(trusted_ips, 1), 0) <= 100);
  end if;
end $$;

-- 3) sensor_commands : demandes de la page au capteur ------------------------------------------------------
create table if not exists public.sensor_commands (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  sensor_id uuid not null references public.sensors(id) on delete cascade,
  kind text not null check (kind in ('scan_now', 'block_ip', 'unblock_ip', 'fix')),
  params jsonb not null default '{}'::jsonb,
  status text not null default 'pending' check (status in ('pending', 'running', 'done', 'failed', 'rejected')),
  result text,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz,
  constraint sensor_commands_params_object check (jsonb_typeof(params) = 'object' and length(params::text) <= 2000),
  constraint sensor_commands_result_len check (result is null or length(result) <= 4000),
  -- Adresse valide, hors 0.x, 127.x et 224.x–255.x (multicast, diffusion) : jamais bloquable.
  constraint sensor_commands_ip_check check (
    kind not in ('block_ip', 'unblock_ip')
    or (params ->> 'ip') ~ '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$'
       and (params ->> 'ip') !~ '^(0\.|127\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)'),
  -- Une correction est un identifiant de la liste connue du capteur, jamais un script.
  constraint sensor_commands_fix_check check (kind <> 'fix' or (params ->> 'id') ~ '^[a-z0-9_]{1,40}$')
);
create index if not exists sensor_commands_queue_idx on public.sensor_commands(sensor_id, status, created_at);
create index if not exists sensor_commands_user_idx on public.sensor_commands(user_id, created_at desc);

alter table public.sensor_commands enable row level security;
drop policy if exists "sensor_commands: propriétaire" on public.sensor_commands;
create policy "sensor_commands: propriétaire" on public.sensor_commands
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and exists (select 1 from public.sensors s where s.id = sensor_commands.sensor_id and s.user_id = (select auth.uid()))
  );

-- 4) blocked_ips : adresses bloquées par le capteur (pare-feu du PC qui l'héberge) -------------------------
create table if not exists public.blocked_ips (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  sensor_id uuid not null references public.sensors(id) on delete cascade,
  ip text not null
    check (ip ~ '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$'
           and ip !~ '^(0\.|127\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)'),
  reason text,
  alert_id uuid references public.alerts(id) on delete set null,
  blocked_by text not null default 'manual' check (blocked_by in ('manual', 'auto')),
  status text not null default 'active' check (status in ('active', 'released', 'failed')),
  error text,
  blocked_at timestamptz not null default now(),
  released_at timestamptz,
  constraint blocked_ips_reason_len check (reason is null or length(reason) <= 500),
  constraint blocked_ips_error_len check (error is null or length(error) <= 1000)
);
-- Une adresse n'est « active » qu'une fois par capteur : un second blocage met à jour, il ne duplique pas.
create unique index if not exists blocked_ips_active_uq on public.blocked_ips(sensor_id, ip) where status = 'active';
create index if not exists blocked_ips_user_idx on public.blocked_ips(user_id, blocked_at desc);

alter table public.blocked_ips enable row level security;
drop policy if exists "blocked_ips: propriétaire" on public.blocked_ips;
create policy "blocked_ips: propriétaire" on public.blocked_ips
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and exists (select 1 from public.sensors s where s.id = blocked_ips.sensor_id and s.user_id = (select auth.uid()))
    and (alert_id is null or exists (select 1 from public.alerts a where a.id = blocked_ips.alert_id and a.user_id = (select auth.uid())))
  );
