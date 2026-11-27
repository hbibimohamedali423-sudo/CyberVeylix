-- CyberVeylix — R1 : résultats du capteur et de l'analyse dans l'application. PROPOSITION À VALIDER.
-- Idempotent. À exécuter dans Supabase > SQL Editor, après schema_n2_hardening.sql.
-- N'ajoute que des colonnes, une table et des politiques : aucune donnée n'est supprimée ni modifiée.

-- 1) vulnerabilities : détails des faiblesses trouvées par l'analyse -----------------------------------
alter table public.vulnerabilities add column if not exists source text not null default 'manual';
alter table public.vulnerabilities add column if not exists finding_key text;   -- « ip:port:règle », stable entre analyses
alter table public.vulnerabilities add column if not exists cves text[];
alter table public.vulnerabilities add column if not exists evidence text;
alter table public.vulnerabilities add column if not exists remediation text;
alter table public.vulnerabilities add column if not exists confidence text;
alter table public.vulnerabilities add column if not exists port integer;
alter table public.vulnerabilities add column if not exists service text;
alter table public.vulnerabilities add column if not exists last_seen timestamptz;
alter table public.vulnerabilities
  add column if not exists network_id uuid references public.networks(id) on delete set null;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'vulnerabilities_source_check') then
    alter table public.vulnerabilities add constraint vulnerabilities_source_check
      check (source in ('manual', 'scan'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'vulnerabilities_confidence_check') then
    alter table public.vulnerabilities add constraint vulnerabilities_confidence_check
      check (confidence is null or confidence in ('certaine', 'probable', 'à vérifier'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'vulnerabilities_port_check') then
    alter table public.vulnerabilities add constraint vulnerabilities_port_check
      check (port is null or port between 1 and 65535);
  end if;
end $$;

-- Une même faiblesse (même appareil, port et règle) n'existe qu'une fois par compte : l'analyse suivante
-- la met à jour au lieu de la dupliquer. Les saisies manuelles (finding_key vide) ne sont pas concernées.
create unique index if not exists vulnerabilities_user_finding_uq on public.vulnerabilities(user_id, finding_key);
create index if not exists vulnerabilities_network_idx on public.vulnerabilities(network_id);

-- Le réseau référencé doit appartenir à l'utilisateur, comme l'appareil (même principe que N2).
drop policy if exists "vulnerabilities: propriétaire" on public.vulnerabilities;
create policy "vulnerabilities: propriétaire" on public.vulnerabilities
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and (device_id is null or exists (
      select 1 from public.devices d
      where d.id = vulnerabilities.device_id and d.user_id = (select auth.uid())))
    and (network_id is null or exists (
      select 1 from public.networks n
      where n.id = vulnerabilities.network_id and n.user_id = (select auth.uid())))
  );

-- 2) alerts : origine et type d'événement ---------------------------------------------------------------
alter table public.alerts add column if not exists source text not null default 'manual';
alter table public.alerts add column if not exists kind text;   -- ex. gateway_spoof, honeypot_scan, vuln_new
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'alerts_source_check') then
    alter table public.alerts add constraint alerts_source_check
      check (source in ('manual', 'agent', 'sensor', 'honeypot', 'vuln_scan'));
  end if;
end $$;

-- 3) services : version annoncée par le service ---------------------------------------------------------
alter table public.services add column if not exists version text;
alter table public.services add column if not exists last_seen timestamptz;

-- 4) sensors : état de chaque capteur installé (« en service depuis… », « arrêté ») ----------------------
create table if not exists public.sensors (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  network_id uuid references public.networks(id) on delete set null,
  name text not null,                      -- nom du PC qui héberge le capteur
  version text,
  ip text,
  honeypot boolean not null default false,
  vuln_scan boolean not null default false,
  started_at timestamptz,
  last_heartbeat timestamptz,
  last_scan_at timestamptz,
  created_at timestamptz not null default now(),
  unique (user_id, name)
);
create index if not exists sensors_network_idx on public.sensors(network_id);

alter table public.sensors enable row level security;
drop policy if exists "sensors: propriétaire" on public.sensors;
create policy "sensors: propriétaire" on public.sensors
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and (network_id is null or exists (
      select 1 from public.networks n
      where n.id = sensors.network_id and n.user_id = (select auth.uid())))
  );
