-- CyberVeylix — N1 : réseaux, liens de topologie et colonnes d'inventaire des appareils.
-- Reproduit à l'identique la structure créée directement dans Supabase (relevée le 24/11/2026),
-- pour qu'une base neuve puisse être construite depuis les fichiers du dépôt.
-- Idempotent : sur une base qui l'a déjà, il ne change rien.
-- Ordre : schema.sql, schema_alerts.sql, schema_scan.sql, schema_hardening.sql,
--         PUIS ce fichier, puis schema_n2_prep.sql, puis schema_status.sql.

-- networks ---------------------------------------------------------------------------------------
create table if not exists public.networks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name text not null,
  cidr text,
  gateway_ip text,
  gateway_mac text,
  ssid text,
  scan_allowed boolean not null default false,
  first_seen timestamptz not null default now(),
  last_seen timestamptz,
  created_at timestamptz not null default now()
);

alter table public.networks enable row level security;
drop policy if exists "networks: propriétaire" on public.networks;
create policy "networks: propriétaire" on public.networks
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- devices : rattachement au réseau et inventaire -----------------------------------------------------
alter table public.devices
  add column if not exists network_id uuid references public.networks(id) on delete set null;
alter table public.devices add column if not exists role text;
alter table public.devices add column if not exists role_evidence text;
alter table public.devices add column if not exists discovery_source text;
alter table public.devices add column if not exists hostname text;
alter table public.devices add column if not exists vendor text;
alter table public.devices add column if not exists model text;
alter table public.devices add column if not exists firmware text;
alter table public.devices add column if not exists serial text;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'devices_role_check') then
    alter table public.devices add constraint devices_role_check check (
      role is null or role in ('gateway', 'switch', 'access_point', 'server', 'workstation', 'printer', 'camera', 'iot', 'other'));
  end if;
end $$;

-- links : liens entre appareils (topologie) ----------------------------------------------------------
-- « status » est créé ici avec la contrainte exacte de la base en service (« status is null or … ») :
-- schema_n2_prep.sql l'ajoute aussi, mais « add column if not exists » le laisse alors intact.
create table if not exists public.links (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  network_id uuid not null references public.networks(id) on delete cascade,
  from_device_id uuid not null references public.devices(id) on delete cascade,
  to_device_id uuid not null references public.devices(id) on delete cascade,
  from_port text,
  to_port text,
  medium text check (medium is null or medium in ('ethernet', 'wifi', 'unknown')),
  vlan text,
  source text not null check (source in ('manual', 'snmp', 'lldp', 'cdp', 'fdb', 'arp', 'traceroute')),
  evidence text,
  status text check (status is null or status in ('observed', 'inferred', 'declared')),
  observed_at timestamptz not null default now(),
  first_seen timestamptz not null default now(),
  last_seen timestamptz,
  created_at timestamptz not null default now(),
  check (from_device_id <> to_device_id)
);

alter table public.links enable row level security;
drop policy if exists "links: propriétaire" on public.links;
create policy "links: propriétaire" on public.links
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
