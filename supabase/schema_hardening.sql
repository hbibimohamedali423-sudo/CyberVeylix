-- CyberVeylix — durcissement RLS et intégrité (idempotent : peut être relancé sans risque)
-- À exécuter dans Supabase > SQL Editor, AVANT d'utiliser le nouvel agent/scan.mjs.

-- services : l'appareil doit appartenir à l'utilisateur
drop policy if exists "services: propriétaire" on public.services;
create policy "services: propriétaire" on public.services
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and exists (select 1 from public.devices d
                where d.id = services.device_id and d.user_id = (select auth.uid()))
  );

-- vulnerabilities : idem (device_id peut rester nul)
drop policy if exists "vulnerabilities: propriétaire" on public.vulnerabilities;
create policy "vulnerabilities: propriétaire" on public.vulnerabilities
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and (device_id is null or exists (
      select 1 from public.devices d
      where d.id = vulnerabilities.device_id and d.user_id = (select auth.uid())))
  );

-- alerts : lien optionnel vers l'appareil (remplace la correspondance texte sur l'IP)
alter table public.alerts
  add column if not exists device_id uuid references public.devices(id) on delete set null;

drop policy if exists "alerts: propriétaire" on public.alerts;
create policy "alerts: propriétaire" on public.alerts
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and (device_id is null or exists (
      select 1 from public.devices d
      where d.id = alerts.device_id and d.user_id = (select auth.uid())))
  );

-- Nécessaire pour l'upsert de l'agent
create unique index if not exists services_device_port_uq
  on public.services(device_id, port, protocol);

-- Index pour RLS et tris
create index if not exists devices_user_idx on public.devices(user_id);
create index if not exists services_user_idx on public.services(user_id);
create index if not exists vulnerabilities_user_idx on public.vulnerabilities(user_id);
create index if not exists vulnerabilities_device_idx on public.vulnerabilities(device_id);
create index if not exists alerts_user_created_idx on public.alerts(user_id, created_at desc);
create index if not exists alerts_device_idx on public.alerts(device_id);
create index if not exists threats_user_idx on public.threats(user_id);
