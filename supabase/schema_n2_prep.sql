-- CyberVeylix — préparation N2 (idempotent : peut être relancé sans risque)
-- À exécuter dans Supabase > SQL Editor.

-- 0) Garde-fou : on s'arrête si les tables attendues n'ont pas la colonne user_id
do $$
begin
  if not exists (select 1 from information_schema.columns
                 where table_schema = 'public' and table_name = 'networks' and column_name = 'user_id') then
    raise exception 'ARRET : networks.user_id est introuvable. Rien n''a ete modifie.';
  end if;
  if not exists (select 1 from information_schema.tables
                 where table_schema = 'public' and table_name = 'links') then
    raise exception 'ARRET : la table links est introuvable. Rien n''a ete modifie.';
  end if;
end $$;

-- 1) type nullable : « inconnu » au lieu d'inventer « Poste »
alter table public.devices alter column type drop not null;

-- 2) alertes rattachées à un réseau, avec RLS qui vérifie la propriété
alter table public.alerts
  add column if not exists network_id uuid references public.networks(id) on delete set null;
create index if not exists alerts_network_idx on public.alerts(network_id);

drop policy if exists "alerts: propriétaire" on public.alerts;
create policy "alerts: propriétaire" on public.alerts
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and (device_id is null or exists (
      select 1 from public.devices d
      where d.id = alerts.device_id and d.user_id = (select auth.uid())))
    and (network_id is null or exists (
      select 1 from public.networks n
      where n.id = alerts.network_id and n.user_id = (select auth.uid())))
  );

-- 3) links : statut et horodatage (nullable : aucune valeur par défaut qui prétende « observé »)
alter table public.links
  add column if not exists status text check (status in ('observed','inferred','declared'));
alter table public.links add column if not exists first_seen timestamptz;
alter table public.links add column if not exists last_seen timestamptz;

-- 4) index
create index if not exists devices_network_idx on public.devices(network_id);
create index if not exists links_network_idx on public.links(network_id);
