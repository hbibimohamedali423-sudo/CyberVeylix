-- CyberVeylix — R8 : un client partage ses données EN LECTURE SEULE avec le compte de son prestataire. Idempotent.
-- - account_shares : qui partage (owner) avec qui (viewer). Créé uniquement par la fonction share_account_with.
-- - Une politique « lecture partagée » (SELECT seulement) s'ajoute aux politiques « propriétaire » existantes, qui
--   ne sont pas modifiées : le prestataire voit, il ne modifie rien. Le partage se retire à tout moment.
-- Aucune donnée existante n'est modifiée ni supprimée.

create table if not exists public.account_shares (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  viewer_id uuid not null references auth.users(id) on delete cascade,
  owner_email text,
  viewer_email text,
  created_at timestamptz not null default now(),
  unique (owner_id, viewer_id),
  check (owner_id <> viewer_id)
);
create index if not exists account_shares_viewer_idx on public.account_shares(viewer_id, owner_id);

alter table public.account_shares enable row level security;
drop policy if exists "account_shares: lecture" on public.account_shares;
create policy "account_shares: lecture" on public.account_shares for select to authenticated
  using (owner_id = (select auth.uid()) or viewer_id = (select auth.uid()));
-- Le client retire un partage, ou le prestataire renonce à un accès. Pas d'insertion directe : fonction ci-dessous.
drop policy if exists "account_shares: retrait" on public.account_shares;
create policy "account_shares: retrait" on public.account_shares for delete to authenticated
  using (owner_id = (select auth.uid()) or viewer_id = (select auth.uid()));

-- Partage avec le compte d'une adresse e-mail (réservé aux comptes connectés). Ne crée aucun compte.
create or replace function public.share_account_with(viewer_email text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := auth.uid();
  target uuid;
begin
  if me is null then raise exception 'Connexion requise.'; end if;
  select u.id into target from auth.users u where lower(u.email) = lower(trim(viewer_email)) limit 1;
  if target is null then raise exception 'Aucun compte CyberVeylix avec cette adresse e-mail.'; end if;
  if target = me then raise exception 'Impossible de partager avec votre propre compte.'; end if;
  insert into public.account_shares (owner_id, viewer_id, owner_email, viewer_email)
  values (me, target, (select u.email from auth.users u where u.id = me), (select u.email from auth.users u where u.id = target))
  on conflict (owner_id, viewer_id) do nothing;
end $$;
revoke all on function public.share_account_with(text) from public, anon;
grant execute on function public.share_account_with(text) to authenticated;

-- Lecture partagée sur chaque table de données (SELECT uniquement).
do $$
declare t text;
begin
  foreach t in array array['devices', 'alerts', 'vulnerabilities', 'threats', 'services', 'networks', 'links',
                           'sensors', 'sensor_commands', 'blocked_ips', 'reports'] loop
    execute format('drop policy if exists %I on public.%I', t || ': lecture partagée', t);
    execute format('create policy %I on public.%I for select to authenticated using (exists (select 1 from public.account_shares s where s.owner_id = %I.user_id and s.viewer_id = (select auth.uid())))',
      t || ': lecture partagée', t, t);
  end loop;
end $$;
