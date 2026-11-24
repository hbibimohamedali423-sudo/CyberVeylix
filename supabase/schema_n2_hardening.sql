-- CyberVeylix — PROPOSITION : durcissement RLS des appareils et des liens (N2). À VALIDER avant exécution.
-- Idempotent. À exécuter dans Supabase > SQL Editor, après schema_n2_prep.sql.
--
-- Problème constaté (testé) : les politiques « devices » et « links » vérifient seulement que la LIGNE
-- appartient à l'utilisateur, pas que le RÉSEAU ou les APPAREILS qu'elle référence lui appartiennent.
-- Les clés étrangères étant vérifiées sans RLS, un compte B pouvait rattacher ses appareils au réseau
-- d'un compte A, ou créer des liens vers les appareils de A (s'il connaît leurs identifiants).
-- Même principe que schema_hardening.sql (services) et schema_n2_prep.sql (alerts).
-- Effet pour un utilisateur normal : aucun (il ne référence que ses propres réseaux et appareils).

drop policy if exists "devices: propriétaire" on public.devices;
create policy "devices: propriétaire" on public.devices
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and (network_id is null or exists (
      select 1 from public.networks n
      where n.id = devices.network_id and n.user_id = (select auth.uid())))
  );

drop policy if exists "links: propriétaire" on public.links;
create policy "links: propriétaire" on public.links
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and exists (select 1 from public.networks n
                where n.id = links.network_id and n.user_id = (select auth.uid()))
    and exists (select 1 from public.devices d
                where d.id = links.from_device_id and d.user_id = (select auth.uid()))
    and exists (select 1 from public.devices d
                where d.id = links.to_device_id and d.user_id = (select auth.uid()))
  );

-- Index utiles aux vérifications ci-dessus.
create index if not exists links_user_idx on public.links(user_id);
create index if not exists networks_user_idx on public.networks(user_id);
