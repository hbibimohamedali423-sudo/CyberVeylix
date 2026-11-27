-- CyberVeylix — R9 : stockage de la matrice d'atteignabilité VLAN-à-VLAN (FortiGate, lecture seule).
-- PROPOSITION À VALIDER — rien n'est appliqué par Claude : à exécuter vous-même dans Supabase > SQL
-- Editor, après schema_r8_sharing.sql, si vous approuvez ce schéma. Idempotent : sur une base qui
-- l'a déjà, ce fichier ne change rien. N'ajoute qu'une table et des politiques : aucune donnée
-- existante n'est modifiée ni supprimée.
--
-- Une ligne = un résultat déjà calculé par sensor/lib/reachability.mjs (« le VLAN A peut-il joindre
-- le VLAN B ? »), jamais une donnée recalculée côté base : Supabase ne fait que stocker ce que le
-- capteur a déjà déterminé, avec la ou les règles de pare-feu exactes comme preuve (evidence).
-- Une seule ligne par paire de zones et par réseau : l'interrogation suivante MET À JOUR cette ligne
-- (upsert sur la contrainte unique ci-dessous) au lieu d'empiler un historique — c'est l'état actuel
-- de la segmentation qui compte pour le tableau de bord, pas son journal.

create table if not exists public.vlan_reachability (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  network_id uuid not null references public.networks(id) on delete cascade,
  sensor_id uuid references public.sensors(id) on delete set null,
  from_zone text not null,          -- nom de l'interface/VLAN lu sur le pare-feu, ex. « vlan20 »
  to_zone text not null,
  from_vlan integer,                 -- identifiant VLAN numérique si connu (peut être absent : interface hors VLAN)
  to_vlan integer,
  status text not null check (status in ('allowed', 'blocked', 'uncertain')),
  reason text,                       -- raison en français déjà produite par reachability.mjs
  evidence jsonb,                    -- règle(s) exacte(s) utilisée(s) : [{ "id": "...", "name": "..." }, ...]
  source text not null default 'fortigate' check (source in ('fortigate')),
  computed_at timestamptz not null default now(),  -- date du calcul par le capteur (pas forcément « maintenant »)
  created_at timestamptz not null default now(),
  unique (user_id, network_id, from_zone, to_zone),
  check (from_zone <> to_zone)
);
create index if not exists vlan_reachability_network_idx on public.vlan_reachability(network_id);

alter table public.vlan_reachability enable row level security;
drop policy if exists "vlan_reachability: propriétaire" on public.vlan_reachability;
create policy "vlan_reachability: propriétaire" on public.vlan_reachability
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and exists (
      select 1 from public.networks n
      where n.id = vlan_reachability.network_id and n.user_id = (select auth.uid()))
    and (sensor_id is null or exists (
      select 1 from public.sensors s
      where s.id = vlan_reachability.sensor_id and s.user_id = (select auth.uid())))
  );

-- Note pour l'étape suivante (code, pas SQL) : à chaque interrogation du pare-feu, le capteur doit
-- aussi supprimer les lignes d'un réseau qui n'apparaissent plus dans la matrice qu'il vient de
-- calculer (ex. un VLAN retiré du pare-feu) — un simple « delete … where network_id = … and
-- computed_at < ce_cycle » avant l'upsert, pour que la table ne garde jamais une paire obsolète.
--
-- Note facultative (partage) : si vous utilisez le partage de compte en lecture seule
-- (schema_r8_sharing.sql), ajouter 'vlan_reachability' à la liste des tables de sa boucle donnerait
-- au prestataire la même lecture sur cette table que sur les autres — à faire séparément, et
-- seulement si vous le souhaitez, ce fichier n'y touche pas.
