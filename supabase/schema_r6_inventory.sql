-- CyberVeylix — R6 : inventaire et identification des appareils par le capteur. Idempotent.
-- N'ajoute que des valeurs autorisées et une colonne : aucune donnée existante n'est modifiée ni supprimée.

-- 1) Rôle « phone » (téléphone / tablette) en plus des rôles existants.
alter table public.devices drop constraint if exists devices_role_check;
alter table public.devices add constraint devices_role_check check (role is null or role in
  ('gateway', 'switch', 'access_point', 'server', 'workstation', 'printer', 'camera', 'iot', 'phone', 'other'));

-- 2) Types affichés (libellés français stockés) : Téléphone, Imprimante, Objet connecté en plus des cinq existants.
alter table public.devices drop constraint if exists devices_type_check;
alter table public.devices add constraint devices_type_check check (type is null or type in
  ('Serveur', 'Poste', 'Caméra', 'Équipement réseau', 'Accès Internet', 'Téléphone', 'Imprimante', 'Objet connecté'));

-- 3) Confiance de l'identification automatique (même vocabulaire que les vulnérabilités).
alter table public.devices add column if not exists role_confidence text;
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'devices_role_confidence_check') then
    alter table public.devices add constraint devices_role_confidence_check
      check (role_confidence is null or role_confidence in ('certaine', 'probable', 'à vérifier'));
  end if;
end $$;

-- 4) Index utiles au capteur (appareils d'un réseau, recherche par MAC).
create index if not exists devices_network_mac_idx on public.devices(network_id, mac);
