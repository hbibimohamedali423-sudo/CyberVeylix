-- CyberVeylix — schéma initial (à relire puis exécuter manuellement dans le SQL Editor
-- d’un projet Supabase DÉDIÉ à CyberVeylix). Non appliqué automatiquement.

create table if not exists public.devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name text not null,
  ip text,
  type text not null check (type in ('Serveur','Poste','Caméra','Équipement réseau','Accès Internet')),
  status text not null default 'un' check (status in ('on','off','un')),
  created_at timestamptz not null default now()
);

create table if not exists public.vulnerabilities (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  title text not null,
  severity text not null check (severity in ('c','h','m','l')),
  device_id uuid references public.devices(id) on delete set null,
  created_at timestamptz not null default now()
);

alter table public.devices enable row level security;
alter table public.vulnerabilities enable row level security;

create policy "devices: propriétaire" on public.devices
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy "vulnerabilities: propriétaire" on public.vulnerabilities
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
