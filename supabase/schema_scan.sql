-- CyberVeylix — support de l'agent de découverte réseau (à exécuter dans le SQL Editor)

alter table public.devices add column if not exists mac text;
alter table public.devices add column if not exists last_seen timestamptz;

create table if not exists public.services (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  device_id uuid not null references public.devices(id) on delete cascade,
  port integer not null check (port between 1 and 65535),
  protocol text not null default 'tcp',
  service text,
  created_at timestamptz not null default now()
);

create index if not exists services_device_idx on public.services(device_id);

alter table public.services enable row level security;

create policy "services: propriétaire" on public.services
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
