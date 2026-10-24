-- CyberVeylix — alertes et menaces (à exécuter dans le SQL Editor du projet CyberVeylix)

create table if not exists public.alerts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  title text not null,
  detail text,
  severity text not null check (severity in ('c','h','m','l')),
  created_at timestamptz not null default now()
);

create table if not exists public.threats (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  category text not null check (category in ('intrusion','malware','scan','c2','autre')),
  blocked boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.alerts enable row level security;
alter table public.threats enable row level security;

create policy "alerts: propriétaire" on public.alerts
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy "threats: propriétaire" on public.threats
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
