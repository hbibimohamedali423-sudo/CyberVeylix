-- CyberVeylix — R7 : historique des rapports produits depuis la page « Rapports ». Idempotent.
-- reports.kind acceptait les exports CSV (devices, alerts, vulnerabilities, threats) ; on ajoute « security » pour le
-- rapport de sécurité imprimé / PDF. Aucune donnée n'est modifiée ni supprimée.
-- Table créée hors de ce dépôt à l'origine : décrite ici à l'identique pour une base neuve (sans effet sur la base en
-- service : « if not exists », politique créée seulement si absente).
create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  kind text not null,
  row_count integer not null default 0,
  created_at timestamptz not null default now()
);
alter table public.reports enable row level security;
do $$
begin
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'reports') then
    create policy "reports: propriétaire" on public.reports for all to authenticated
      using (user_id = auth.uid()) with check (user_id = auth.uid());
  end if;
end $$;

alter table public.reports drop constraint if exists reports_kind_check;
alter table public.reports add constraint reports_kind_check
  check (kind in ('devices', 'alerts', 'vulnerabilities', 'threats', 'security'));
create index if not exists reports_user_created_idx on public.reports(user_id, created_at desc);
