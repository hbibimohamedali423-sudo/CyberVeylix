-- CyberVeylix — suivi des alertes et des vulnérabilités (statut, dates, note).
-- Colonnes utilisées par les pages « Menaces & Incidents » et « Vulnérabilités » (boutons
-- « Prise en compte » / « Résoudre », note) et par les exports CSV, absentes des scripts précédents.
-- Idempotent : peut être relancé sans risque. À exécuter dans Supabase > SQL Editor, après schema_hardening.sql.
-- Les politiques RLS existantes (propriétaire uniquement) couvrent automatiquement ces nouvelles colonnes.

-- alerts --------------------------------------------------------------------------------------
alter table public.alerts add column if not exists status text not null default 'open';
alter table public.alerts add column if not exists acknowledged_at timestamptz;
alter table public.alerts add column if not exists resolved_at timestamptz;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'alerts_status_check') then
    alter table public.alerts
      add constraint alerts_status_check check (status in ('open', 'ack', 'resolved'));
  end if;
end $$;

-- vulnerabilities ---------------------------------------------------------------------------------
alter table public.vulnerabilities add column if not exists status text not null default 'open';
alter table public.vulnerabilities add column if not exists acknowledged_at timestamptz;
alter table public.vulnerabilities add column if not exists resolved_at timestamptz;
alter table public.vulnerabilities add column if not exists note text;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'vulnerabilities_status_check') then
    alter table public.vulnerabilities
      add constraint vulnerabilities_status_check check (status in ('open', 'ack', 'resolved'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'vulnerabilities_note_length') then
    alter table public.vulnerabilities
      add constraint vulnerabilities_note_length check (note is null or char_length(note) <= 2000);
  end if;
end $$;

-- Index pour les filtres par statut des deux pages.
create index if not exists alerts_user_status_idx on public.alerts(user_id, status);
create index if not exists vulnerabilities_user_status_idx on public.vulnerabilities(user_id, status);
