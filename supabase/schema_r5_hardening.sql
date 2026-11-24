-- CyberVeylix — R5 : durcissement signalé par l'analyseur de sécurité Supabase. Idempotent.
-- public.rls_auto_enable() est la fonction du déclencheur d'événement « ensure_rls » : elle active RLS sur chaque
-- nouvelle table du schéma public. Elle n'a pas à être appelable depuis l'API (/rest/v1/rpc/rls_auto_enable).
-- On retire seulement le droit d'appel à public / anon / authenticated : le déclencheur continue de fonctionner.
-- Aucune table, donnée ou politique n'est modifiée.
revoke execute on function public.rls_auto_enable() from public, anon, authenticated;

-- Index de la clé étrangère blocked_ips.alert_id (ajoutée en R4), signalé par l'analyseur de performances.
create index if not exists blocked_ips_alert_idx on public.blocked_ips(alert_id);
