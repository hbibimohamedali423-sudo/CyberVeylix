# CyberVeylix project rules (read first)
- Stack: React 19 + Vite + Supabase. French UI. Keep the existing architecture; never rebuild from scratch.
- Never read, print, edit or commit .env or agent/.env. Never expose secrets.
- Do not modify the Supabase schema, RLS policies or auth. Propose SQL in a separate file and wait for approval.
- Do not run git commit/push/reset or switch branches. The owner commits.
- No invented data: devices, alerts, vulnerabilities and metrics must come from stored records.
- Scanner (agent/scan.mjs): private ranges only, explicit --yes authorization. No public-IP scanning, exploitation or brute force. No Node-only scanning in the React frontend.
- Work in small phases. Before editing, present a short plan and wait for approval.
- After each phase run `npm run lint` and `npm run build`, and report the real output (never claim an untested pass). List files changed.
- Never read or print agent/snmp.json (SNMP credentials).
