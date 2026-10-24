# CyberVeylix

Tableau de bord réseau & cybersécurité (React + Vite + Supabase), interface en français.

## Démarrage
```
npm install
npm run dev
```

## Supabase
1. Projet Supabase dédié à CyberVeylix.
2. Exécuter `supabase/schema.sql` dans le SQL Editor (tables `devices` et `vulnerabilities`, RLS par utilisateur).
3. Copier `.env.example` vers `.env` et renseigner `VITE_SUPABASE_URL` et `VITE_SUPABASE_ANON_KEY` (clé publique uniquement).
4. Relancer `npm run dev`, créer un compte, se connecter.

Ne jamais committer `.env` ni une clé `service_role`.
Aucune donnée de démonstration : tout ce qui est affiché vient de la base ou de la saisie de l’utilisateur.
