# CyberVeylix

Tableau de bord réseau & cybersécurité (React + Vite), interface en français.

## Démarrage
```
npm install
npm run dev
```

## Données
Aucune donnée de démonstration. Appareils et vulnérabilités saisis manuellement
sont gardés dans le navigateur (localStorage) en attendant la connexion à Supabase.

## Supabase (à venir)
1. Créer un projet Supabase dédié à CyberVeylix.
2. Relire puis exécuter `supabase/schema.sql` dans le SQL Editor.
3. Copier `.env.example` vers `.env` et renseigner l’URL et la clé anon.
Ne jamais committer `.env` ni une clé `service_role`.
