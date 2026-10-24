# Agent de découverte réseau CyberVeylix

Inventorie les appareils de **votre** réseau local et les envoie à votre compte CyberVeylix.

## Ce qu'il fait
- Ping + table ARP sur une plage privée (10/8, 172.16/12, 192.168/16, de /22 à /30).
- Connexion TCP simple sur ~23 ports courants (aucune exploitation, aucun envoi de données).
- Met à jour `devices` (statut, MAC, dernier vu) et `services` (ports ouverts).
- Les appareils de la plage non vus passent « Hors ligne ».

## Alertes automatiques
- « Nouvel appareil détecté » quand une adresse inconnue apparaît.
- « Port … ouvert » quand un port sensible (Telnet, FTP, RDP, VNC, bases de données) s'ouvre sur un appareil.
- Le premier inventaire d'une plage sert de référence : aucune alerte n'est créée.
- `--no-alerts` désactive les alertes pour un lancement.
- `--check` vérifie la configuration et la connexion sans scanner.

## Ce qu'il ne fait pas
Il ne détecte pas de vulnérabilités (CVE) et ne bloque aucune menace.

## Utilisation
1. Exécuter `supabase/schema_scan.sql` dans Supabase.
2. Copier `agent/.env.example` vers `agent/.env` et le remplir (clé anon uniquement, jamais service_role).
3. Lancer depuis la racine du projet :
```
node --env-file=agent/.env agent/scan.mjs --yes
```
`--yes` confirme que vous êtes autorisé à scanner ce réseau.
`--cidr=192.168.0.0/24` remplace SCAN_CIDR.

## Sécurité
- Ne scannez que des réseaux qui vous appartiennent ou avec autorisation écrite.
- `agent/.env` contient votre mot de passe : il est ignoré par Git, ne le partagez pas.
