# CyberVeylix

Surveillance de sécurité d'un réseau local : un **capteur** installé sur un PC Windows qui reste allumé dans le
réseau, et un **tableau de bord** (React + Supabase) que le capteur sert lui-même dans le navigateur.

## Installation sur le PC permanent (résumé)
1. Télécharger le paquet `cyberveylix-sensor-<version>-windows-x64.zip` (release GitHub, ou artefact du workflow
   « Capteur Windows » dans l'onglet Actions). Clic droit → Propriétés → « Débloquer », puis « Extraire tout ».
2. Double-cliquer sur `install.cmd` et répondre aux questions (Npcap proposé s'il manque ; relier au tableau de bord
   avec l'URL du projet Supabase, la clé **publique** et votre compte : la connexion est vérifiée sur place).
3. Ouvrir le raccourci **CyberVeylix** du Bureau (`http://localhost:8710`) et se connecter.

Base de données : exécuter dans l'ordre les scripts de `supabase/` (voir plus bas), dont `schema_r1_results.sql`,
`schema_r4_actions.sql` et `schema_r5_hardening.sql` pour le capteur. Détails du capteur : `sensor/README.md`.

## Ce que fait la plateforme
- Inventaire et topologie du réseau, alertes d'intrusion en temps réel (usurpation de passerelle, DHCP pirate,
  usurpation ARP, leurres touchés…), analyse non intrusive des vulnérabilités (CVE, preuves, corrections).
- Depuis le tableau de bord : analyse immédiate, blocage / déblocage d'une adresse dans le pare-feu du PC du capteur
  (manuel ou automatique), correction des réglages dangereux de ce PC (SMBv1, RDP sans NLA, Telnet), journal de
  surveillance, rapport imprimable en PDF. Interface en 5 langues (fr, en, de, ar, it).
- Toutes les valeurs affichées viennent des enregistrements de la base : rien n'est simulé.

## Vérifications
`npm run lint`, `npm test`, `npm run build`, puis `npm run test:integration` (vrai capteur avec carte réseau
simulée et fausse base locale).

---

# Agent de découverte réseau CyberVeylix

Inventorie les appareils de **votre** réseau local et les envoie à votre compte CyberVeylix.

## Ce qu'il fait
- Ping + table ARP sur une plage privée (10/8, 172.16/12, 192.168/16, de /22 à /30).
- Connexion TCP simple sur ~23 ports courants (aucune exploitation, aucun envoi de données).
- Met à jour `devices` (statut, MAC, dernier vu) et `services` (ports ouverts).
- Identité d'un appareil = son adresse MAC : il est suivi même si son IP change (DHCP) ; une MAC inconnue sur une IP déjà utilisée crée un **nouvel** appareil et une alerte qui cite l'ancien occupant.
- Un appareil ajouté à la main n'est jamais déclaré « Hors ligne » tant que l'agent ne l'a pas vu.
- Les appareils de la plage non vus passent « Hors ligne » après 90 minutes d'absence (deux scans horaires manqués).

## Alertes automatiques
- « Nouvel appareil détecté » quand une adresse inconnue apparaît.
- « Port … ouvert » quand un port sensible (Telnet, FTP, RDP, VNC, bases de données) s'ouvre sur un appareil.
- Le premier inventaire d'une plage sert de référence : aucune alerte n'est créée.
- `--no-alerts` désactive les alertes pour un lancement.
- `--check` vérifie la configuration et la connexion sans scanner.

## Ce qu'il ne fait pas
Il ne détecte pas de vulnérabilités (CVE) et ne bloque aucune menace.

## Utilisation
1. Base neuve : exécuter dans Supabase > SQL Editor, dans cet ordre : `supabase/schema.sql`, `schema_alerts.sql`, `schema_scan.sql`, `schema_hardening.sql`, `schema_n1_networks.sql` (réseaux et liens), `schema_n2_prep.sql`, puis `schema_status.sql` (suivi des alertes et vulnérabilités). Les quatre derniers peuvent être relancés sans risque. `schema_n2_hardening.sql` est une **proposition** de durcissement RLS à valider avant exécution. Vérifier ensuite avec `npm run agent:check`.
2. Copier `agent/.env.example` vers `agent/.env` et le remplir (clé anon uniquement, jamais service_role).
3. Lancer depuis la racine du projet :
```
node --env-file=agent/.env agent/scan.mjs --yes
```
`--yes` confirme que vous êtes autorisé à scanner ce réseau.
`--cidr=192.168.0.0/24` remplace SCAN_CIDR.
`--approve-network` : ajoute le réseau auquel ce PC est connecté (premier lancement, à la main, sur VOTRE réseau).
Un réseau inconnu n'est jamais scanné ni enregistré : beaucoup de Wi-Fi (cafés, hôtels, clients) utilisent aussi
192.168.1.x, et un lancement automatique (`--local-only`) ne peut jamais ajouter de réseau.

## Sécurité
- Ne scannez que des réseaux qui vous appartiennent ou avec autorisation écrite.
- `agent/.env` contient votre mot de passe : il est ignoré par Git, ne le partagez pas.
