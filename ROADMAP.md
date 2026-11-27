# Où en est CyberVeylix

Ce fichier est un résumé court, tenu à jour après chaque étape terminée. Il sert à reprendre
rapidement le travail (ici ou dans une nouvelle conversation) sans tout relire. Il ne remplace
pas le code ni l'historique Git : il n'affirme que ce qui est réellement commité et vérifié.

**Dernière mise à jour :** 2026-11-27, branche `claude/integration-travail-local`.

## ✅ Terminé, testé, commité sur cette branche

- **Capteur passif de base** (préexistant) : écoute ARP/DHCP, leurres (honeypot), analyse des
  vulnérabilités, lecture des switchs Cisco en SNMP (lecture seule), alertes Telegram.
- **Nouvelle interface « HUD »** : page de connexion (œil holographique, appareils 3D en orbite),
  habillage visuel de toute l'application (fond bleu-vert quadrillé, cyan), tableau de bord
  entièrement reconstruit avec des données réelles uniquement (aucun chiffre inventé).
- **Moteur de détection de comportement** (`sensor/lib/behavior.mjs`) + liste de menaces
  (`threatlist.mjs`) : balayage du réseau, communication avec une adresse malveillante connue,
  comportement inhabituel. Alimenté par le trafic ARP local.
- **Pare-feu FortiGate en lecture seule** (`fortigate.mjs`, `fortigate-parse.mjs`,
  `fortigate-sync.mjs`) : VLAN, baux DHCP, table ARP, sessions actives — alimente le moteur de
  comportement sur TOUT le réseau, pas seulement le segment du capteur.
- **Détection réseau-large sur Cisco/SNMP** (`cisco-behavior.mjs`) : une adresse MAC apprise par
  plusieurs switchs à la fois (clonage/usurpation, ou usurpation de la passerelle elle-même).
- **Analyse d'atteignabilité VLAN-à-VLAN** (`sensor/lib/reachability.mjs`) : à partir des règles
  de pare-feu FortiGate + objets/groupes d'adresses, calcule « le VLAN A peut-il joindre le
  VLAN B ? » avec la règle exacte comme preuve. Trois résultats : autorisé / bloqué / incertain
  (adresse non résolvable qui pourrait changer la réponse). Respecte l'ordre réel d'évaluation
  des règles FortiGate (première correspondance gagne — une première version ignorait cet ordre
  et a été corrigée avant tout test). 21 tests dédiés, y compris les cas d'ordre de règles.
  **Calculée et journalisée uniquement pour l'instant** (console du capteur) — pas encore
  enregistrée ni affichée dans le tableau de bord (voir ci-dessous).

Capteur publié : version 0.13.3 (voir `sensor/package.json`). **Pas encore testé sur un vrai
pare-feu/switch réel** — construit et vérifié par des exemples seulement, à confirmer au premier
essai sur le réseau Meridiana.

## 🚧 En cours

Rien en cours de construction actuellement — la dernière étape (atteignabilité VLAN) est
terminée, testée (238/238) et commitée. En attente d'une décision utilisateur avant de continuer
(voir « Prochaine étape » ci-dessous).

## ⏭️ Prochaine étape (au choix de l'utilisateur)

L'analyse d'atteignabilité VLAN est calculée mais invisible pour l'instant (console seulement).
Pour qu'elle serve réellement, il faut, dans l'ordre :
1. Proposer une nouvelle table Supabase (SQL dans un fichier séparé, à approuver — aucune
   modification de schéma ne sera appliquée sans accord explicite, règle du projet).
2. Enregistrer la matrice calculée dans cette table à chaque interrogation du pare-feu.
3. Construire la page du tableau de bord qui l'affiche.

Pistes additionnelles déjà discutées et notées en mémoire, pas encore commencées : détection de
règles de pare-feu mortes/trop larges, détection de point unique de défaillance (switch/lien) à
partir de la topologie déjà lue, classement des appareils par « rayon d'impact », diagnostic
« la règle autorise mais aucun chemin réel n'existe ».

## ⏳ En attente du côté de l'utilisateur (rien à coder)

- Demander la community SNMP (lecture seule) à l'administrateur réseau de Meridiana : sans elle,
  la lecture des switchs et la nouvelle détection Cisco ne fonctionnent pas sur ce réseau.
- Activer « Leaked password protection » dans Supabase (Authentication).
- Décider quand fusionner `claude/integration-travail-local` dans `main`.
- Décider quand publier une nouvelle release du capteur (actuellement non publiée depuis 0.13.0 :
  toutes les phases ci-dessus ne sont donc pas encore sur un capteur installable).
