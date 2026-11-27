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

Capteur publié : version 0.13.3 (voir `sensor/package.json`). **Pas encore testé sur un vrai
pare-feu/switch réel** — construit et vérifié par des exemples seulement, à confirmer au premier
essai sur le réseau Meridiana.

## 🚧 En cours — PAS testé, PAS commité

**Analyse de portée (« si cet appareil est compromis, qu'est-ce qu'il peut atteindre ? »).**
Décision et détail complet dans la mémoire Claude du projet (note
`prochaine-fonctionnalite-segmentation`). État exact au moment de la pause :
- `fortigate-parse.mjs` / `fortigate.mjs` modifiés (nouvelles lectures : objets adresse, groupes
  d'adresses, règles de pare-feu — toujours en lecture seule) mais **sans aucun test**.
- Reste à faire, dans l'ordre : créer `reachability.mjs` (résolution des adresses + matrice
  VLAN→VLAN avec preuve), écrire les tests, lancer lint/tests/build, puis seulement commiter.
- L'affichage dans le tableau de bord viendra après, comme étape séparée.

## ⏭️ Prochaine étape unique

Finir l'analyse de portée ci-dessus. Rien d'autre tant qu'elle n'est pas terminée et testée.

## ⏳ En attente du côté de l'utilisateur (rien à coder)

- Demander la community SNMP (lecture seule) à l'administrateur réseau de Meridiana : sans elle,
  la lecture des switchs et la nouvelle détection Cisco ne fonctionnent pas sur ce réseau.
- Activer « Leaked password protection » dans Supabase (Authentication).
- Décider quand fusionner `claude/integration-travail-local` dans `main`.
- Décider quand publier une nouvelle release du capteur (actuellement non publiée depuis 0.13.0 :
  toutes les phases ci-dessus ne sont donc pas encore sur un capteur installable).
