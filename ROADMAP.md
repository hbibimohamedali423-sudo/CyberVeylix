# Où en est CyberVeylix

Ce fichier est un résumé court, tenu à jour après chaque étape terminée. Il sert à reprendre
rapidement le travail (ici ou dans une nouvelle conversation) sans tout relire. Il ne remplace
pas le code ni l'historique Git : il n'affirme que ce qui est réellement commité et vérifié.

**Dernière mise à jour :** 2026-11-27, branche `claude/integration-travail-local`.

**⏸️ Travail mis en pause ici, volontairement.** À la reprise, lire seulement les deux sections
« Prochaine étape unique » et « En attente de l'utilisateur » ci-dessous : elles suffisent pour
repartir sans tout relire.

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
- **Enregistrement de l'atteignabilité dans Supabase** (`syncReachability` dans `sensor/lib/push.mjs`) :
  avec `--push` et la table créée (voir juste en dessous), la matrice complète remplace l'état
  précédent à chaque interrogation (comme les liens de topologie) — table absente : message
  unique, rien ne plante. **Affichage dans le tableau de bord : pas encore fait** (voir ci-dessous).

Capteur publié : version 0.13.3 (voir `sensor/package.json`). **Pas encore testé sur un vrai
pare-feu/switch réel** — construit et vérifié par des exemples seulement, à confirmer au premier
essai sur le réseau Meridiana.

## 🚧 En cours

Rien en cours de construction actuellement. L'atteignabilité VLAN est calculée ET enregistrée
dans Supabase (si `supabase/schema_r9_reachability.sql` a été exécuté) ; seul l'affichage dans le
tableau de bord manque encore.

## ⏭️ Prochaine étape unique

Construire la page/section du tableau de bord qui affiche la matrice d'atteignabilité déjà
enregistrée dans la table `vlan_reachability` (lecture seule côté interface, rien à calculer
côté React).

Pistes additionnelles déjà discutées et notées en mémoire, pas encore commencées : détection de
règles de pare-feu mortes/trop larges, détection de point unique de défaillance (switch/lien) à
partir de la topologie déjà lue, classement des appareils par « rayon d'impact », diagnostic
« la règle autorise mais aucun chemin réel n'existe ».

## ⏳ En attente du côté de l'utilisateur (rien à coder)

- Exécuter `supabase/schema_r9_reachability.sql` dans Supabase (SQL Editor) pour que
  l'atteignabilité VLAN soit réellement enregistrée — sinon le capteur continue, mais sans écrire.
- Demander la community SNMP (lecture seule) à l'administrateur réseau de Meridiana : sans elle,
  la lecture des switchs et la nouvelle détection Cisco ne fonctionnent pas sur ce réseau.
- Activer « Leaked password protection » dans Supabase (Authentication).
- Décider quand fusionner `claude/integration-travail-local` dans `main`.
- Décider quand publier une nouvelle release du capteur (actuellement non publiée depuis 0.13.0 :
  toutes les phases ci-dessus ne sont donc pas encore sur un capteur installable).
