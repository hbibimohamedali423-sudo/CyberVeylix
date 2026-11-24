# Capteur passif CyberVeylix

Écoute le réseau local et signale en temps réel les signes d'attaque ou de panne visibles par
n'importe quel poste du réseau. Il n'envoie de lui-même aucun paquet : seuls ses leurres
(facultatifs) répondent à qui s'y connecte. Aucun réglage n'est modifié chez le client :
ni routeur, ni switch, ni appareil.

## Ce qu'il détecte
| Événement | Gravité | Signification |
|---|---|---|
| Usurpation de la passerelle | Critique | Une autre machine se fait passer pour le routeur : attaque « homme du milieu » probable |
| Serveur DHCP non autorisé | Critique | Un appareil distribue des adresses : serveur pirate ou équipement mal configuré qui perturbe le réseau |
| Usurpation ARP probable | Haute | Une même machine revendique rapidement 5 adresses IP ou plus (empoisonnement ARP) |
| Changement de MAC sur une adresse connue | Haute | Conflit d'adresse IP ou usurpation ciblée d'un appareil |
| Inondation d'adresses MAC | Haute | Plus de 20 nouveaux appareils par minute : attaque par inondation ou outil de balayage |
| Nouvel appareil détecté | Moyenne | Une MAC jamais vue apparaît sur le réseau |
| Balayage de ports interne (leurres) | Critique | Un appareil sonde au moins 3 leurres en une minute : reconnaissance ou malware qui se propage |
| Tentative d'intrusion sur un leurre | Critique | Identifiant envoyé à un faux Telnet, FTP ou portail web : attaque de mots de passe, botnet type Mirai |
| Connexion à un service leurre | Haute | Un appareil se connecte à un service que personne n'a de raison d'utiliser |

## Leurres (honeypot)
Avec `--honeypot` (activé par défaut par l'installateur), le capteur ouvre sur l'adresse du PC des
services factices : FTP (21), SSH (22), Telnet (23, 2323), portail web (80, 8080), SQL Server (1433),
MySQL (3306), Bureau à distance (3389) et VNC (5900). Aucun appareil légitime n'a de raison de s'y
connecter : **tout contact est une alerte**, dès la première seconde (pas de période d'apprentissage).

- **Mots de passe jamais conservés** : un employé peut taper son vrai mot de passe par erreur. Seuls
  l'identifiant et le fait qu'un mot de passe a été envoyé sont enregistrés.
- **Faible interaction** : les leurres n'exécutent rien et ferment vite la connexion
  (15 s maximum, 4 Ko lus au plus, 64 connexions simultanées par leurre).
- **Vrais services protégés** : si un port est déjà servi sur ce PC (ex. Bureau à distance activé, IIS),
  le leurre correspondant est ignoré et le vrai service n'est jamais perturbé.
- **Pare-feu** : l'installateur ajoute une règle Windows qui n'ouvre que ces ports, pour le seul
  programme du capteur, et seulement depuis le réseau local (groupe « CyberVeylix », retiré à la désinstallation).
- **Scanners légitimes** : si le client utilise un outil d'inventaire ou de scan, ajoutez son IP avec
  `--honeypot-allow=192.168.1.50` (ou à la question de l'installateur) pour ne pas déclencher d'alerte.
  Le PC du capteur lui-même est toujours ignoré (l'agent `agent/scan.mjs` peut y tourner).
- Chaque alerte indique l'IP **et la MAC** de l'appareil fautif quand elle est connue.

## Analyse des vulnérabilités
Avec `--vuln-scan` (proposé par l'installateur), le capteur analyse les appareils qu'il a appris
5 minutes après l'apprentissage, puis toutes les 24 h (`--vuln-scan-hours`). À la demande :
```
node sensor/vulnscan.mjs --yes --targets=192.168.1.0/24 --client="Société X"
```
(sur un PC installé : `vulnscan.cmd` en administrateur, qui reprend les appareils et le client du capteur).

**Non intrusive** : lecture de ce que chaque service annonce et négociation normale des protocoles.
Aucune exploitation, aucun essai de mot de passe, réseaux privés uniquement (10/8, 172.16/12, 192.168/16).

| Contrôle | Gravité | Comment |
|---|---|---|
| vsftpd 2.3.4 (porte dérobée, CVE-2011-2523) | Critique | Bannière FTP |
| ProFTPD 1.3.5 mod_copy (CVE-2015-3306) | Critique | Bannière FTP (à vérifier : module chargé ?) |
| Apache 2.4.49 / 2.4.50 (CVE-2021-41773 / 42013) | Critique | En-tête HTTP Server |
| IIS 6.0 / Windows Server 2003 (CVE-2017-7269) | Critique | En-tête HTTP Server |
| VNC sans mot de passe | Critique | Types de sécurité RFB |
| Redis, API Docker sans authentification | Critique | PING Redis, GET /version |
| OpenSSH 8.5p1 à 9.7p1 « regreSSHion » (CVE-2024-6387) | Haute | Bannière SSH (« à vérifier » si la distribution corrige sans changer de numéro) |
| SSH v1, Dropbear < 2016.74 | Haute | Bannière SSH |
| SMBv1 activé (EternalBlue, CVE-2017-0144) | Haute | Négociation SMB1 seule, sans authentification |
| Bureau à distance sans NLA (BlueKeep, CVE-2019-0708) | Haute | Négociation RDP en TLS seul |
| Telnet actif, Elasticsearch ouvert | Haute | Connexion / GET / |
| FTP sans TLS, page de connexion en HTTP, bases de données exposées, TLS 1.0, certificat expiré | Moyenne | FEAT, page d'accueil, négociation TLS |
| Certificat auto-signé | Basse | Certificat TLS |

Chaque analyse produit `rapport-vulnerabilites-AAAAMMJJ-HHMM.html` dans le dossier de données (à ouvrir
dans un navigateur, imprimable en PDF pour le client : preuves, CVE, corrections recommandées) et met à jour
`vulns-latest.json`. Alertes : la première analyse donne un résumé et les faiblesses critiques ; ensuite,
chaque **nouvelle** faiblesse et chaque faiblesse **corrigée** est signalée (un appareil éteint n'est jamais
considéré comme corrigé). Avec `--push`, les faiblesses rejoignent la page « Vulnérabilités » du tableau de bord.

**Limites** : la base de règles est courte et vérifiée, pas exhaustive. L'absence de résultat ne prouve pas
l'absence de vulnérabilité.

## Inventaire et identification des appareils
Avec `--push`, le capteur inventorie son réseau toutes les 5 minutes (premier passage 1 min après le démarrage) :
- **Réseau** : enregistré dans `networks` pour la MAC de passerelle confirmée à l'installation (nom = client),
  avec son sous-réseau (ex. `10.15.0.0/16`). Jamais pour une MAC simplement apprise ou annoncée par un tiers.
- **Appareils** : chaque MAC vue (ARP cohérent, demandes DHCP) devient un appareil du réseau, suivi par sa MAC
  même si son IP change. « Hors ligne » après 2 h d'absence (appareils découverts par le capteur seulement).
- **Identification** (rôle + type + confiance + preuve, colonne `role_evidence` « Capteur : … ») : fabricant
  (registre IEEE, paquet `oui-data`), nom et système annoncés en DHCP (« android-dhcp », « MSFT 5.0 »…), ports
  relevés par l'analyse, MAC aléatoire (téléphones récents). Sans indice : rien n'est inventé.
- Un nom, un type ou un rôle saisis à la main ne sont **jamais** écrasés.
- Limite : un PC seul ne voit pas sur quel port de switch ni sur quel point Wi-Fi chaque appareil est branché ;
  cela demande la lecture des switchs (SNMP, en lecture seule).

## Interface (tableau de bord)
L'installateur place le tableau de bord dans le dossier `ui` et le capteur le sert lui-même : aucun site
externe à installer. Sur le PC : raccourci **CyberVeylix** sur le Bureau, ou `http://localhost:8710`.
Depuis un autre appareil du réseau local : `http://<nom du PC>:8710`.

- La connexion se fait avec le compte du tableau de bord ; la page ne contient que l'URL du projet et la clé
  publique « anon » (`/config.js`), jamais le mot de passe du compte ni une clé `service_role`.
- Pare-feu : règle limitée au réseau local (`LocalSubnet`) et au programme du capteur, jamais Internet.
  `-UiLocalOnly` : ce PC seulement (pas de règle). `-NoUi` : pas d'interface. `-UiPort 9000` : autre port.
- Nécessite l'envoi au tableau de bord (`-Push` / compte renseigné à l'installation).
- À la main : `node listener.mjs --yes --ui [--ui-port=8710] [--ui-local]`.

## Demandes de la page web
Avec l'envoi au tableau de bord (`--push`), le capteur consulte toutes les 5 s la table `sensor_commands`.
La page « Analyse & Scan » y dépose une demande ; le capteur la réclame (une seule fois), l'exécute lui-même
et écrit le résultat. Le navigateur n'exécute jamais rien sur le réseau.
- **Liste blanche** : `scan_now` (analyse), `block_ip` / `unblock_ip` (blocage) et `fix` (correction de CE PC).
  Tout autre type est refusé explicitement (« non pris en charge »).
- Une demande de plus de 15 minutes n'est pas exécutée (le capteur était éteint) ; une demande « en cours » lors
  d'un redémarrage est marquée en échec.
- Ne vise que les appareils déjà connus du capteur, réseaux privés uniquement (comme l'analyse périodique).

## Bloquer une adresse
Dans « Menaces & Incidents », chaque alerte dont l'adresse du fautif est fiable (leurre touché, serveur DHCP pirate,
nouvel appareil) porte un bouton **Bloquer**. Pour une usurpation de passerelle ou ARP, l'IP annoncée est celle de la
victime imitée : seule la **MAC** est affichée, pour retrouver l'appareil.
- Le capteur pose deux règles du **pare-feu Windows de son PC** (`CyberVeylix-Block-<ip>`, entrante et sortante),
  sans shell, avec une adresse validée strictement. Le débloquage les retire. Cela protège **ce PC**, pas tout le réseau
  (bloquer au niveau du routeur dépend de son modèle : non fait ici).
- **Jamais bloquables** : la passerelle, le PC du capteur, le serveur DHCP de confiance, les adresses du tableau de bord
  (Supabase), la liste `trusted_ips` du capteur, et les adresses 0.x, 127.x, 224.x–255.x.
- **Blocage automatique** (colonne `sensors.auto_block`, désactivé par défaut) : seulement après un balayage de leurres
  ou une tentative d'intrusion sur un leurre, 20 blocages par heure au plus, mêmes garde-fous.
- La table `blocked_ips` est écrite par le capteur (résultat réel du pare-feu) ; les règles survivent au redémarrage.

## Audit de ce PC et bouton « Corriger »
Le PC du capteur n'est jamais analysé par le réseau (ses leurres ouverts fausseraient le résultat) : le capteur lit
directement son état (lecture seule, 1 min après le démarrage, toutes les 6 h, et à chaque analyse) :
SMBv1 activé, Bureau à distance sans NLA, service Telnet en cours d'exécution. Chaque faiblesse apparaît dans
« Vulnérabilités » (clé `local:<pc>:<id>`, confiance « certaine ») avec un bouton **Corriger** :
| Correction | Effet | Conséquence à connaître |
|---|---|---|
| `smbv1` | `Set-SmbServerConfiguration -EnableSMB1Protocol $false` | Très anciens appareils (XP, vieux NAS) privés de partages |
| `rdp_nla` | Registre RDP-Tcp `UserAuthentication = 1` | Très anciens clients sans NLA refusés |
| `telnet` | Arrêt et désactivation du service `TlntSvr` | Plus de connexion Telnet à ce PC |

Scripts PowerShell **constants** (aucun texte venant de la page n'est exécuté). Avant d'agir, le capteur relit l'état ;
après, il vérifie : il ne répond « corrigé » que si la faiblesse a réellement disparu, puis met la page à jour.
Les autres appareils (caméras, imprimantes…) ne sont jamais modifiés à distance : leurs faiblesses gardent les
instructions de correction.

## Test d'intégration
`npm run build` puis `npm run test:integration` lance le vrai `listener.mjs` avec une carte réseau simulée
(`test/integration/stubmods/cap`) et une fausse base Supabase locale : pouls, interface servie, `/config.js` sans
secret, et exécution des demandes (analyse, blocage refusé pour la passerelle, etc.).

## Ce qu'il ne fait pas
- Il ne bloque rien de lui-même au niveau du réseau : le blocage (à votre demande, ou automatique si activé) ne concerne
  que le pare-feu du PC du capteur.
- Il ne voit que le trafic **diffusé** (ARP, DHCP) : il ne voit pas la navigation des autres appareils.
- Il ne corrige jamais les AUTRES appareils : leur rapport donne les corrections, l'analyse suivante vérifie qu'elles sont faites.
  Seul le PC du capteur peut être corrigé, à votre demande, avec les trois corrections ci-dessus.

## Installation (Windows)
1. Installer **Node.js 20.6 ou plus récent**.
2. Installer **Npcap** depuis https://npcap.com en cochant **« Install Npcap in WinPcap API-compatible Mode »**.
3. Installer les **Visual Studio Build Tools** avec la charge « Développement Desktop en C++ »
   (le module `cap` est compilé lors de l'installation).
4. Depuis la racine du projet :
```
npm install --prefix sensor
```

## Utilisation
Lister les interfaces réseau :
```
node sensor/listener.mjs --list
```
Lancer la surveillance (`--yes` confirme l'autorisation écrite du propriétaire du réseau) :
```
node sensor/listener.mjs --yes
```

Au premier lancement, le capteur **apprend le réseau normal pendant 10 minutes** sans alerter
(appareils présents, MAC de la passerelle, serveur DHCP légitime), puis passe en surveillance.
La référence est enregistrée dans `sensor/data/baseline.json` et rechargée aux lancements suivants.

| Option | Rôle |
|---|---|
| `--interface=192.168.1.10` | Interface à écouter (IP ou nom affiché par `--list`). Par défaut : la première interface en adresse privée |
| `--gateway=192.168.1.1` | IP de la passerelle (détectée automatiquement sinon) |
| `--gateway-mac=00:11:22:33:44:55` | MAC de la passerelle fixée à la main. **Recommandé** : sans elle, la première MAC vue pour la passerelle sert de référence |
| `--learn-minutes=10` | Durée d'apprentissage (0 si une référence existe déjà) |
| `--reset-baseline` | Oublie la référence et réapprend le réseau |
| `--push` | Envoie aussi les alertes au tableau de bord (voir ci-dessous) |
| `--honeypot` / `--no-honeypot` | Active / désactive les leurres |
| `--honeypot-ports=21,23,8080` | Ports des leurres (par défaut : la liste ci-dessus) |
| `--honeypot-allow=192.168.1.50` | IP autorisées à toucher les leurres sans alerte (séparées par des virgules) |
| `--vuln-scan` / `--no-vuln-scan` | Active / désactive l'analyse périodique des vulnérabilités |
| `--vuln-scan-hours=24` | Intervalle entre deux analyses (1 à 168 h) |

Les alertes s'affichent dans la console et sont ajoutées à `sensor/data/events.jsonl`.

### Envoi vers le tableau de bord
```
node --env-file=agent/.env sensor/listener.mjs --yes --push
```
Utilise les mêmes variables que l'agent de découverte (`agent/.env`). Aucune modification du
schéma Supabase n'est nécessaire : les alertes vont dans la table `alerts` existante.

### Démarrage automatique
Planificateur de tâches Windows → Créer une tâche :
- Déclencheur : **Au démarrage**
- Action : `sensor\run-sensor.bat` (journal dans `sensor\data\sensor.log`)
- Cocher **« Exécuter même si l'utilisateur n'est pas connecté »**, et **« Exécuter avec les autorisations
  maximales »** si Npcap a été installé en mode réservé aux administrateurs.

## Tests
```
npm test --prefix sensor
```
Les analyseurs et la détection sont testés avec de vraies trames construites octet par octet,
y compris 20 000 trames aléatoires ou corrompues (aucune exception tolérée).

## Sécurité, vie privée et licences
- Ne surveillez que des réseaux dont vous avez l'**autorisation écrite** du propriétaire.
- `sensor/data/` contient l'inventaire du réseau du client : il est ignoré par Git, ne le partagez pas.
- `--push` utilise le mot de passe de `agent/.env` : sur le poste d'un client, réservez la lecture de ce fichier à votre compte.
- **Npcap** est gratuit pour un usage personnel ; son usage commercial ou sa redistribution
  dans un produit vendu nécessitent une licence (https://npcap.com/oem/). Vérifiez ses conditions
  avant de commercialiser CyberVeylix.
