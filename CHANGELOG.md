# Changelog CADRE

Toutes les modifications notables de ce projet sont documentées ici.
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).
Numérotation [SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté — `cadre secrets-sync-beats`

Résout définitivement (au lieu de la reprise manuelle décrite ci-dessous)
la resynchronisation de `CADRE_ELASTIC_PASS` vers Winlogbeat et Auditbeat
après une rotation : la nouvelle commande pousse le mot de passe courant du
coffre-fort vers `winlogbeat.yml` (WinRM) et `auditbeat.yml` (SSH), puis
redémarre les deux services. Le mot de passe transite par un fichier
temporaire à permissions restrictives sur chaque VM cible (déposé par
`Set-Content`/SFTP), jamais comme argument de ligne de commande shell — voir
`src/cadre/synchronise_secrets.py` et `docs/SECURITY.md` (section rotation).

### Corrigé — IDENTIFIANTS RÉELS CODÉS EN DUR (CWE-798, trouvé en exploitant l'infra réelle)

`tests/test_securite.py::SECRETS_INTERDITS` — une liste censée ne contenir
que des valeurs factices pour vérifier que le logger ne fuit jamais de
secret — contenait en réalité deux VRAIS mots de passe du labo
(Elasticsearch et Kibana). Même chose dans `documentation-projet.html`
(dump HTML généré du code source), où une ancienne capture du
docker-compose du SIEM exposait encore un des deux en clair, échappée à
`detect-secrets` (son filtre `is_prefixed_with_dollar_sign` traite tout
`${VAR:-...}` comme une référence de variable, jamais comme un secret en
dur, même quand la valeur par défaut EST un vrai secret). Les deux valeurs
remplacées par des valeurs bidon ; les deux mots de passe réels rotés
côté Elasticsearch par précaution (visibles dans l'historique Git de
toute façon). Trouvé en cherchant spécifiquement dans l'historique complet
du dépôt (pas seulement `HEAD`), à l'occasion d'une rotation volontaire de
ces mêmes secrets pour vérifier la résilience de la chaîne de télémétrie
— qui a elle-même révélé que Winlogbeat et Auditbeat gardent le mot de
passe `elastic` codé en dur dans leur propre configuration, hors du
coffre-fort CADRE, et ne le rafraîchissent jamais automatiquement après
une rotation (les deux mis à jour et revérifiés par leurs logs respectifs
et un cycle réel complet, 5/5 validées).

### Ajouté — ARRÊT PROPRE DE L'ENVIRONNEMENT (`scripts/arreter-environnement.ps1`)

Symétrique de `demarrer-environnement.ps1`, jusque-là absent : arrête le
dashboard, les VM (Windows + Kali) et le SIEM (Docker) en une commande —
`ARRETER-CADRE.bat` pour un double-clic. Deux choix délibérés :

- **VM : signal ACPI d'abord** (`VBoxManage controlvm acpipowerbutton`),
  jamais un `poweroff` immédiat — un arrêt brutal est la cause connue et
  documentée d'une régression réseau (carte Host-Only qui repasse en
  profil « Public » au démarrage suivant, bloquant WinRM). Repli
  automatique si l'ACPI ne suffit pas dans le délai imparti (constaté en
  réel juste après un cycle complet de 71 attaques : 2 min dépassées) :
  `scripts/arreter-vm-proprement.py` déclenche `Stop-Computer -Force`
  **depuis l'intérieur** de l'invité via `VBoxManage guestcontrol` (même
  canal hors bande que `reparer-winrm.py`), qui ne dépend pas du réglage
  du bouton d'alimentation de l'invité. `-Force` reste disponible en
  dernier recours pour une coupure immédiate.
- **SIEM : `docker compose stop`, jamais `down -v`** — le volume nommé
  `elasticsearch-data` (tout l'historique de détections/règles indexées)
  doit survivre à un arrêt.

**2 bugs trouvés en testant ce nouveau script en conditions réelles**
(VM réellement éteinte, pas juste un code de retour vérifié) :
1. Passer plusieurs arguments (`shutdown.exe /s /t 0 /f`) après `--` à
   `guestcontrol run` s'est avéré peu fiable — `shutdown.exe` a reçu ses
   arguments mal formés et affiché son aide au lieu de s'exécuter (code
   retour 33). Remplacé par une commande PowerShell unique encodée en
   base64 (`-EncodedCommand`, comme `reparer-winrm.py`), qui élimine tout
   risque de découpage incorrect.
2. `subprocess.run(..., text=True)` sans encodage explicite plantait le
   thread de lecture de `guestcontrol` (`UnicodeDecodeError` sur un octet
   `0x90`, la sortie de `shutdown.exe` n'étant pas en cp1252) — corrigé
   par `encoding="utf-8", errors="replace"`. **Même correctif appliqué à
   `reparer-winrm.py`**, qui partageait le même défaut latent (jamais
   déclenché jusqu'ici, la sortie qu'il capture étant restée jusque-là
   purement ASCII).

### Corrigé — JOURNAL DASHBOARD NOYÉ PAR SECRET_READ (audit exécution réelle, 07/09)

Trouvé en conditions réelles (cycle complet + navigation dans le dashboard,
pas en test unitaire) : les 300 dernières lignes du fichier de log réel
étaient **100 % `SECRET_READ`** (niveau DEBUG). `_auth_ok()` relit
`CADRE_DASHBOARD_PASSWORD` sur CHAQUE requête HTTP (avant même de vérifier
le cookie de session), et le dashboard sonde le serveur toutes les 2 à 9 s
selon le flux (barre d'état, onglet actif, statut de cycle) — l'onglet
« Erreurs & journaux » n'affichait donc plus aucune entrée utile après
quelques minutes d'ouverture, malgré le correctif du 16/08 qui avait déjà
démoté `SECRET_READ` en DEBUG pour ne pas inonder la **console** (le
fichier de log, lui, reste volontairement complet et non filtré — voir
`Logger.evenement` — c'est `/api/logs`, qui le lit tel quel sans le
moindre filtre de niveau, qui n'avait jamais été corrigé).

`tail_logs()` (`dashboard.py`) exclut désormais les entrées DEBUG et
continue de remonter dans le fichier jusqu'à réunir `n` événements
réellement visibles, au lieu de renvoyer `n` lignes brutes dont la quasi-
totalité étaient filtrées après coup côté client. 1 nouveau test
(reproduisant exactement le ratio observé en réel : bruit DEBUG entrelacé
avec des événements utiles). Vérifié contre le vrai fichier de log de ce
soir (300 lignes 100 % DEBUG en entrée → 60 événements WARN/ATTACK/
SUCCESS/INFO en sortie, 0 DEBUG).

### Corrigé — VÉRIFICATION FINALE (8 défauts, 2 vagues)

Même protocole que les vagues précédentes (correctif d'un défaut, puis revue
indépendante ciblée de CE correctif) — jamais documentée jusqu'ici dans ce
fichier bien que déjà committée pour les 2 premiers points.

- **Path traversal sur `attaque.id` (écriture)** — un identifiant « rooté »
  (commençant par `/` ou `\`, ex. forgé via un dépôt Atomic Red Team externe)
  contournait `repertoire_regles` entièrement via l'opérateur `/` de pathlib,
  qui remplace le préfixe au lieu de le concaténer. Corrigé par validation
  stricte du format dans `enregistrer_attaque_utilisateur`.
- **Filtre anti-destruction contournable (EDR/AV, reverse shell)** — toute une
  famille de désactivation de sécurité (`Stop-Service`/`net stop`/`sc
  stop|delete|config ... disabled`, `taskkill`/`Stop-Process` sur processus
  EDR/AV connus, `Add-MpPreference -Exclusion*`, `auditpol`) passait le
  filtre malgré la promesse du docstring du module ; de même pour `nc ... -e`
  en fin de commande (au lieu de juste après `nc`), `ncat`, `socat` et
  `/dev/tcp/`. Durci en 2 temps (revue indépendante du 1er correctif y ayant
  trouvé les cmdlets PowerShell équivalentes).
- **Path traversal sur `attaque.id` (lecture)** — même défense de fond que
  ci-dessus, mais côté écriture seulement : `charger_attaques_utilisateur`
  ne revérifiait pas l'id au chargement, alors que `catalogue_perso.json`
  reste un fichier modifiable hors du chemin normal. Trouvé par audit
  indépendant du correctif précédent, corrigé le même soir.
- **Secret SMTP en clair sur la CLI** (`cadre loop --smtp-password`) —
  exposait le mot de passe dans l'historique shell. Ajout du support
  `envvar="CADRE_SMTP_PASSWORD"` sur l'option Click.
- **`risk_score` incohérent sur la corrélation de kill chain** —
  `_calculer_clause_eql` codait en dur `"risk_score": 75` au lieu de
  réutiliser la table `_RISK_SCORE_PAR_SEVERITE` déjà utilisée par le
  générateur de règle Sigma principal (bug distinct de celui déjà corrigé
  sur ce dernier, voir Annexe D du rapport).
- **Fenêtre de faux positifs figée** — `valider_bruit_seul` acceptait un
  paramètre `fenetre_tp_sec` mais utilisait la constante globale
  `FENETRE_TP_SEC` à sa place, rendant le paramètre muet.
- **Code mort dashboard** (`.app-main`, `.kpi-primaire`) — classes CSS et
  attribut de données sans effet, supprimés.
- **Dashboard : une vue en échec à l'initialisation blanchissait tout le
  tableau de bord** — `app.js::demarrer()` montait les 12 onglets sans
  `try/catch` ; une exception dans une seule vue empêchait le montage des
  suivantes, sans aucun message pour l'utilisateur. Chaque `creer()` est
  désormais isolé : une vue en échec affiche une erreur confinée à son
  propre onglet (`etatErreur` de `ui.js`), les autres restent utilisables.
  Vérifié en conditions réelles au navigateur (erreur injectée
  volontairement dans une vue, confirmé que les 11 autres onglets
  continuaient de fonctionner, puis retirée).
- Dédoublonnage `th()`/`badge()` (identiques dans 5 fichiers de vues) vers
  `ui.js` — pas un défaut, maintenabilité seulement, mentionné ici pour
  traçabilité de session.
- 1 nouveau test (path traversal en lecture), suite complète relancée
  (1148 tests, 93,99 % de couverture, 0 régression).

### Ajouté — COMMANDE `cadre nettoyer-kibana` (règles orphelines)

- **Trouvé par un test réel exhaustif du 29/08** : Kibana contenait 131
  règles CADRE pour seulement 71 techniques — **60 doublons**. Cause : des
  déploiements ANTÉRIEURS au mécanisme d'idempotence (`rule_id_stable`,
  déjà en place) utilisaient un `rule_id` UUID aléatoire ; ces règles n'ont
  jamais été remises à jour et se sont accumulées. Le code actuel ne crée
  plus de doublons — c'était un résidu de données historiques.
- Nouvelle commande **`cadre nettoyer-kibana`** (+ méthode
  `nettoyer_regles_orphelines_kibana`) : inventorie les règles CADRE
  orphelines (`rule_id` non `cadre-…`) et, avec `--appliquer` (confirmation
  requise), les supprime. **Garde-fou de sûreté** : une orpheline n'est
  supprimée que si une règle à jour couvre déjà la MÊME technique MITRE —
  jamais une détection unique (vérifié par mutation). 3 tests.
- Exécutée en réel : Kibana nettoyé de **131 → 71 règles**, 0 doublon,
  71/71 actives.

### Ajouté — DISJONCTEUR (CIRCUIT BREAKER) SUR LES ÉCHECS D'EXÉCUTION EN CHAÎNE

- **Un cycle qui perdait sa cible en cours de route s'acharnait sur TOUTES
  les attaques restantes.** Trouvé en réel le 28/08 : sous la charge d'un
  cycle complet, le service WinRM de la VM cible est passé « zombie » (port
  TCP ouvert — le pré-vol de joignabilité passe — mais aucune commande ne
  répond, chaque exécution timeout). Résultat observé : **20 attaques de
  suite en « Échec exécution »**, ~50 min gaspillées, sans que le cycle ne
  réagisse ni ne le signale clairement.
- `_boucle_attaques` (`orchestrateur.py`) compte désormais les échecs
  d'exécution **consécutifs** (statut `ERREUR`, une fois le pré-vol passé) :
  un succès réel (validé, angle mort, faux négatif — l'exécution a bien eu
  lieu) remet le compteur à zéro ; un `NON_APPLICABLE` (plateforme sans
  cible configurée) est neutre. Au-delà du seuil
  (`seuil_echecs_execution_consecutifs`, défaut **5**, `0` désactive), le
  cycle s'interrompt proprement — message d'erreur explicite et attaques
  restantes marquées « non exécutée (cycle interrompu par le disjoncteur) »
  pour un rapport honnête, au lieu de 34 échecs silencieux.
- 4 tests couvrent la mécanique (déclenchement à 5, réinitialisation sur
  succès, neutralité du `NON_APPLICABLE`, désactivation à 0), le
  déclenchement étant **vérifié par mutation**. La logique est prouvée hors
  ligne ; le scénario réel qui l'a motivée (service WinRM zombie) a été
  directement observé le même jour.

### Corrigé — REPLI SILENCIEUX SUR UN ENUM NON RECONNU (catalogue utilisateur)

- **`_normaliser_enum()` (`catalogue_utilisateur.py`) retombait sans le
  moindre signal sur la valeur par défaut** quand une chaîne ne correspondait
  à aucun membre de l'énumération. La tolérance envers les chaînes est
  délibérée (le LLM et les JSON édités à la main en produisent), mais le
  silence, lui, ne l'était pas : une attaque décrite avec
  `"plateforme": "ubuntu"` devenait `windows` sans trace, envoyant une
  commande Linux vers la VM Windows. Le repli est conservé — un
  avertissement journalisé distingue désormais le champ **absent** (cas
  normal, silencieux) de la valeur **fournie mais non reconnue** (faute de
  frappe ou hallucination du LLM). Régression figée par deux tests, dont un
  garde-fou contre l'excès inverse (ne pas journaliser un champ simplement
  absent), **vérifiés par mutation**.

### Vérifié — CONTRÔLE COMPLET DE LA CHAÎNE QUALITÉ

- **`black --check` échouait sur 4 fichiers** (`compilation_sigma.py`,
  `cli.py`, et deux fichiers de tests) — la CI aurait été rouge. Formatage
  appliqué, chaîne complète repassée au vert : `ruff`, `black`, `mypy`
  (24 modules), `bandit` (0 constat sur `src/`), `detect-secrets`
  (0 fichier), hygiène du dépôt (389 fichiers suivis : 0 espace en fin de
  ligne, 0 newline finale manquante, 0 marqueur de conflit, 0 fichier
  >1 Mo, 0 clé privée).
- **Vérification fonctionnelle hors tests** : les 23 modules s'importent,
  les 23 commandes de la CLI se chargent, et les **68 attaques du catalogue
  génèrent une règle Sigma compilant en Lucene syntaxiquement valide**
  (0 échec, 0 requête invalide).
- **`CHAMPS_TEXTE_ANALYSE` confirmé correct** : les 34 attaques à
  `valeur_detection` multi-mots portent sur `process.command_line` et
  `process.title`, dont les cycles réels enregistrés prouvent qu'ils
  matchent bien (T1003.002 `save HKLM\SAM` TP=1, T1087.001
  `cat /etc/passwd` TP=8, T1003.008 TP=2) — ces champs ne sont donc pas
  analysés, contrairement à `powershell.file.script_block_text`, seul
  membre légitime de la liste.

### Corrigé — 10 DÉFAUTS RÉELS TROUVÉS PAR REVUES INDÉPENDANTES POST-SOUTENANCE

Deux rounds de revue par agents indépendants (regard neuf, sans accès au
raisonnement ayant produit le code), chacun vérifié empiriquement avant
correction. Le second round portait délibérément sur **le code des correctifs
du premier** — et y a trouvé 4 défauts nouveaux, dont le plus sérieux de la
série.

**Round 1 — 6 défauts (revue à 4 agents)**

- **Le mot de passe de la VM transitait en clair en argument de ligne de
  commande** (`VBoxManage guestcontrol --password <valeur>`), lisible par tout
  processus local le temps de l'exécution via `wmic`/Process Explorer
  (CWE-214). Remplacé par `--passwordfile` pointant un fichier temporaire
  supprimé systématiquement.
- **Le même mot de passe fuyait une seconde fois dans les journaux** :
  `subprocess.TimeoutExpired.__str__()` réintègre l'argv complet (CWE-532,
  confirmé empiriquement en reproduisant l'exception). `TimeoutExpired` est
  désormais capturée séparément du cas générique, sans jamais logguer `e`.
- **`verifier_winrm_reel()` pouvait bloquer indéfiniment** dans exactement le
  scénario « port ouvert, service figé » qu'elle existe pour diagnostiquer
  rapidement — l'inverse de l'effet recherché. Le garde-fou de timeout dur
  (`_executer_run_ps_avec_timeout_dur`) ne couvrait que `run_ps`, pas le
  `run_cmd` de cette méthode ; généralisé en `_executer_avec_timeout_dur(appel,
  timeout_sec)` et câblé aux deux appelants.
- **Un `TimeoutError` survenant précisément à la 3e tentative gaspillait
  silencieusement une récupération VirtualBox pourtant réussie** : avec
  `for tentative in range(1, 4)`, le `continue` post-récupération épuisait
  l'itérateur — la boucle se terminait sans jamais retenter la commande, ni
  même logguer l'abandon. Converti en boucle `while` à incrémentation
  explicite.
- **La forme groupée `champ:(*a b* OR *c*)` échappait à la réécriture
  wildcard→phrase** : pysigma produit cette forme (jamais `champ:*a* OR
  champ:*b*`) pour un `contains` à plusieurs valeurs sur le même champ — le
  correctif du faux négatif ne matchait que la forme simple et ratait
  silencieusement tous ces cas.
- **`_resoudre_chemin_vboxmanage()` pouvait résoudre `VBoxManage` via le
  `PATH`** sans que rien ne le signale (risque de détournement de `PATH`) ;
  un avertissement explicite est désormais journalisé dans ce cas.

**Round 2 — 4 défauts, dans le code des correctifs ci-dessus**

- **L'échec de suppression du fichier temporaire contenant le mot de passe
  était avalé en silence** (`contextlib.suppress(OSError)`). Sur Windows, un
  EDR qui verrouille un fichier fraîchement créé (cas documenté sur ce poste :
  conflit SentinelOne) transformait une exposition « de quelques
  millisecondes » en **mot de passe laissé en clair sur le disque
  indéfiniment, sans la moindre trace de log**. Remplacé par un `except
  OSError` explicite qui journalise l'échec (le nom du fichier n'est pas
  sensible, seul son contenu l'est).
- **`vm_pass` à `None` provoquait un crash non maîtrisé** : `_charger_secrets`
  se contente d'un `warn` si le secret est absent du coffre, et `vm_vbox_nom`
  est une clé indépendante — rien n'imposait que les deux soient renseignés
  ensemble. `f.write(None)` levait alors un `TypeError` **hors de tout
  `try`/`finally`**, laissant un fichier orphelin et une exception remontant
  jusqu'à l'appelant (où, levée depuis un bloc `except`, elle n'était rattrapée
  par aucun `except` frère). Identifiants validés en amont.
- **Le fichier de mot de passe subissait la traduction `
` → `
`** du
  mode texte de Python sous Windows (vérifié empiriquement) : un mot de passe
  contenant un saut de ligne littéral aurait été corrompu sur le disque lu par
  `--passwordfile`, causant un échec d'authentification silencieux. Corrigé
  par `newline=""`.
- **La boucle `while` accordait une tentative WinRM réelle de trop** : le
  `continue` post-récupération sautait l'incrémentation **quel que soit le
  rang**, portant le total à 4 tentatives au lieu de 3 même hors du cas limite
  visé — en contradiction avec le commentaire « max 3 tentatives » et les
  messages `retry X/3`, et au détriment du quota `MaxShellsPerUser=5` dont le
  code s'inquiète explicitement. Le bonus est désormais borné au seul rang 3.

Les 4 défauts du round 2 sont figés par des tests de régression dédiés,
**chacun vérifié par mutation**. Suite complète : 1104 tests, 94,06 % de
couverture, `ruff` et `mypy` propres.

Non résolu et signalé comme tel : le redémarrage du service WinRM via
`VBoxManage guestcontrol` échoue actuellement en `CouldNotStopService` sur la
VM de labo (authentification réussie, service impossible à ouvrir) — problème
d'état de la VM, hors de portée d'un correctif de code.


### Corrigé — SSRF DANS LE RAPPORT PDF VIA CONTENU NON ÉCHAPPÉ (revue de sécurité dédiée)

- **`generer_rapport_pdf()` (`rapport.py`) passait `description`/`raison` brutes
  à `Paragraph()` de reportlab**, qui interprète son texte comme un balisage
  XML/HTML restreint (`<b>`, `<font>`, `<a href>`, `<img src>`...) — jamais
  comme du texte brut. Ces deux champs peuvent provenir d'une découverte IA
  (description générée par le LLM, jamais filtrée par le garde-fou
  anti-destruction qui ne porte que sur `commande`) ou d'un import Atomic Red
  Team tiers. **Prouvé exploitable empiriquement** (pas seulement théorique) :
  un test de mutation retirant l'échappement a fait planter la génération
  avec `OSError: Cannot open resource 'http://attaquant.example/beacon.png'`
  — reportlab tentait réellement de télécharger l'URL injectée pendant la
  construction du PDF (SSRF vers l'infrastructure interne du labo, ou fuite
  d'IP/user-agent vers un serveur externe). Le générateur HTML du même
  fichier échappait déjà ces champs (`html.escape`, cohérent) ; le générateur
  PDF, ajouté plus tard dans le projet, avait divergé de cette discipline.
  Corrigé en appliquant `escape()` avant construction des `Paragraph()`
  (extrait dans `_ligne_tableau_pdf()`, au passage : la fonction dépassait la
  limite de complexité ruff une fois le correctif ajouté inline). Régression
  figée par test (`test_description_et_raison_sont_echappees_avant_reportlab`),
  vérifié par mutation.

### Corrigé — DÉCOUVERTE IA « JUSTE UN NOM » PEU FIABLE + PDF ABSENT DE L'HISTORIQUE (constat pré-soutenance)

Suite à la demande « je donne juste le nom de l'attaque, le reste doit être
automatique », vérification en conditions réelles (8 tentatives successives
sur « Pass the Hash », nom seul, aucune technique imposée) ayant révélé 3
bugs indépendants dans CADRE, chacun corrigé et revérifié, plus un problème
d'infrastructure externe (conflit SentinelOne/VirtualBox, voir plus bas) qui
a fait échouer les tentatives 5 à 7 malgré le code déjà corrigé. **Tentative
8 : succès complet** — `CADRE-IA-003 — Pass the Hash` → T1078.001 → statut
`VALIDE`, une fois l'infrastructure stabilisée — preuve que les 3 correctifs
ci-dessous tiennent réellement en conditions réelles, pas seulement en
théorie :

- **Bouton PDF absent de l'onglet Historique du dashboard.** `pdf_disponible`
  avait été ajouté à l'API (`lister_cycles`/`dernier_cycle`) et à la page
  statique `/rapports` lors d'un chantier précédent, mais **pas** à la vue
  SPA `historique.js` : la table `LIENS` (HTML/MD/CSV/Navigator) n'avait
  jamais reçu l'entrée PDF correspondante. Ajoutée avec une icône dédiée
  (`download`, ajoutée à `icones.js`) et l'attribut `download` (au lieu de
  `target="_blank"`) pour un téléchargement direct, cohérent avec la page
  statique. Vérifié en direct : `fetch()` renvoie `200`,
  `Content-Type: application/pdf`, `Content-Disposition: attachment`.
- **`valeur_detection` générée par l'IA : sous-chaîne à cheval sur
  l'exécutable et ses arguments (ex. "net.exe use"), invalide dès que
  Windows insère un guillemet après le chemin de l'exécutable dans le
  journal (`"C:\...\net.exe" use ...`)** → faux négatif garanti même quand
  l'attaque s'exécute correctement. Root-causé en rejouant la requête
  Lucene compilée contre l'événement réellement indexé (`net.exe use` → 0
  résultat, `\\cible\share` seul → 2 résultats) : c'est le même piège que
  celui déjà documenté pour d'autres exécutables (voir `catalogue_attaques.py`,
  ex. `rundll32.exe" /?`, `whoami.exe" /all`), mais jamais explicité dans le
  prompt de `suggerer_attaque()`. Ajouté comme règle unique et sans
  ambiguïté (« prends la valeur de détection entièrement dans les
  arguments ») plutôt qu'une consigne à deux branches que le modèle 7B ne
  suivait pas de façon fiable.
- **Course critique dans `_detecter_modele()` : un modèle jamais installé
  (`llama3.1:8b`) pouvait rester pinné à vie.** Juste après un
  (re)démarrage d'Ollama, `/api/tags` peut répondre avant que le registre
  de modèles ne soit chargé (liste vide alors que le serveur est joignable
  et les modèles bel et bien installés). Comme `obtenir_assistant_llm()`
  est un singleton mis en cache pour toute la durée du processus, une seule
  détection ratée au mauvais moment pinnait durablement le mauvais modèle —
  toute découverte échouait ensuite en boucle avec un 404 Ollama, même une
  fois Ollama pleinement disponible. Corrigé par 3 tentatives avec un court
  délai avant d'abandonner (délai total négligeable pour un serveur
  vraiment injoignable).

Deux effets de bord découverts en cours de vérification, documentés, pas des
bugs CADRE :
- `scripts/demarrer-environnement.ps1` affichait toujours « VM en démarrage »
  en vert même quand `VBoxManage startvm` échouait — le code de sortie
  n'était jamais vérifié. Corrigé (message d'erreur + astuce redémarrage sur
  échec).
- **Conflit EDR/hyperviseur (poste de développement, hors CADRE)** :
  VirtualBox (`VBoxHeadless.exe`, `VBoxNetDHCP.exe`) plantait
  systématiquement (`0xC0000005`, même offset sur les deux exécutables —
  signature d'un hook injecté par un composant tiers) au démarrage d'une VM.
  D'abord attribué à tort à une mise à jour Windows (corrélation d'un jour,
  trop faible) ; la vraie cause, confirmée par une corrélation à moins de 90
  minutes entre les logs d'installation de service Windows et le premier
  plantage, est l'agent SentinelOne installé le même jour sur ce poste —
  conflit connu et documenté entre agents EDR à hooks noyau et VirtualBox.
  Aucune action côté CADRE ; correction propre = exclusion de
  `C:\Program Files\Oracle\VirtualBox\*` dans la politique SentinelOne
  (nécessite un rôle Admin sur la console, pas Viewer).

### Corrigé — DÉCOUVERTE IA EN TIMEOUT SUR MATÉRIEL CPU-ONLY (constat pré-soutenance)

- **`TIMEOUT_GENERATION_SEC` (défaut 180s) insuffisant pour une inférence
  Ollama 100% CPU** (`size_vram: 0`, aucun GPU détecté, `qwen2.5-coder:7b`
  Q4_K_M) : un scénario réaliste (« Découverte IA » sur une technique
  ClickFix / faux CAPTCHA menant à Lumma Stealer) mesuré à **206s** en
  conditions réelles, contre un timeout configuré de 180s — la génération
  produisait une réponse JSON parfaitement cohérente, mais 26 secondes
  *après* que le code ait déjà abandonné, ce qui remontait un faux
  « IA injoignable ou réponse illisible » alors que le modèle fonctionnait
  normalement, juste lentement. Défaut remonté à 300s
  (`src/cadre/assistant_llm.py`), avec marge réelle au-dessus du pire cas
  mesuré. Reste configurable via `CADRE_OLLAMA_TIMEOUT_SEC` pour un poste
  avec GPU (bien plus rapide) ou au contraire encore plus lent. Revérifié
  en conditions réelles bout en bout (dashboard → dictée d'une description
  d'attaque → génération LLM → exécution réelle sur la VM → validation →
  déploiement Kibana) : succès, règle `CADRE-IA-002` déployée et visible
  au catalogue (67 attaques).

### Corrigé — RÈGLES KIBANA DÉPLOYÉES INEXÉCUTABLES (constat pré-soutenance)

- **`query` envoyé à l'API Kibana Detection Engine comme objet DSL sérialisé
  en JSON** (`json.dumps({"query_string": {"query": ...}})`) au lieu d'une
  chaîne Lucene brute + `language: "lucene"`. Le déploiement réussissait
  (200/201, Kibana ne valide pas la syntaxe à la création) mais **chaque
  exécution planifiée échouait** au parsing KQL dès le premier caractère `{`
  ("Expected ... but "{" found") — 127 des 129 règles CADRE constatées en
  échec dans Kibana, la règle de séquence EQL (chemin `language: "eql"`,
  correct) étant la seule épargnée. Corrigé aux deux points de déploiement
  (`deployer_kibana`, `redeployer_regle_editee`) ; les 124 règles déjà
  déployées ont été réparées en place (PUT, même `rule_id`, requête Lucene
  extraite du JSON cassé) sans relancer d'attaque. Régression figée par
  `test_query_avec_antislash_preservee_telle_quelle` (les deux occurrences),
  qui vérifiait auparavant le comportement cassé.
- **Isolation de test incomplète** (`tests/conftest.py`) : la fixture
  `isolation_environnement` supprimait certains secrets de l'environnement
  mais ne neutralisait ni `CADRE_DASHBOARD_PASSWORD` ni le trousseau OS
  (`keyring.get_password`, palier 2 de `coffre_fort.obtenir()`, hors de
  portée de `monkeypatch` sur `os.environ`) — dès qu'un vrai mot de passe
  dashboard est configuré sur le poste de dev, toute la classe
  `TestServeurHTTP` basculait en 401 sans lien avec le code testé. Keyring
  neutralisé pour la durée de chaque test.

### Corrigé — AUDIT COMPLET DU PROJET (22 constats, sécurité + moteur + CLI + tests/CI)

Audit à 4 angles (sécurité, moteur, CLI/intégrations, tests/CI/documentation)
suivi d'une correction exhaustive. Chaque correctif ci-dessous a été vérifié
par test de mutation (retour au comportement pré-correctif → le nouveau test
échoue bien → restauration du correctif → le test repasse au vert), en plus
de `ruff`/`mypy`/suite complète. Total : **1002 tests verts, 93,34 % de
couverture**.

#### Sécurité
- **RCE via `/api/regle/pousser`** : la route acceptait un chemin de fichier
  arbitraire côté serveur au lieu de se limiter au dossier des règles
  générées — corrigé par validation stricte du chemin.
- **`cadre scenario` n'acquérait jamais le verrou inter-processus F-009** :
  une kill chain pouvait s'exécuter en parallèle d'un `cadre cycle`, avec
  risque de contamination croisée des fenêtres de validation TP/FP.
  Nouvelle exception dédiée `VerrouCycleActifError` pour distinguer une
  collision de verrou (cas normal, message propre) d'une erreur arbitraire.
- **Filtre anti-destruction contournable** — durci contre les
  reformulations qui échappaient à la détection d'intention destructrice.
- **Mots de passe Windows en dur + fuite dans les logs** — retirés/masqués.
- **Injection YAML via `valeur_detection`** — assainissement avant
  sérialisation dans la règle Sigma générée.
- **Lot dashboard/coffre-fort/CLI** : plusieurs durcissements ponctuels
  découverts en auditant la surface HTTP du dashboard.

#### Moteur
- **Fail-open Elasticsearch → panne silencieuse** : `attente_indexation.py`
  retournait `0` en cas de panne ES, indiscernable d'un vrai zéro résultat.
  Nouvelle exception `ErreurComptageElastic` : on échoue franchement plutôt
  que de mentir sur l'absence de détection (fail-closed).
- **`risk_score` inversé** dans la règle Sigma générée : la sévérité
  `low/medium/high` ne se traduisait pas dans le bon sens. Corrigé avec
  `_RISK_SCORE_PAR_SEVERITE = {"low": 21, "medium": 47, "high": 73}`,
  aligné sur la convention des règles prébuilt Elastic.
- **Statut `EN_ATTENTE_REVUE` absent des statuts de rapport** : une attaque
  validée mais dont le déploiement était différé pour revue humaine
  (`cadre cycle --revue`) n'apparaissait dans aucun total de rapport/tableau
  de bord — trou de comptage. Enfilé dans `STATUTS_DETECTES`,
  `_ORDRE_STATUTS`, `_STATUTS_SUCCES` et l'affichage dashboard.
- **Isolation du mode `--parallel` incomplète** : l'historique de collision
  de `partitionner_pour_parallelisme()` ne comparait qu'au sein du lot en
  cours, pas contre tous les lots déjà placés — risque réel de collision de
  fenêtre de validation entre deux lots non adjacents.
- **Couverture kill chain surestimée** : les attaques en mode `SIMULE`
  comptaient comme preuve réelle de détection. Nouveau sous-ensemble
  `STATUTS_DETECTES_KILL_CHAIN` (exclut `SIMULE`), utilisé uniquement pour
  les affirmations de preuve réelle en kill chain.
- **Daemon qui meurt sur erreur d'écriture + pipeline figé en mode revue** —
  corrigés (gestion d'erreur explicite au lieu de laisser le process
  mourir/se bloquer silencieusement).
- **Injection CSV (CWE-1236)** dans l'export `cadre list --csv` : une valeur
  de cellule commençant par `=`/`+`/`-`/`@`/tabulation/retour chariot peut
  être interprétée comme une formule par Excel/LibreOffice à l'ouverture.
  Corrigé par `_defuse_formule_csv()` (préfixe `'`). Corrigés en même temps :
  rotation de `catalogue_actif` et résultats non réinitialisés entre deux
  cycles.

#### CLI
- **`VerrouCycleActifError` non rattrapé** : une collision de verrou
  remontait une stacktrace brute à l'utilisateur au lieu d'un message
  d'erreur propre. Nouveau helper `_signaler_verrou_actif_et_quitter()
  -> NoReturn`.
- **`cadre daemon` sous Windows lançait réellement la boucle en arrière-plan**
  au lieu de refuser proprement (le fork réel n'est supporté que sous
  Linux) — corrigé.
- **`logger.py`** : le flag `self.avec_couleur` était calculé mais jamais
  consulté (codes ANSI injectés même en sortie redirigée/fichier) ; ajout
  de la rotation de log (`_TAILLE_MAX_LOG_OCTETS = 10 Mo`) ; docstring
  corrigée.
- Validations mineures diverses côté CLI.

#### Tests / CI
- **Fixture `_verrou_isole` consolidée en `autouse` dans `conftest.py`** —
  élimine la duplication et les oublis silencieux entre modules de test.
  Une classe (`TestVerrouCycleInterProcessusViaId`) a besoin du vrai verrou
  non redirigé : override local documenté (même nom de fixture, portée plus
  étroite gagne).
- **`make ci` ne reproduisait pas fidèlement `.github/workflows/cadre-ci.yml`** :
  2 gates absentes localement, et les appels locaux à `bandit`/`pip-audit`
  étaient plus permissifs que ceux de la CI — un `make ci` vert en local ne
  garantissait donc pas un `cadre-ci.yml` vert. Corrigé pour miroir exact,
  étape par étape.
- **Documentation** : chiffres obsolètes alignés sur l'état réel du projet
  (`GUIDE_PROJET.md`, `README.md`, `ARCHITECTURE.md`) ; build Sphinx corrigé
  (dépendance `linkify-it-py` manquante, options de thème invalides, 2 bugs
  reStructuredText dans les docstrings de `catalogue_attaques.py`) et
  vérifié par un build HTML réel réussi ; 4 nouvelles pages de référence API
  (`coffre_fort`, `anonymisation`, `compilation_sigma`, `rapport`).

### Ajouté — COUVERTURE PRIVILEGE ESCALATION (62 → 65 attaques)

- **3 nouvelles attaques comblent un vrai manque du catalogue** :
  Privilege Escalation ne comptait qu'1/62 entrée (`CADRE-PRI-001`, UAC
  bypass). Initial Access reste volontairement hors scope (0 ajout) — le
  projet documente déjà explicitement que cette tactique n'est pas
  émulable depuis une exécution *sur* la cible (WinRM/SSH présuppose
  l'accès initial) ; y ajouter une attaque aurait contredit cette
  documentation.
  - **`CADRE-PRI-002`** (T1548.001, Linux) : chasse aux binaires SUID
    (`find / -xdev -perm -4000`). `-xdev` indispensable — vérifié en réel :
    sans lui, la commande a mis 4 min 49 s (parcourt `/proc`, `/sys`...) ;
    avec, 23 s.
  - **`CADRE-PRI-003`** (T1548.003, Linux) : énumération des droits sudo
    (`sudo -l`).
  - **`CADRE-PRI-004`** (T1098, Windows) : ajout d'un compte au groupe
    Administrateurs. Corrélation sur EventID 4732 (ajout à un groupe
    local) plutôt que 4672/4624 (privilèges spéciaux/logon) — **vérifiés
    en réel bien trop bruyants sur ce labo** (922/931 hits sur 7 jours,
    déclenchés par chaque connexion WinRM admin) contre 7 hits pour 4732.
    Champ de corrélation (`user.target.group.name`) et valeur
    (`"Administrateurs"`, le labo est en localisation française — pas
    `"Administrators"`) confirmés sur un document réel déjà indexé avant
    d'écrire la règle, pas devinés.
  - Extension de `_NATIVE_SERVICE_PAR_EVENT`/`_NATIVE_CHAMP_CORRELATION`
    (`src/cadre/orchestrateur.py`) pour l'EventID 4732.
  - Les 3 sont classées `indicateur_reel` (syntaxe/artefact réel, pas un
    marqueur) : TTP-first passe de 50/62 (81 %) à **53/65 (82 %)**.
  - **Vérifié en conditions réelles**, une attaque à la fois puis en
    cycle complet (séquentiel et `--parallel`) : les 3 nouvelles
    valident proprement (scores de confiance 96/98/100), 0 régression sur
    les 62 attaques existantes.
  - **+6 tests** ([tests/test_catalogue.py](tests/test_catalogue.py)).
    Suite complète : **682 tests verts**.

### Ajouté — PARALLÉLISME PRUDENT (G2, `cadre cycle --parallel`)

- **Le cycle complet (62 attaques) peut désormais s'exécuter avec jusqu'à 2
  attaques WinRM/validations simultanées**, borne dure volontairement non
  configurable. Item explicitement reporté lors de la revue finale
  (`REVUE/U3-corrections.md`) à cause d'un risque réel de contamination de
  la fenêtre de validation TP (`double_validation_tp_fp`, `now-600s`) entre
  deux techniques exécutées trop proches dans le temps — repris et traité
  une fois le temps disponible pour concevoir puis vérifier correctement.
  - **`partitionner_pour_parallelisme`** ([src/cadre/catalogue_attaques.py](src/cadre/catalogue_attaques.py))
    neutralise le risque **à la source** : une règle générique
    (`event.code` seul) reste toujours isolée, de même que deux règles dont
    les valeurs de corrélation textuelle sont en collision de sous-chaîne.
  - **`--parallel` opt-in**, jamais activé par `--demo` (avertissement
    explicite si combinés) et **structurellement inatteignable** par
    `cadre scenario` (une kill chain dépend d'un ordre chronologique réel
    pour la corrélation EQL).
  - État partagé (`_ctx_progression`, `resultats`) rendu thread-safe sans
    changer le comportement séquentiel (`threading.local`, collecte des
    résultats sur le thread principal uniquement). Verrou ajouté sur
    l'écriture du fichier de log (`Logger._ecrire_fichier`), trouvé pendant
    la conception.
  - **Vérifié en conditions réelles** (VM + Elasticsearch + Kibana) : petit
    lot contrôlé (5/5 validées), puis cycle complet des 62 techniques —
    **9 min 51 s contre 17 min 45 s en séquentiel (~45 % plus rapide)**,
    60 validées / 1 rejetée (bruit Linux, sans lien avec le parallélisme) /
    1 non applicable / 0 erreur / 0 angle mort. `--demo` rejoué ensuite en
    réel : comportement inchangé. Détail complet : `REVUE/U7-parallelisme.md`.
  - **+18 tests** ([tests/test_catalogue.py](tests/test_catalogue.py),
    [tests/test_orchestrateur.py](tests/test_orchestrateur.py),
    [tests/test_cli.py](tests/test_cli.py)), dont une preuve de concurrence
    réelle via `threading.Barrier`. Suite complète : **676 tests verts**.

### Corrigé — DÉPENDANCE RÉSEAU CACHÉE (export Kibana)

- **Le format d'export `kibana` (`siem_rule_ndjson`) déclenchait un téléchargement
  Internet** : pysigma enrichit chaque règle avec les données MITRE ATT&CK STIX
  qu'il récupère depuis GitHub (`urlopen`, timeout 30 s). Cela contredisait la
  posture **hors-ligne** du projet et rendait `test_kibana_est_un_ndjson`
  **non-déterministe** (échec sous `getaddrinfo failed` / read timeout hors-ligne).
  - Le code de production dégradait **déjà** proprement (`compiler_regles_multi`
    → `None` + log ; `export_sigma` saute le format via `if contenu:`) — aucun
    crash. Les formats **lucene** et **es-dsl** sont **100 % hors-ligne**.
  - **Test rendu déterministe** : `test_kibana_est_un_ndjson` **skip** si le format
    est indisponible hors-ligne (ne peut plus échouer sur l'environnement).
  - **Message de log actionnable** dans [compilation_sigma.py](src/cadre/compilation_sigma.py)
    (détecte la cause réseau/MITRE, indique les formats hors-ligne disponibles).
  - Dépendance documentée dans la description du format kibana.

### Sécurité & robustesse — AUDIT PRÉ-SOUTENANCE

Audit technique complet (fonctionnel + OWASP) ; 7 correctifs :

- **[Élevé] CSRF sur le dashboard** — les routes POST (`/api/cycle/lancer`,
  `/api/decouverte/lancer` qui lancent de **vraies attaques**, `/api/secrets` qui
  **écrit un secret**) n'avaient aucun contrôle d'origine. Ajout de
  `_origine_locale_ok()` : `Host` doit être loopback (bloque le DNS rebinding) et
  l'`Origin` présent doit être loopback (bloque le CSRF d'un site tiers). Vérifié
  en direct (Origin/Host tiers → 403, requête locale → passe).
- **[Moyen] XSS stocké sur le dashboard** — le JS interpolait des noms/commandes
  d'attaques **arbitraires** (atomics ART, suggestions IA) dans `innerHTML` sans
  échappement. Ajout d'un `esc()` HTML appliqué à **tous** les sinks (catalogue,
  matrice, cycles, logs, découverte, secrets).
- **[Moyen] `stats --json` non parsable** — la bannière décorative polluait
  stdout. Déplacée sur **stderr** (`console_err`) : stdout redevient du JSON pur.
- **[Moyen] Divergence `pyproject.toml` / `requirements.txt`** — pyproject épinglait
  `cryptography>=41` (réintroduisait PYSEC-2026-3552) et **omettait `paramiko`**
  (install packagé cassé côté Linux/SSH). Aligné : `cryptography>=50.0.0`,
  `paramiko`, `requests-ntlm`, `pysigma>=0.11`.
- **[Faible] DoS mémoire** — `_lire_corps_json` lisait un `Content-Length`
  arbitraire ; ajout d'un plafond de 1 Mio.
- **[Faible] Robustesse TOCTOU** — `_lire_csv` renvoie `[]` si le CSV a disparu
  (au lieu de `FileNotFoundError`).
- **[Faible] Code mort** — suppression des paquets vides `cadre/cli/` et
  `cadre/helpers/`.
- **+8 tests** de non-régression (CSRF, XSS, plafond corps, TOCTOU, JSON pur).

### Ajouté — INGESTION ATOMIC RED TEAM (source d'attaques)

- **CADRE ingère Atomic Red Team** ([src/cadre/atomic_red_team.py](src/cadre/atomic_red_team.py))
  comme **source d'attaques** communautaire (~1600 tests) — sans se laisser
  remplacer par elle. Chaque atomic YAML est parsé (vrai schéma ART :
  `attack_technique`, `atomic_tests`, `executor`, `input_arguments` interpolés),
  converti au modèle CADRE, puis passe **EXACTEMENT le même pipeline** que les
  attaques natives (exécution → télémétrie → règle Sigma → double validation
  TP/FP → déploiement).
  - **Filtre de sécurité réutilisé** (`commande_dangereuse`, partagé avec l'agent
    IA) : Atomic contient des tests **destructeurs** (chiffrement, effacement de
    journaux, arrêt machine…) — tout atomic correspondant à la denylist est
    **REFUSÉ avant toute exécution**. Cohérent avec la contrainte labo non-
    destructif. C'est le différenciateur : *CADRE homologue la source, il ne
    l'exécute jamais aveuglément.*
  - **Routage plateforme** : seuls les atomics `windows`/`linux` automatisables
    (executor non-`manual`) sont retenus ; macOS/cloud/`manual` sont ignorés,
    jamais devinés. Détection sur `process.command_line` (Windows) ou
    `process.title` (Linux). Tactique dérivée du catalogue natif.
  - **Nouvelle commande** `cadre atomic` : aperçu des atomics ingérables (sûrs vs
    refusés) ; `--import` les enregistre au catalogue personnel (ils rejoignent
    alors `cadre list`, `cadre cycle`, `cadre scenario`). `--repo <chemin>` pointe
    vers un checkout d'Atomic Red Team pour les ~1600 tests ; `--platform` et
    `--technique` filtrent.
  - **Jeu d'exemples embarqué** ([src/cadre/data/atomics_exemple/](src/cadre/data/atomics_exemple/)) :
    5 atomics au vrai format ART (3 sûrs retenus + 2 destructeurs refusés :
    `cipher /w`, `wevtutil cl`) — la fonctionnalité marche sans cloner le dépôt.
  - **+16 tests** ([tests/test_atomic_red_team.py](tests/test_atomic_red_team.py)) :
    parsing, filtre de sécurité, routage plateforme, conversion, CLI. Bandit 0/0.

### Ajouté — SCÉNARIOS D'ADVERSAIRE (kill chains)

- **CADRE émule désormais des campagnes d'attaque complètes**, pas seulement des
  techniques isolées. Un *scénario* enchaîne plusieurs attaques du catalogue
  **dans l'ordre d'une vraie kill chain** MITRE ATT&CK, puis mesure la
  **couverture de détection phase par phase**. C'est le différenciateur face à un
  émulateur classique (type Caldera) : CADRE **joue la chaîne ET homologue la
  détection** de chaque étape (génération + validation TP/FP + déploiement), là où
  l'émulation seule s'arrête à « la chaîne a été jouée ».
  - **4 scénarios déterministes** ([src/cadre/scenarios.py](src/cadre/scenarios.py)) :
    `RANSOMWARE` (7 phases, exécution→impact), `VOL_IDENTIFIANTS` (6 phases, type
    APT29), `RECONNAISSANCE` (6 phases, 100 % Discovery), `INTRUSION_LINUX`
    (6 phases, multi-OS). Chaque étape est une attaque **existante** du catalogue
    → reproductible à l'identique, contrairement à un planificateur autonome.
  - **Nouvelle commande** `cadre scenario --list` / `cadre scenario --id <ID>`
    (`--simulate` pour une démo sans VM). Affiche le déroulé de la chaîne dans le
    terminal (détectée / angle mort) + une synthèse de couverture.
  - **Rapport HTML « kill chain » dédié** (`generer_rapport_kill_chain`) :
    autonome (CSS/JS inline, zéro ressource réseau), thème clair/sombre, chaîne
    verticale phase par phase, KPI de couverture, liste des angles morts à combler.
  - **`analyser_kill_chain`** : analyse pure (couverture %, phases détectées,
    angles morts) réutilisable et testée.
  - Boucle d'exécution factorisée (`_boucle_attaques`) partagée entre
    `executer_cycle_complet` (catalogue) et `executer_scenario` (kill chain) —
    même logique d'exécution, aucune duplication.
  - **+15 tests** ([tests/test_scenarios.py](tests/test_scenarios.py)) : cohérence
    du catalogue (aucune référence cassée), analyse de couverture, rapport
    autonome, CLI. Suite complète : **497 tests verts**.

### Ajouté — CATALOGUE ÉTENDU (62 attaques)

- **+16 attaques Linux (catalogue v1.6) → 62 attaques au total** (42 Windows +
  20 Linux), **50 techniques MITRE, 11 tactiques**. Nouvelles techniques Linux
  couvertes : `T1082` (System Info), `T1083` (File Discovery), `T1057` (Process
  Discovery), `T1016` (Network Config), `T1049` (Network Connections), `T1033`
  (System Owner), `T1087.001` (Local Account), `T1518` (Software), `T1007`
  (Service Discovery), `T1069.001` (Groups), `T1070.003` (Clear History),
  `T1222.002` (File Permissions), `T1003.008` (/etc/passwd & shadow), `T1552.003`
  (Bash History), `T1485` (Data Destruction safe), `T1005` (Data Collection).
  **Chacune validée end-to-end en réel** (SSH → Auditbeat → règle → double
  validation TP/FP → déploiement Kibana ; 16/16 TP=1, FP=0). Détection sur
  `process.title` via marqueur distinctif.
- **Le lanceur démarre aussi la VM Linux** ([scripts/demarrer-environnement.ps1](scripts/demarrer-environnement.ps1)) :
  après la VM Windows, il réveille la VM Kali et attend le port SSH (22).
  Absente/éteinte = attaques Linux `NON_APPLICABLE`, le reste marche.

### Ajouté — SUPPORT LINUX (multi-OS)

- **CADRE devient multi-OS** : en plus des attaques Windows (WinRM), il exécute
  désormais les attaques Linux **par SSH** (`paramiko`) sur une VM cible Linux,
  avec télémétrie **Auditbeat** (module `auditd`, événements `execve` en ECS).
  - **Routage automatique par plateforme** (`_cible_pour_attaque`) : une attaque
    `windows` va vers WinRM + `winlogbeat-*`, une attaque `linux` vers SSH +
    `auditbeat-*`. Le chemin Windows est **strictement inchangé**.
  - **Détection Linux** : règle Sigma `logsource: product: linux`, détection sur
    `process.title` (ligne de commande reconstruite par auditd), compilée **sans
    le pipeline `ecs_windows`** (pipeline « aucun », car Auditbeat est déjà ECS).
  - **Attente d'indexation** en mode correspondance texte (wildcard sur
    `process.title`, champ keyword) pour Linux — pas d'EventID Windows.
  - **Config** : `CADRE_LINUX_VM_IP` / `_USER` / `_PORT` (env ou coffre) +
    `CADRE_LINUX_VM_PASS` (coffre). Absente = attaques Linux `NON_APPLICABLE`
    (comportement historique préservé).
  - **Les 4 attaques Linux** (`CADRE-LIN-001..004` : bash, cron, systemd,
    recherche de credentials) ont été **validées end-to-end en réel** (SSH →
    Auditbeat → règle → double validation TP/FP → déploiement Kibana ;
    TP≥2, FP=0 pour chacune). La limite « mono-OS » est **levée**.
  - Dépendance ajoutée : `paramiko>=3.4`. Exceptions Bandit documentées
    (`# nosec B507`/`B601`) : VM jetable host-only, commandes issues du
    catalogue audité / denylist IA.

### CI/CD & qualité

- **Pipeline CI renforcé** ([`.github/workflows/cadre-ci.yml`](.github/workflows/cadre-ci.yml)) :
  `mypy` devient **bloquant** (le code passe le typage proprement, la CI
  l'exige maintenant au lieu de `continue-on-error`) ; le scan de dépendances
  passe de `safety` (déprécié, exige un compte) à **`pip-audit`** (gratuit,
  recommandé PyPA/OpenSSF). Une exception documentée et unique
  (`PYSEC-2026-2447`, `diskcache` transitif de pySigma, sans correctif publié)
  garde la CI verte sans masquer d'autres vulnérabilités.
- **Cible `make ci`** : rejoue **exactement** les 6 gates du CI en local
  (black, ruff, mypy, pytest+couverture 75 %, bandit, pip-audit) — pour ne
  jamais pousser un build rouge. Tous les gates vérifiés verts en local
  (474 tests, 85,8 % de couverture).

### Ajouté

- **Export multi-format (multi-SIEM)** (`compilation_sigma.py:compiler_regles_multi`,
  `FORMATS_SORTIE`) : `cadre export-sigma` produit désormais, en plus des règles
  Sigma sources, les requêtes compilées prêtes à l'emploi — **Lucene**
  (`cadre_lucene.txt`), **Elasticsearch Query DSL** (`cadre_es_dsl.json`) et
  surtout un **bundle Kibana Security** (`cadre_kibana_import.ndjson`)
  **importable en un clic** via *Security → Rules → Import* (46 règles d'un
  coup). Aucune dépendance ajoutée (le backend Elastic déjà installé fournit
  ces 5 formats). Architecture prévue extensible à d'autres SIEM (Splunk,
  Sentinel) via l'installation du backend pysigma correspondant. 10 tests.
- **Durcissement production du transport WinRM** (`orchestrateur.py`) : le
  transport est désormais entièrement configurable via variables
  d'environnement — `CADRE_WINRM_SCHEME` (http→https), `CADRE_WINRM_PORT`
  (5985→5986), `CADRE_WINRM_TRANSPORT` (ntlm→kerberos), `CADRE_WINRM_CERT_VALIDATION`
  (ignore→validate). Le défaut laboratoire (http/5985/ntlm/ignore) est
  **strictement inchangé**. L'endpoint est construit dynamiquement
  (`https://<vm>:5986/wsman`). Au passage, la config non-secrète
  (`CADRE_VM_IP`, `CADRE_ELASTIC_URL`, `CADRE_KIBANA_URL`, `CADRE_INDEX_PATTERN`)
  est enfin lue depuis l'environnement (lacune corrigée : elle était ignorée).
  Priorité : défaut < variables d'environnement < config passée au constructeur.
  Documenté dans `docs/SECURITY.md` (§4 bis). 6 tests dédiés.
- **`cadre valider-regle`** (`validation_regle.py`) : valide une règle Sigma
  **existante** (ex. SigmaHQ) contre **votre** télémétrie Elasticsearch, sans
  exécuter d'attaque ni toucher la VM. Verdict : `NON_COMPILABLE`,
  `SILENCIEUSE`, `ACTIVE` ou `BRUYANTE`. Réponse directe à « on installe
  SigmaHQ et voilà » : CADRE dit **lesquelles fonctionnent et lesquelles
  noient le SOC** sur l'environnement réel.
- **`cadre export-sigma`** (`export_sigma.py`) : exporte les 46 règles du
  catalogue au format Sigma standard partageable (+ `index.md`) — pour une
  contribution open-source ou l'import dans un autre SIEM.
- **Rapport de cycle exportable en PDF** : bouton « Imprimer / PDF » dans
  le rapport HTML interactif, avec style d'impression dédié (fond clair,
  boutons masqués) et dépliage automatique des règles Sigma avant impression.
  Zéro dépendance ajoutée (impression navigateur → « Enregistrer en PDF »).

### Corrigé

- **Encodage des CSV pour Excel/LibreOffice** : les exports CSV sont désormais
  écrits en `utf-8-sig` (UTF-8 + BOM). Sans ce BOM, Excel les ouvrait en
  Windows-1252 et affichait les accents en mojibake (« RÃ¨gle » au lieu de
  « Règle »). Les lecteurs internes utilisent `utf-8-sig` pour retirer le BOM.

- **Matrice de couverture MITRE ATT&CK dans le dashboard**
  (`construire_matrice`, endpoint `/api/matrice`) : les 14 tactiques de la
  kill-chain en colonnes, chaque technique du catalogue en cellule, colorée
  selon son **statut réel** — validée par un cycle réussi (vert), testée non
  validée (ambre) ou au catalogue (gris). Les 3 tactiques amont
  (Reconnaissance, Resource Development, Initial Access) sont affichées
  grisées et documentées comme **hors périmètre par conception** (elles
  précèdent l'accès à la cible). Vue « ATT&CK Navigator » de la couverture,
  qui montre honnêtement les angles morts assumés. Se rafraîchit après chaque
  cycle.
- **6 nouvelles attaques (catalogue v1.3) → 46 attaques, 45 techniques,
  11 tactiques** : `T1083` File/Directory Discovery, `T1518` Software
  Discovery, `T1140` Deobfuscate/Decode (certutil), `T1552.004` Private Keys,
  `T1074.001` Local Data Staging, `T1571` Non-Standard Port. Toutes utilisent
  le **motif de détection le plus fiable** du projet (valeur littérale dans
  l'argument `-Command` de powershell.exe, préservée telle quelle par Windows —
  contourne les pièges de normalisation), et **chacune a été validée en cycle
  réel** (TP≥1, FP=0, règle déployée dans Kibana).
- **Agent IA offensif autonome, sous garde-fous** (`decouverte_ia.py`,
  `cadre decouvrir`, bouton dans le dashboard) : le LLM **génère de nouvelles
  attaques par lui-même**, CADRE les exécute dans le labo isolé et n'ajoute au
  catalogue que celles **validées** (TP/FP). Trois garde-fous, en défense en
  profondeur : (1) **filtre anti-destruction** — une denylist stricte rejette
  toute commande destructrice (effacement, chiffrement, désactivation de
  sécurité, arrêt machine, dropper, scan de masse…) AVANT toute exécution ;
  (2) **isolation** — exécution sur la VM host-only, jamais ailleurs ;
  (3) **barrière de validation** — rien conservé sans preuve de détection.
  *Le LLM propose, les garde-fous disposent.* Le lancement exige une
  confirmation explicite (attaques réelles).
- **Dashboard enrichi (dataviz)** : graphique en barres « Couverture par
  tactique MITRE » (série unique, teinte laiton, tooltips au survol), et
  panneau « Agent IA autonome » avec suivi en direct des attaques découvertes
  / refusées.
- **Génération de règles par LLM, gardée par la même validation**
  (`cadre cycle --generation llm`, config `mode_generation_regle`) : le LLM
  peut désormais **rédiger la règle Sigma réellement candidate au
  déploiement** — mais elle passe par la MÊME compilation + double validation
  TP/FP que la règle déterministe, et n'est déployée que si elle **prouve**
  qu'elle détecte l'attaque. Le déterministe reste le défaut (reproductible) ;
  le mode LLM retombe automatiquement sur lui si le LLM est injoignable, rend
  du vide, ou produit une règle non compilable — une attaque ne peut jamais
  échouer à cause du LLM. Principe : *la source de confiance est la
  validation, pas le générateur.* Robustesse de la génération LLM : envoi
  d'un log **compact** (les champs de détection seulement, le log brut
  noyait un modèle 7B), prompt à **structure Sigma explicite**, et
  **remplacement de l'`id`** par un UUID valide (les LLM en hallucinent
  souvent un invalide). Vérifié en réel : le LLM produit une règle qui
  compile et se valide ; le repli fonctionne quand il échoue.
- **Catalogue élargi : 34 → 40 attaques, +6 techniques MITRE** (33 techniques
  de base au lieu de 27). Six nouvelles attaques Discovery natives Windows,
  **chacune vérifiée en conditions réelles** (exécutée sur la VM → captée par
  Sysmon → règle validée TP/FP → déployée dans Kibana, 6/6 validées) :
  T1049 (netstat), T1007 (tasklist /svc), T1069.001 (net localgroup),
  T1201 (net accounts), T1033 (whoami /all), T1012 (reg query clé Run).
  Chaque `valeur_detection` a été relevée sur un document Elasticsearch réel
  (normalisation Windows : `NETSTAT.EXE` majuscules, `net`→`net1`, guillemets),
  jamais devinée — méthode qui garantit qu'une attaque ajoutée se détecte
  vraiment plutôt que de gonfler le catalogue avec des faux négatifs.
- **Dashboard auto-explicatif** : bandeau d'introduction (« à quoi sert
  CADRE » + les 3 étapes d'usage), une ligne d'aide sous chaque panneau
  (état de la stack, lancer un cycle, identifiants, IA, catalogue, logs), et
  une légende en clair des statuts (VALIDÉE / REJETÉE / ANGLE MORT / NON
  APPLICABLE). Un non-expert comprend l'outil sans explication externe.
- **Démarrage sans attente ressentie** : le lanceur ouvre désormais le
  dashboard immédiatement (~5 s) et démarre Docker/SIEM/VM en parallèle en
  arrière-plan ; la vérification globale se rafraîchit toute seule toutes
  les 8 s jusqu'à ce que tout soit vert (plus besoin de recliquer).
- **Vérification globale en un clic** dans le dashboard
  (`verification_globale()`, `GET /api/verifier`) : bilan complet et lisible
  (stack Elasticsearch/Kibana, VM, identifiants critiques, assistant IA,
  catalogue) sous forme de points /, avec un verdict `tout_ok` qui ignore
  les briques optionnelles (Ollama). Bouton « Tout vérifier » en tête de
  page.
- **Panneau « Identifiants » corrigé et clarifié** : il listait les secrets
  via `lister_cles()`, qui n'énumère que l'environnement et le `.env` — donc
  affichait « Aucun secret configuré » alors que les secrets réels sont dans
  le trousseau système. Nouveau `statut_secrets()` teste la résolution
  réelle (trousseau inclus) et affiche chaque identifiant attendu avec un
  point vert/rouge « configuré / à définir ». Le champ de saisie est passé
  en menu déroulant des clés attendues (plus besoin de connaître les noms).
  Détail d'erreur de connexion raccourci pour l'UI (plus de stack trace
  brute dans un panneau).
- **Lanceur en un double-clic** (`DEMARRER-CADRE.bat` +
  `scripts/demarrer-tout.ps1`) : démarre tout l'environnement (Docker, SIEM,
  VM), lance le dashboard web et ouvre le navigateur — zéro commande à taper.
  Un raccourci « Demarrer CADRE » est posé sur le Bureau. Toute
  l'utilisation (configurer les secrets, générer des attaques par IA, lancer
  des cycles, lire les rapports) se fait ensuite dans le dashboard.
- **Catalogue extensible par IA** (`catalogue_utilisateur.py`, nouveau
  module) : le catalogue n'est plus figé à 34 attaques. `cadre suggest
  --enregistrer --id CADRE-PERSO-00X` valide un brouillon d'attaque proposé
  par l'assistant LLM et l'ajoute à un **catalogue personnel persistant**
  (`~/.cadre/catalogue_perso.json`). Ces attaques rejoignent
  `catalogue_actif()` (natif + perso) et sont exécutées aux prochains
  cycles par l'orchestrateur, le CLI (`cycle`, `list`) et le dashboard.
  **Garantie centrale préservée** : elles suivent EXACTEMENT le même
  pipeline que les natives — exécution WinRM, règle Sigma déterministe,
  double validation TP/FP, et déploiement **uniquement si elles passent la
  validation**. L'IA propose, la validation dispose ; elle ne décide jamais
  seule un déploiement. Le socle natif `CATALOGUE` reste immuable et testé
  (34 attaques) — `catalogue_actif()` est le point d'entrée qui fusionne
  sans jamais le muter. Vérifié en réel : une attaque ajoutée via ce flux
  a traversé tout le pipeline jusqu'au déploiement Kibana (TP=1, FP=0).
- **Métriques de valeur métier** (`metriques.py`, nouveau module) :
  transforme les résultats bruts d'un cycle en indicateurs quantifiés —
  temps d'ingénierie économisé (estimation basée sur une hypothèse
  **explicite et configurable** : ~1,6 h par règle écrite à la main, jamais
  un chiffre inventé présenté comme mesuré), couverture MITRE ATT&CK réelle
  (tactiques/techniques distinctes couvertes), et bruit résiduel **médian**
  par règle (médiane plutôt que moyenne pour ne pas être faussée par les
  règles baseline volontairement bruyantes). Exposé partout : section
  « Valeur métier » du rapport de cycle, commande `cadre metriques`,
  bandeau de KPI en tête du dashboard (`GET /api/metriques`). Sur un cycle
  réel : 24 règles produites (80 %), ~38 h économisées, 10/11 tactiques
  couvertes (90,9 %), 13 FP/règle médian.
- **`cadre dashboard`** (`dashboard.py`) : dashboard web local (bibliothèque
  standard uniquement, même approche que `cadre metrics`) devenu un
  véritable poste de pilotage :
  - Cycles déjà exécutés (liste + détail par statut) et rapports déjà
    générés (HTML/CSV/Markdown/layer Navigator), servis avec garde anti
    path-traversal.
  - **État de la stack** (Elasticsearch/Kibana/VM) — même logique que
    `cadre status`.
  - **Catalogue** en lecture seule, filtrable.
  - **Secrets** : liste des clés configurées (jamais les valeurs) et
    formulaire pour en définir de nouvelles, via le coffre-fort habituel
    (donc journalisé comme tout accès au coffre-fort).
  - **Brouillon d'attaque IA** (`cadre suggest`) directement depuis le
    navigateur.
  - **Lancement de cycle, simulation ou réel.** Un cycle réel touche la
    vraie VM/SIEM configurés : la route `POST /api/cycle/lancer` exige un
    champ `confirmer: true` explicite dans le corps de la requête, sinon
    elle refuse (400) — aucun bouton de l'interface ne peut contourner
    cette garde silencieusement. Un seul cycle à la fois (verrou partagé
    `EtatCycle`), quel que soit le mode.
  Bind `127.0.0.1` par défaut, aucune authentification — même frontière de
  confiance que la CLI elle-même, qui exécute déjà des cycles réels sans
  confirmation ; la confirmation ajoutée ici protège contre un clic
  accidentel, ce n'est pas un modèle de sécurité multi-utilisateurs.
- **`site/index.html` réécrit intégralement** : l'ancienne version
  contenait des témoignages clients et une grille tarifaire entièrement
  fabriqués (CADRE n'a ni client ni offre commerciale), ainsi que des
  chiffres périmés (12 attaques au lieu de 34, compilation Sigma dite via
  CLI). Remplacé par une page qui ne cite que des faits vérifiables
  (statistiques du catalogue, résultat de la suite de tests, limites
  assumées explicitement listées) et une section "État du projet" dédiée
  à la transparence.

- `scripts/demarrer-environnement.ps1` : démarre automatiquement Docker
  Desktop, le SIEM (`CADRE_SIEM/docker-compose.yml`), la VM cible
  VirtualBox, vérifie Ollama, puis lance `cadre status` — remplace la
  routine manuelle par une seule commande. Chaque étape attend que la
  précédente réponde réellement avant de continuer.
- **Filtrage par plateforme cible** : une attaque dont `plateforme` ne
  correspond pas à `config["plateforme_cible"]` (ni `"both"`) est
  désormais marquée `NON_APPLICABLE` avant tout appel WinRM, au lieu de
  remonter en `ERREUR`. Le taux de réussite des rapports (`rapport.py`)
  exclut ces entrées du dénominateur.
- **Seuil de faux positifs par attaque** : nouveau champ
  `seuil_fp_max: int | None` sur `AttaqueCatalogue`, qui prime sur le
  seuil global (`config["seuil_fp_max"]`) quand renseigné. Utilisé pour
  `CADRE-EXE-001`, dont le signal est naturellement bruyant.
- **`cadre cycle --dry-run`** : affiche les attaques qui seraient
  exécutées (avec leur statut de compatibilité plateforme) sans jamais
  instancier `OrchestrateurCADRE` ni toucher WinRM/Elasticsearch.
- **`cadre list --csv <fichier>`** : exporte le catalogue complet en CSV.
- Badges CI/Codecov dans le README (pointent vers le dépôt GitHub prévu,
  s'activent au premier run CI après publication).
- **Mode verbeux/silencieux configurable** : `cadre --verbose` (`-v`)
  abaisse le seuil console du logger à `DEBUG` ; `cadre --quiet` (`-q`)
  le relève à `WARN`. La sortie fichier JSON (`logs/cadre.log.json`)
  reste toujours complète — seule la verbosité console change
  (`logger.py` : `_RANG_NIVEAU`, `CADRELogger.evenement()`).
- **Journal d'audit du coffre-fort** : chaque lecture (`obtenir`),
  écriture (`stocker`) et suppression (`supprimer`) d'un secret est
  désormais tracée via le logger (`SECRET_READ`/`SECRET_WRITE`/
  `SECRET_DELETE`), avec la clé et la source/méthode — **jamais la
  valeur du secret**. Un accès en échec (clé introuvable, suppression
  sans effet) est journalisé en `WARN`.
- **Rapport HTML autonome** (`rapport.py` : `generer_rapport_html()`) —
  même contenu que le rapport Markdown, CSS inline, aucune dépendance
  externe, généré automatiquement à chaque fin de cycle.
- **Export MITRE ATT&CK Navigator** (`rapport.py` :
  `generer_layer_navigator()`) — layer JSON v4.5 (couleur par statut,
  meilleur statut retenu si une technique est testée par plusieurs
  attaques) importable directement sur
  `mitre-attack.github.io/attack-navigator`, généré à chaque fin de
  cycle à côté du rapport.
- **`cadre cycle --ia-draft-regles`** : demande en plus à l'assistant
  LLM (Ollama) un brouillon de règle Sigma par attaque, à partir du log
  anonymisé réellement collecté (`AssistantLLM.suggerer_regle_sigma()`).
  Affiché à côté de la règle déterministe dans le rapport, sous un
  intitulé explicite « brouillon IA, non validé, non déployé ». Ce
  brouillon n'est **jamais** compilé, jamais soumis à la double
  validation TP/FP, jamais déployé — le chemin critique
  génération/validation/déploiement continue d'utiliser exclusivement
  la règle déterministe. Désactivé par défaut (coûteux, ~1-2 min/appel
  LLM) ; une panne Ollama ne fait jamais échouer l'attaque (défense en
  profondeur dans `_generer_brouillon_regle_ia()`).
- **`cadre cycle --timeout-indexation <s>`** : rend configurable le délai
  d'attente d'un événement avant de déclarer un angle mort (défaut 180 s).
  C'est le poste de coût dominant d'un cycle — chaque angle mort attend ce
  délai en entier — donc le baisser accélère nettement une démo (au prix
  d'un risque de faux angle mort si l'indexation est lente).

### Performance (cycle réel)

- **Pause inter-attaques supprimée quand elle ne sert à rien** : la pause
  de 5 s (2 s en simulation) laissait retomber la charge côté cible/SIEM,
  mais s'exécutait aussi après la dernière attaque (plus rien ne suit) et
  pour les attaques `NON_APPLICABLE` (aucun appel WinRM/Elastic, donc rien
  à laisser retomber). Sur un cycle complet à dominante Windows, ça
  économise ~25 s de pure attente sans rien changer au comportement.

### Corrigé

- **Assistant LLM : auto-détection du modèle Ollama installé**
  (`assistant_llm.py`). Le modèle par défaut était codé sur `llama3.1:8b` ;
  si l'utilisateur avait un autre modèle (cas réel : `qwen2.5-coder`),
  `cadre suggest` échouait silencieusement. Désormais, en l'absence de
  `CADRE_OLLAMA_MODEL` explicite, CADRE interroge `/api/tags` et choisit un
  modèle réellement installé (préférence douce llama3 > qwen2.5 > mistral >
  phi > gemma, sinon le premier disponible). Marche sans configuration sur
  n'importe quelle machine ; retombe sur le défaut historique si le serveur
  ne répond pas.
- **Trois faux négatifs de détection résolus (cycle réel : 23/30 → 25/30),
  chacun vérifié contre un document Elasticsearch réel avant/après :**
  - `compilation_sigma.py::valider_syntaxe_lucene()` comptait un guillemet
    **échappé** (`\"`) dans l'équilibre des guillemets, rejetant en
    `SYNTAXE_INVALIDE` une requête pourtant valide dès qu'une valeur de
    détection contenait un guillemet. Corrigé pour ignorer les `\"`.
  - `CADRE-EXE-005` (rundll32) : `valeur_detection` était `rundll32.exe /?`,
    mais Windows normalise la commande en `"...\\rundll32.exe" /?` — un
    guillemet s'intercale, donc la sous-chaîne n'existait pas. Corrigé en
    `rundll32.exe" /?` (forme normalisée exacte).
  - `CADRE-COM-001` (curl) : la commande utilisait `curl`, qui est un
    **alias PowerShell de `Invoke-WebRequest`** — aucun process `curl.exe`
    n'était donc créé. Forcé en `curl.exe`.
- **`coffre_fort.py::lister_cles()` — fuite des variables système,
  découverte en exposant cette méthode via `cadre dashboard`** : la
  méthode unionnait tout `os.environ` (des centaines de variables —
  `PATH`, `USERNAME`, variables d'IDE...) au lieu de se limiter aux
  secrets réellement gérés par CADRE. Sans conséquence grave en CLI
  (`cadre init --list` restait un outil local que l'utilisateur lance sur
  sa propre machine), mais une vraie fuite d'information une fois exposée
  via une réponse HTTP. Corrigé : ne retient désormais que les variables
  d'environnement préfixées `CADRE_`, en plus des clés déjà présentes
  dans le fichier `.env`. Préexistant, pas introduit par le dashboard —
  révélé par lui. Test de régression :
  `test_lister_cles_ne_fuit_pas_les_variables_systeme`.
- **`cli.py` — bug réel découvert en développant `--dry-run`** : la
  commande `list` était définie comme `def list():`, masquant le
  builtin Python `list()` dans **tout le module** — ce qui cassait
  silencieusement `cadre cycle --technique ...` et `cadre loop
  --webhook ...` (tous deux appelaient `list(...)` en interne, résolu
  vers la commande Click au lieu du builtin). Préexistant, pas introduit
  par ce lot. Renommé en `list_attaques()` (le nom visible `cadre list`
  est inchangé grâce à `@cli.command(name="list")`).

### Corrections (infrastructure SIEM, hors code CADRE)

- `CADRE_SIEM/docker-compose.yml` : ports Elasticsearch/Kibana restreints
  à `127.0.0.1` (ils étaient exposés à tout le réseau local), ajout de
  `restart: unless-stopped` + healthchecks, secrets déplacés vers un
  `.env` non commité, mot de passe `kibana_system` régénéré proprement
  (l'ancien contenait des guillemets littéraux suite à une erreur de
  configuration d'origine).

---

## [1.5.0] - 2026-07-31

### Correctifs — moteur de détection (le premier cycle réel révélait un Faux Négatif systématique)

Le tout premier cycle non-simulé jamais exécuté (après connexion correcte
VM ↔ SIEM) a révélé que la double validation TP/FP échouait toujours,
malgré une collecte de télémétrie parfaite. Root cause : la génération de
règle Sigma n'avait jamais été testée en conditions réelles (tous les
cycles précédents tournaient en `--simulate`, qui saute cette étape).

- **`orchestrateur.py`** : `SIGMA_TEMPLATE` codait en dur
  `process.command_line|contains: 'CADRE_TEST_<id>'` pour **toutes** les
  attaques, quel que soit leur signal réel — et ce marqueur n'était de
  toute façon **jamais injecté** dans la commande exécutée par
  `executer_commande_winrm()`. Toute attaque dont le signal n'était pas
  dans `process.command_line` (création de compte, service, registre,
  DNS, accès mémoire...) ne pouvait structurellement jamais matcher.
  Remplacé par une déduction automatique du `logsource` et du champ de
  corrélation à partir de l'EventID réel de l'attaque (tables
  `_SYSMON_EVENT_INFO`, `_POWERSHELL_EVENT_INFO`,
  `_NATIVE_SERVICE_PAR_EVENT`, `_NATIVE_CHAMP_CORRELATION`), vérifiées
  contre le pipeline `pysigma` installé et contre des documents réels
  indexés (ex : sur un événement 4720, `user.name` porte l'auteur de
  l'action et **non** le compte créé — c'est `user.target.name`).
- **`catalogue_attaques.py`** : nouveau champ optionnel
  `valeur_detection` sur `AttaqueCatalogue` — un texte **déjà présent
  dans la commande réelle de l'attaque** (jamais une valeur injectée à
  part), peuplé pour les 34 attaques. `event_ids_attendus` réordonné pour
  quelques attaques (ex : DNS, registre) afin que l'EventID le plus
  pertinent pour la détection soit en première position.
- **Bug de chaînage `&&`/`&` invalide en PowerShell 5.1** — découvert en
  testant en réel : `Le jeton '&&' n'est pas un séparateur d'instruction
  valide`. ~18 commandes du catalogue utilisaient un chaînage façon
  `cmd.exe` (`commande1 && commande2`) directement comme source
  PowerShell (elles sont exécutées dans un bloc `Try { ... }` PowerShell),
  ce qui échouait systématiquement — invisible jusqu'ici car aucun cycle
  réel n'avait tourné sur ces attaques. Remplacé par `;` (séparateur
  PowerShell valide, sémantiquement équivalent ici grâce à
  `$ErrorActionPreference = 'SilentlyContinue'` déjà en place). Un cas
  (`CADRE-COL-001`) est passé par un `cmd.exe /c "..."` explicite plutôt
  que `;`, car il dépend spécifiquement de la syntaxe `copy /Y`, non
  comprise par l'alias PowerShell `Copy-Item`.
- **`CADRE-EXE-002`** : `timeout /t 1` échoue sous WinRM (« la
  redirection de l'entrée n'est pas prise en charge » — `timeout.exe`
  exige une console interactive absente en session WinRM). Remplacé par
  `ping -n 2 127.0.0.1 >nul`, équivalent non-interactif classique.

### Correctifs supplémentaires (découverts en validant le cycle complet sur les 34 attaques)

Un premier cycle complet (post-correctifs ci-dessus) a fait remonter
8/34 validées — suffisant pour prouver que le mécanisme fonctionne, mais
avec des causes racines distinctes encore à traiter par attaque :

- **`2>nul` invalide sous PowerShell/WinRM** (9 attaques) : contrairement
  à `cmd.exe`, PowerShell ne traite pas `nul` comme le périphérique nul —
  il essaie d'ouvrir un `FileStream` littéral, ce qui échoue en session
  WinRM non-interactive (« FileStream devait ouvrir un périphérique qui
  n'était pas un fichier »). Remplacé partout par `2>$null` (syntaxe
  PowerShell correcte).
- **`WMIC` (`CADRE-EXE-004`)** : `process.command_line` n'est pas un
  champ analysé/insensible à la casse, et Windows normalise `wmic` en
  `WMIC.exe` (casse d'origine sur disque) dans le command_line réel — la
  règle ne matchait donc jamais. `valeur_detection` déplacé vers un
  argument tapé par nous (`processid`), dont la casse est garantie.
- **`rundll32` (`CADRE-EXE-005`)** : `valeur_detection="rundll32"` était
  trop générique et matchait aussi des tâches système légitimes
  (`Startupscan.dll,SusRunTask`) — resserré à `"rundll32.exe /?"`.
- **`sc create` (`CADRE-PER-003`)** : `sc` est un alias PowerShell
  intégré pour `Set-Content`, pas `sc.exe` (Service Control) — la commande
  échouait silencieusement et le service n'était jamais créé. Invocation
  explicite en `sc.exe`.
- **`2>&1` sur commande native (`CADRE-LAT-001`)** : bug connu de
  PowerShell 5.1 — rediriger le stderr d'une commande native l'enveloppe
  dans un `NativeCommandError` qui fait échouer l'appel WinRM même à exit
  code 0. Redirection supprimée (inutile, `$ErrorActionPreference =
  'SilentlyContinue'` gère déjà le silence).
- **`Compress-Archive` sur dossier vide (`CADRE-COL-002`)** : échoue
  silencieusement si le dossier source est vide, ce qui faisait ensuite
  échouer le `Remove-Item` de nettoyage sur un fichier jamais créé. Un
  fichier de test est maintenant placé dans le dossier avant compression.
- **Latence d'indexation transitoire** : `double_validation_tp_fp()`
  déclarait parfois un `FAUX_NEGATIF` alors que l'événement existait
  bien, juste pas encore visible par la requête de validation (délai
  near-real-time Elasticsearch + harvest Winlogbeat, plus sensible en
  cycle chargé). Ajout d'un retry unique après 3s avant de conclure à un
  vrai Faux Négatif.
- **Windows Defender/AMSI actif (`CADRE-COM-002`)** : `certutil
  -urlcache` est bloqué par l'antivirus (« Ce script dont le contenu est
  malveillant a été bloqué »). Limite d'environnement, pas un bug CADRE —
  Defender est censé être désactivé sur cette VM de labo par conception ;
  à vérifier manuellement côté VM.

### Performance

- **`compiler_sigma_vers_lucene()`** appelait `sigma-cli` en
  sous-processus (relance un interpréteur Python complet à chaque
  attaque, ~1-2s de overhead). Remplacé par un appel direct à l'API
  Python de `pysigma` (`SigmaCollection` + `LuceneBackend`) en mémoire —
  mesuré à ~10ms par compilation, soit environ 150x plus rapide sur cette
  étape. Plus de fichier temporaire, plus de dépendance au binaire
  `sigma-cli` pour le chemin critique (reste disponible en extra optionnel
  pour un usage manuel).

### Ajouté

- Rapport de cycle (`rapport.py::generer_rapport_cycle`) restructuré en
  sections groupées par statut (validées / non déployées /
  rejetées / angles morts / erreurs) au lieu d'un unique tableau
  plat mélangeant tout, plus lisible pour un usage réel.
- `scripts/verifier-tout.ps1` : regroupe en une seule commande la
  vérification qualité du code (tests/lint/format/typage), l'état de
  l'environnement (SIEM + VM) et un cycle d'audit réel complet.

### Validé

- Les correctifs initiaux ont été vérifiés individuellement en conditions
  réelles (non-simulé) : `CADRE-DIS-001`, `CADRE-EXE-002`,
  `CADRE-PER-001`, `CADRE-PER-004`.
- Les correctifs supplémentaires ont chacun été diagnostiqués par
  inspection directe de documents Elasticsearch réels et/ou d'appels
  WinRM de diagnostic, avant correction.

### Limite connue (hors scope de ce correctif)

- Les 4 attaques Linux (`CADRE-LIN-00x`) restent compilées avec le
  pipeline `-p ecs_windows` (le seul utilisé par
  `compiler_sigma_vers_lucene()`), qui ne correspond pas au modèle
  `auditd`/Linux — leur validation TP/FP réelle n'est pas garantie.
  Nécessiterait un pipeline `ecs_linux` dédié.

### Nettoyage — dépendances fantômes et diagramme désynchronisé du code

Audit de cohérence code/documentation en préparation de la soutenance :

- **Dépendances jamais importées nulle part dans `src/`**, retirées de
  `pyproject.toml` et `requirements.txt` : `jinja2` (la génération Sigma
  utilise `str.format()`, pas de moteur de template), `pydantic`,
  `tabulate`, `markdown`, `python-dateutil`.
- **`rapport.py`** : le diagramme d'architecture ASCII du rapport de
  soutenance décrivait une "Zone 3 — Attaquant" (Kali Linux, Metasploit,
  Sliver C2) et mentionnait "Atomic Red Team" comme vecteur d'attaque sur
  la VM cible — aucun des deux n'existe dans le code réel (le catalogue
  déterministe de `catalogue_attaques.py`, exécuté directement depuis
  l'hôte via WinRM, est le seul vecteur d'attaque). Diagramme corrigé
  pour refléter l'architecture à 2 zones réellement implémentée.

### Correctifs supplémentaires (2ᵉ passe, après un cycle complet à 16/34)

- **Bug structurel — code de sortie natif propagé comme échec WinRM** :
  `executer_commande_winrm()` considérait l'appel comme échoué dès que le
  processus `powershell.exe` distant ne rendait pas l'exit code 0 — or
  PowerShell propage le `$LASTEXITCODE` de la **dernière commande
  native** comme son propre code de sortie de processus, y compris pour
  les attaques dont l'échec de la commande testée est le résultat
  *attendu* (ex: `CADRE-LAT-001`, authentification avec mauvais mot de
  passe pour tester la détection d'échec de logon). Le `Try/Catch`
  existant ne suffisait pas à absorber ce cas puisqu'aucune exception
  .NET n'est levée pour un simple exit code natif non-nul. Corrigé par
  un `; exit 0` final explicite, conforme à l'intention déjà documentée
  dans le code ("l'important est que la commande ait été lancée").
- **`service.name` (ECS) n'existe pas** dans les documents winlogbeat
  réels pour le provider "Service Control Manager" (EventID 7045,
  canal System) — confirmé par inspection directe de documents indexés.
  Remplacé par `winlog.event_data.ServiceName` (champ non-ECS mais
  réellement peuplé) dans `_NATIVE_CHAMP_CORRELATION`.
- **`nslookup` ne déclenche jamais Sysmon EventID 22** (DNS Query), avec
  ou sans serveur explicite — l'outil utilise toujours son propre
  résolveur interne (hérité de BIND), jamais l'API de résolution
  standard de Windows que Sysmon hooke. Remplacé par `Resolve-DnsName`
  (cmdlet PowerShell natif) dans `CADRE-EXF-001`, confirmé
  empiriquement générer l'événement attendu avec le bon domaine.
- **`cipher /w` bloquait l'appel WinRM** : l'option `/w` écrase l'espace
  libre de tout le volume contenant le dossier cible (pas seulement ce
  dossier), une opération pouvant prendre plusieurs minutes — largement
  au-delà du timeout WinRM (30s), faisant échouer `CADRE-IMP-002` à
  tort après 3 tentatives. Remplacé l'appel direct par
  `Start-Process cipher.exe` (sans `-Wait`), qui génère l'événement
  ProcessCreate attendu sans bloquer l'appel WinRM.

### Limite d'infrastructure découverte (pas un bug CADRE)

- Les événements DNS (Sysmon EventID 22) sont indexés avec un
  `@timestamp` figé très en arrière dans le temps par rapport à l'heure
  réelle d'exécution (observé : ~30h de décalage), alors que les autres
  types d'événements (ProcessCreate, RegistryEvent, événements de
  service) ont un horodatage correct. Comme la double validation TP/FP
  ne cherche que dans les 10 dernières minutes, `CADRE-EXF-001` échoue
  systématiquement malgré une règle correcte et un événement réellement
  présent dans l'index — cause probable côté Sysmon/ETW ou horloge VM,
  hors du code CADRE. À investiguer côté configuration VM/Sysmon.
- **`CADRE-IMP-001`** : le fichier `.txt` est bel et bien créé (confirmé
  par lecture directe sur la VM) mais Sysmon ne génère aucun événement
  FileCreate — la plupart des configurations Sysmon (dont la config en
  place) excluent volontairement les fichiers texte génériques de la
  surveillance FileCreate pour limiter le bruit. Réglage Sysmon côté VM,
  pas un bug CADRE.
- **`CADRE-EVA-002`/`CADRE-LAT-002`** : le contenu exact de commandes
  PowerShell encodées triviales n'apparaît pas dans les événements
  ScriptBlockLogging (EventID 4104) générés, malgré 4104 actif et
  abondant pour d'autres script blocks — probablement un réglage GPO
  ("Log Script Block Invocation Logging") à ajuster côté VM.
- **`CADRE-CRE-002`/`CADRE-EXF-002`** : `procdump`/`rclone` ne sont très
  probablement pas installés sur la VM de labo (best-effort assumé dès
  la conception du catalogue).

### Correctifs supplémentaires (3ᵉ passe, après un cycle complet à 17/34)

- **`CADRE-DIS-004`** : même piège que WMIC — Windows résout `net` en
  chemin complet (`"C:\Windows\system32\net.exe"`), donc la sous-chaîne
  littérale `"net user /domain"` n'apparaît jamais dans la vraie ligne
  de commande. `valeur_detection` resserré à `"user /domain"` (survit à
  la normalisation du chemin). Confirmé en réel : TP=2, FP=10, validée.

### Corrections infrastructure VM (hors code CADRE, faites en session avec l'utilisateur)

- **Décalage d'horodatage ETW/DNS (~38h)** : résolu par un redémarrage
  complet de la VM (les sessions ETW de Sysmon gardaient une référence
  temporelle figée depuis un pause/reprise antérieur — un simple
  rechargement de config `sysmon64.exe -c` ne suffisait pas, il fallait
  réinitialiser les sessions ETW elles-mêmes). `CADRE-EXF-001` valide
  maintenant (TP=1, FP=4).
- **Contenu ScriptBlockLogging non capturé** pour les commandes
  PowerShell encodées triviales : résolu en activant explicitement
  "Journaliser l'invocation des débuts et fins de blocs de script" via
  `gpedit.msc` (Modèles d'administration → Composants Windows →
  Windows PowerShell). `CADRE-EVA-002` et `CADRE-LAT-002` valident
  maintenant.
- **Profil réseau retombant sur "Public" après redémarrage de VM**,
  bloquant WinRM : résolu de façon permanente via une stratégie
  Network List Manager ("Réseaux non identifiés" → type d'emplacement
  "Privé"), plus fiable qu'un correctif manuel à refaire à chaque boot.

### Fiabilité — retry TP/FP renforcé

- Le retry unique de 3s dans `double_validation_tp_fp()` ne suffisait
  pas toujours sous charge (plusieurs attaques enchaînées) — des règles
  correctes (déjà validées lors de cycles précédents) retombaient
  parfois en `FAUX_NEGATIF` par pure latence d'indexation. Remplacé par
  un backoff progressif à 3 tentatives (3s, 5s, 8s = 16s cumulés max)
  avant de conclure à un vrai Faux Négatif.

---

## [1.4.0] - 2026-07-31

### Interface CLI habillée avec rich

`rich` était déjà une dépendance déclarée (`pyproject.toml`,
`requirements.txt`) mais jamais utilisée dans le code — toute la sortie
passait par de simples `click.echo()`. Cette version l'exploite
réellement pour une interface en couleur, cohérente et lisible.

### Ajouté

- Bannière CADRE en panneau centré (remplace l'ASCII art brut)
- `cadre list` : tableau coloré (risque low/medium/high en vert/jaune/rouge)
- `cadre stats` : résumé + tableaux tactiques/risques côte à côte ;
  nouveau flag `--json` pour retrouver la sortie JSON brute (scripts, `jq`)
- `cadre status` : tableau d'état des services au lieu de lignes brutes
- `cadre cycle` : synthèse finale dans un panneau, couleur par statut
- `cadre suggest` : brouillon IA affiché en JSON coloré syntaxiquement
  (`rich.syntax.Syntax`), toujours dans un encadré magenta — la couleur
  dédiée au contenu généré par IA, jamais utilisée pour un résultat
  déterministe, pour qu'on ne les confonde jamais visuellement
- Palette cohérente sur toute la CLI : cyan (identité CADRE), vert/jaune/
  rouge (succès/attention/danger), magenta (IA)

### Corrections

- `logger.py` : la détection "le terminal supporte-t-il la couleur ?"
  utilisait `sys.stdout.isatty()` seul, insuffisant sur Windows (faux
  positif possible sans support ANSI réel) et incohérent avec la nouvelle
  détection `rich` utilisée par la CLI. Les deux s'appuient maintenant sur
  la même détection robuste (`rich.console.Console().is_terminal`).

### Notes

- Aucune nouvelle dépendance : `rich` était déjà installée, seulement
  jamais appelée.
- La couleur se désactive automatiquement hors terminal (tests, CI,
  redirection vers un fichier `>`) — comportement natif de `rich`, aucune
  configuration nécessaire.

---

## [1.3.0] - 2026-07-30

### Extension du catalogue — Privilege Escalation et Collection

Extension du catalogue de 26 à **34 attaques**, avec deux nouvelles
tactiques MITRE ATT&CK jusqu'ici absentes (**Privilege Escalation**,
**Collection**), et un renforcement des tactiques les moins couvertes
(Lateral Movement, Command and Control, Credential Access).

### Ajouté

- `CADRE-PRI-001` — T1548.002 Bypass UAC (détournement de registre
  fodhelper, sans élévation réelle) — première attaque *Privilege
  Escalation* du catalogue
- `CADRE-COL-001` — T1005 Data from Local System (copie/suppression de
  fichier) — première attaque *Collection*
- `CADRE-COL-002` — T1560.001 Archive Collected Data via Utility
  (Compress-Archive)
- `CADRE-COM-002` — T1105 Ingress Tool Transfer (certutil), renforce
  Command and Control (1 → 2 attaques)
- `CADRE-LAT-002` — T1021.001 Remote Desktop Protocol (test de
  connectivité), renforce Lateral Movement (1 → 2 attaques)
- `CADRE-CRE-003` — T1552.001 Credentials In Files (Windows)
- `CADRE-CRE-004` — T1558.003 Kerberoasting (requête SPN)
- `CADRE-LIN-004` — T1552.001 Credentials In Files (variante Linux)

Credential Access passe de 2 à 5 attaques (le double compte de T1552.001
Windows + Linux). Catalogue désormais à **34 attaques / 11 tactiques /
33 techniques uniques**.

### Notes

- Volontairement non couvertes : **Initial Access** et **Reconnaissance**
  — ces tactiques décrivent des actions qui précèdent l'accès à la
  machine cible et ne peuvent pas être émulées de façon significative
  depuis une commande WinRM exécutée *sur* la cible.
- Le commentaire d'en-tête du catalogue ne recopie plus de compte
  d'attaques figé (source d'obsolescence répétée) — `cadre stats` reste
  la seule source de vérité pour ces chiffres.

---

## [1.2.0] - 2026-07-30

### Assistant LLM local (Ollama)

Ollama était déjà scaffoldé (`docker-compose.yml`, `.env.example`) et même
mentionné dans le rapport de soutenance généré, mais aucun code ne l'appelait
réellement. Cette version comble cet écart avec un assistant IA **en couche
d'assistance**, jamais dans le chemin critique de génération, de validation
ou de déploiement des règles — qui reste 100% déterministe.

### Ajouté

- Nouveau module `src/cadre/assistant_llm.py` : client Ollama minimal
  (`AssistantLLM`), dégradation gracieuse totale si Ollama est injoignable
  (aucune fonctionnalité existante n'est affectée)
- `cadre suggest -d "description" [-t T1234] [-o fichier.json]` : brouillon
  d'attaque (champs `AttaqueCatalogue`) proposé par le LLM à partir d'une
  description en langage naturel — jamais inséré automatiquement dans le
  catalogue, toujours marqué `brouillon_ia: true`
- `cadre cycle --llm` : ajoute une synthèse exécutive et des pistes
  d'investigation pour les angles morts dans le rapport Markdown généré
- Nouvelle section « Synthèse IA » dans `generer_rapport_cycle`,
  clairement étiquetée comme non déterministe/consultative

### Corrections

- `generer_rapport_soutenance` affirmait que la règle Sigma était générée
  « via LLM local (Ollama) » alors que la génération est déterministe par
  catalogue depuis la v1.0 — le texte reflète maintenant la réalité du
  pipeline et le rôle réel de l'assistant IA

### Notes

- `cadre suggest` et `cadre cycle --llm` nécessitent Ollama actif
  (`docker compose up -d ollama` puis `ollama pull llama3.1:8b`) ; sans
  Ollama, ces fonctionnalités se désactivent proprement sans faire échouer
  le reste du pipeline

---

## [1.1.0] - 2026-07-28

### Extension catalogue + automatisation

Cette version étend le catalogue de 12 à **26 attaques MITRE ATT&CK**
(Ajout de 11 attaques Windows v1.1 + 3 attaques Linux) et introduit le
mode simulation, la boucle automatisée et l'export Prometheus.

### Ajouté

#### Catalogue étendu (12 → 26)
- 11 nouvelles attaques Windows : VBScript (T1059.005), WMIC (T1047),
  rundll32 (T1218.011), Windows Service (T1543.003), Registry Run Key
  (T1547.001), Process Listing (T1057), Domain Account Discovery
  (T1087.002), LSASS Handle (T1003.001), HTTP C2 (T1071.001), Cloud
  Upload (T1567.002), Data Destruction (T1485)
- 3 attaques Linux : Bash (T1059.004), Cron (T1053.003), systemd
  (T1546.004)
- Couvre désormais **9 tactiques MITRE** et **26 techniques uniques**

#### Mode simulation (sans VM)
- Nouvelle méthode `_executer_attaque_simulation()` dans `orchestrateur.py`
- Flag CLI `--simulate` / `-s` sur `cadre cycle`
- Génère la règle Sigma + compile Lucene + produit les rapports sans
  toucher la VM cible — utile pour démos, dev, CI/CD
- Statut dédié `SIMULE` dans les rapports

#### Boucle automatisée (`cadre loop`)
- Nouveau module `src/cadre/boucle.py` avec classe `BoucleAutomatisee`
- Rotation des techniques (sous-ensemble par cycle)
- Intervalle configurable (`--intervalle`, `--max-cycles`,
  `--techniques-par-cycle`)
- Notifications Slack/Discord/Teams (`--webhook`)
- Notifications email SMTP (`--email`, `--smtp-*`)
- Statistiques cumulatives persistées dans
  `rapports/cadre_cumulatif.json`
- Arrêt propre sur Ctrl+C (SIGINT/SIGTERM)

#### Daemon + métriques Prometheus
- `cadre daemon --pidfile ./cadre.pid` (Linux) : mode arrière-plan
- `cadre metrics --port 9090` : exposition métriques Prometheus
  (`cadre_cycles_total`, `cadre_validees_total`, `cadre_rejetees_total`,
  `cadre_angles_morts_total`, `cadre_erreurs_total`) + endpoint
  `/health`

#### Améliorations pipeline
- UUID v4 valide pour les règles Sigma (au lieu d'un hash court)
- Template Sigma pré-calculé (corrige bug `'str' object has no attribute 'replace('`)
- Retry WinRM avec backoff exponentiel (3 tentatives, 2s/4s)
- Pré-check connectivité VM via socket TCP port 5985
- Anonymisation stricte : `user.name`, `host.name`, etc. toujours hashés
- Multi-id dans `cadre cycle --id X --id Y --id Z`
- Fix UnicodeEncodeError cp1252 sur Windows (reconfigure UTF-8 + logo ASCII)

#### Tests
- 89 → **146 tests verts** (`pytest tests/ -q`)
- Nouveau fichier `tests/test_boucle.py` (rotation, simulation, connectivité)
- Tests adaptés à la vraie API (`lister_attaques`, `fichier_log=`, hash 17 chars, etc.)

#### Documentation
- Nouveau `GUIDE_TRANSFER.md` : guide ultra-complet partageable (19 sections)
- Nouveau `CONTEXT_HANDOFF.md` : résumé conversation pour reprise
- Catalogue inchangé dans `docs/`

### Corrections
- `requirements-dev.txt` : retrait de la ligne `trivy` (n'est pas un package PyPI)
- `pyproject.toml` : retrait de `collect_ignore` invalide

### Notes
- Mode `--simulate` produit des règles et rapports mais ne valide PAS
  contre Elastic (TP/FP = 0 par construction)
- Le daemon Linux utilise `os.fork()` (pas dispo sur Windows)

---

## [1.0.0] - 2026-07-16

### Première release stable

C'est la première version de CADRE, un pipeline CI/CD de détection
entièrement automatisé. Cette release est le fruit d'un travail de
recherche et développement de 6 mois (PFA 2026).

### Ajouté

#### Catalogue
- 12 attaques MITRE ATT&CK couvrant 7 tactiques
- 7 catégories : Execution (T1059.001, T1059.003), Persistence
  (T1136.001, T1053.005), Discovery (T1087.001, T1057),
  Credential Access (T1003.002), Lateral Movement (T1021.002),
  Defense Evasion (T1518.001, T1027), Exfiltration (T1048.003),
  Impact (T1070.004)
- Catalogue immutable via `@dataclass(frozen=True)`
- Fonctions : `obtenir_attaque`, `obtenir_par_technique`,
  `obtenir_par_tactique`, `statistiques_catalogue`

#### Sécurité
- Coffre-fort multi-backend (Windows Credential Manager, macOS
  Keychain, Linux Secret Service)
- Chiffrement Fernet (AES-128-CBC + HMAC-SHA256) pour le fallback
  fichier
- Module d'anonymisation RGPD-by-design avec hash déterministe
- Support PII : IPv4, IPv6, email, username, domaine Windows,
  hash MD5/SHA, NTLM, JWT, token Bearer, password, MAC address,
  chemins Windows

#### Orchestrateur
- Cycle complet automatisé (9 étapes)
- Exécution WinRM avec NTLM, timeout 30s, retry x3
- Attente d'indexation adaptative (polling 3s → 15s)
- Génération de règles Sigma **déterministe** (pas de LLM)
- Compilation Sigma → Lucene via `sigma convert`
- Double validation TP/FP :
  - TP : ≥ 1 hit sur fenêtre 10 min
  - FP : ≤ 50 hits sur fenêtre 7 jours
- Déploiement automatique dans Kibana via
  `/api/detection_engine/rules`

#### Rapports
- Markdown structuré pour audit RSSI
- CSV pour analyse Excel
- JSON pour forensic
- Rapport de soutenance PFA dédié

#### Interface CLI
- `cadre init` : configuration interactive des secrets
- `cadre cycle` : audit complet ou ciblé (par ID, technique)
- `cadre status` : health check de la stack
- `cadre list` : liste des attaques du catalogue
- `cadre stats` : statistiques du catalogue
- `cadre rapport` : génération de rapport

#### Infrastructure
- Docker Compose : Elasticsearch 8.13, Kibana 8.13, Ollama
- Dockerfile python:3.13-slim avec utilisateur non-root
- Healthchecks configurés
- Volumes persistants

#### Documentation
- README.md complet
- INSTALL.md (7 sections)
- ARCHITECTURE.md (diagrammes + flux)
- THREAT_MODEL.md (analyse STRIDE)
- SECURITY.md (politique + RGPD)
- WHITE_PAPER.md (commercial)
- Site web de présentation (index.html)

#### Tests
- `test_catalogue.py` : intégrité et API
- `test_coffre_fort.py` : stockage/récupération
- `test_anonymisation.py` : hash, dict, logs Elastic
- `test_compilation_sigma.py` : validation Lucene
- Couverture cible : ≥ 75 %

#### CI/CD
- GitHub Actions multi-OS (Python 3.11, 3.12, 3.13)
- Lint (black, ruff, mypy)
- Tests avec couverture
- Audit sécurité (bandit, safety, trivy)
- Build & publication PyPI sur tag
- Audit CADRE hebdomadaire (cron)

### Sécurité
- Modèle de menace STRIDE complet
- Politique de divulgation responsable
- Aucun secret commité par défaut
- Anonymisation systématique avant tout rapport

### Conformité
- AGPL-3.0 (version open-source)
- Licence commerciale disponible (sans copyleft)
- Compatible RGPD (anonymisation par défaut)
- Compatible NIS2 (traçabilité complète)

### Notes de release
- Cette release est destinée à un usage en **environnement de test**
- Le passage en production nécessite l'application des recommandations
  du `SECURITY.md` (WinRM HTTPS, secrets rotation, etc.)
- Le support Linux est en roadmap (v1.1)
- Le support Wazuh/Splunk est en roadmap (v1.2)

### Remerciements
- MITRE ATT&CK (framework de référence)
- SigmaHQ (format de règles)
- Atomic Red Team (inspiration)
- Elastic (stack ELK)
- Ollama (LLM local)
- Communauté open-source

---

## [0.9.0] - 2026-06-01 (bêta)

### Ajouté
- Première version bêta
- Catalogue de 8 attaques
- Exécution WinRM basique
- Génération Sigma manuelle

### Problèmes connus
- 100 % d'angles morts (logs non collectés)
- Pas de validation TP/FP
- Pas d'anonymisation (RGPD non conforme)
- Secrets en clair dans le code

---

## [0.5.0] - 2026-04-01 (alpha)

### Ajouté
- POC initial
- 3 attaques (T1059.001, T1136.001, T1087.001)
- Connexion Elastic basique

---

## Liens

- [Repository GitHub](https://github.com/Mohamed-Amine-Eddari/cadre)
- [Issues](https://github.com/Mohamed-Amine-Eddari/cadre/issues)
- [Releases](https://github.com/Mohamed-Amine-Eddari/cadre/releases)

[1.0.0]: https://github.com/Mohamed-Amine-Eddari/cadre/releases/tag/v1.0.0
[0.9.0]: https://github.com/Mohamed-Amine-Eddari/cadre/releases/tag/v0.9.0
[0.5.0]: https://github.com/Mohamed-Amine-Eddari/cadre/releases/tag/v0.5.0
