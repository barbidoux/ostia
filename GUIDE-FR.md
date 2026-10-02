# Ostia — guide de pilotage du développement avec Claude Code

Ce guide est pour toi, le propriétaire du projet (« owner »). Tout le reste du dépôt est en anglais ;
ce fichier est le seul en français. Il explique comment démarrer le dépôt, comment faire avancer Claude
work package par work package, et à quels moments ton intervention est indispensable.

## 1. Ce que contient le kit

| Élément | Rôle |
|---|---|
| `CLAUDE.md` | Mémoire de projet chargée à chaque session : carte du dépôt, commandes, invariants d'architecture. Importe `AGENTS.md`. |
| `AGENTS.md` | Règles non négociables pour tout agent (test d'abord, jamais toucher aux tests verrouillés, quand s'arrêter et demander). |
| `.claude/settings.json` | Permissions (autorisé / à confirmer / interdit) et branchement des hooks. |
| `.claude/hooks/guard_files.py` | Bloque toute modification des « rails », des tests verrouillés, l'ajout de `skip`/`xfail`/`#[ignore]`, l'`unsafe` hors liste ; demande ton accord pour toute suppression d'avertissement (`# noqa`, `#[allow]`…). |
| `.claude/hooks/guard_bash.py` | Bloque force-push, `--no-verify`, `git tag`, `just lock`, merge/publish, écriture shell sur les rails, appels à VirusTotal ou à des dépôts de malwares, écriture sur un vrai disque. |
| `.claude/hooks/session_start.py` | À chaque démarrage, reprise ou compaction : rappelle la branche, la phase, les verrous, les notes de travail. |
| `.claude/rules/*.md` | Règles par type de fichier (Rust, Python, tests, contrats, sécurité, UI), chargées seulement quand Claude touche ces fichiers. |
| `.claude/skills/` | Commandes `/wp-start`, `/wp-implement`, `/wp-finish`, `/phase-lock`, `/phase-gate`. |
| `.claude/agents/` | Sous-agents de revue indépendante : `reviewer` (code) et `test-auditor` (qualité des tests). |
| `prompts/00-bootstrap.md` | Le tout premier message à coller dans Claude Code. |
| `prompts/P0.md` … `P9.md` | Brief de chaque phase : ordre des WP, conseils techniques, pièges, points d'arrêt, contenu des tests d'acceptation de la phase suivante. |
| `tools/kit/req.py` | Affiche un WP et le texte intégral des exigences qu'il cite (`req.py WP-1.8`, `req.py FR-06`, `req.py phase P2`). |
| `tools/lock/ostia_lock.py` | Verrouillage des tests d'acceptation (manifeste SHA-256 + tag git), vérification, exécution de porte dans un pytest isolé ; manifeste des rails (`tools/lock/RAILS.sha256`). |
| `tools/kit/rails.just` | Recettes `just` du kit, importées par le `justfile` (dont les recettes réservées : `lock`, `relock`, `rails-update`). |
| `tools/kit/test_kit.py` | Auto-test du kit (hooks, verrouillage, rails, recherche d'exigences) : une cinquantaine de tests. |
| `docs/spec.md`, `docs/plan.md` | Spécification v0.2 et plan de développement (101 WP), exportés des documents Claude. |
| `docs/phase-status.md` | Phase en cours et cases à cocher par WP ; la phase et les portes ne sont modifiées que par toi. |
| `docs/questions.md` | Où Claude consigne ses questions bloquantes. |
| `.github/` | `CODEOWNERS`, workflow `rails.yml` (auto-test du kit, verrous et manifeste des rails à chaque push), modèle de merge request. |
| `justfile` | Importe `tools/kit/rails.just` ; complété par Claude au WP-0.1. |

**Principe.** Claude ne peut pas modifier les rails (règles, hooks, prompts, spec, plan, outils de verrouillage,
tests verrouillés) : les permissions refusent, les hooks bloquent, et le workflow `rails` rattrape ce qui
passerait quand même (manifeste `RAILS.sha256` des fichiers de rails, manifestes `LOCK.sha256` des tests,
comparés aux tags). Les modifications des tests et de la configuration de test passent obligatoirement par
les outils d'édition de Claude, que le hook inspecte (ajout de `skip`, suppression d'assertions, filtres de
collecte…). Toi seul verrouilles, tagues, merges, mets à jour le manifeste des rails et coches les portes.

## 2. Prérequis sur ta machine (WSL2 Debian)

1. WSL2 avec Debian stable, systemd activé (`/etc/wsl.conf` : `[boot]` puis `systemd=true`, puis `wsl --shutdown`).
2. `git`, `python3` (3.12 de préférence), `gh` (GitHub CLI) authentifié, Claude Code installé **dans WSL**.
3. Le reste (Rust, uv, just, buf, outils de systèmes de fichiers, bubblewrap, ClamAV…) : Claude en dresse la
   liste au bootstrap et te donne les commandes ; c'est toi qui les lances.

## 3. Initialiser le dépôt

```bash
mkdir -p ~/dev/ostia && cd ~/dev/ostia
unzip ~/Downloads/ostia-claude-kit.zip -d .        # le contenu du zip à la racine
sed -i 's/@OWNER/@<ton-pseudo-github>/' .github/CODEOWNERS
git init -b main
python3 tools/lock/ostia_lock.py rails-update      # CODEOWNERS a changé : on ré-enregistre les rails
git add -A
git commit -m "chore: rails kit (Claude Code configuration, spec v0.2, plan)"
python3 -m unittest tools/kit/test_kit.py           # doit afficher OK
gh repo create ostia --private --source . --push    # privé tant que le nom n'est pas validé
```

Puis, sur GitHub (le WP-0.9 le documentera en détail) :
- protéger `main` : pull request obligatoire avec **0 approbation requise** (c'est toi qui ouvres les PR que
  Claude prépare, et GitHub interdit d'approuver sa propre PR ; ta relecture puis ton merge font office de
  validation), check `rails` requis dès maintenant, check `ci` requis une fois le WP-0.1 mergé (le job s'appellera
  `ci`), pas de force-push ;
- règles de tags (rulesets) : toi seul peux créer ou déplacer les tags `lock-*` et `v*` ;
- méthode de merge : **« Rebase and merge » ou « Create a merge commit », jamais « Squash »** — le squash
  efface la preuve que le commit `test(...)` précède le commit `feat(...)`.

## 4. Lancer Claude Code

```bash
cd ~/dev/ostia
claude
```
- Accepte la confiance du dossier. Vérifie avec `/hooks` que les trois hooks apparaissent et avec
  `/permissions` que les règles sont chargées.
- Mode de permission : le mode par défaut, ou « accept edits » une fois en confiance. **N'utilise jamais
  le mode qui saute toutes les permissions** : les commandes « ask » (push, ajout de dépendances, sudo, réseau)
  sont tes points de contrôle.
- Colle le contenu de `prompts/00-bootstrap.md` (la partie entre les deux traits). Claude vérifie le kit,
  l'environnement, lit le brief P0 et s'arrête en attendant ton feu vert.

## 5. La boucle de travail, pour chaque work package

1. **`/wp-start WP-0.1`** — Claude vérifie les prérequis, crée la branche `wp/0.1-...`, extrait les exigences,
   écrit son plan de tests dans `.wp-notes/WP-0.1.md` (non versionné) et liste ses questions.
   → **Toi** : lis le plan de tests et les questions. Réponds, ou dis « go ».
2. **`/wp-implement`** — rouge → vert → refactor, exigence par exigence, avec un commit `test(REQ)` puis
   un commit `feat(REQ)`. Claude s'arrête de lui-même s'il bloque trois fois, s'il a besoin d'une dépendance,
   d'un privilège ou d'une décision.
3. **`/wp-finish`** — `just check`, revue par les sous-agents `reviewer` et `test-auditor`, corrections,
   coche du WP dans `docs/phase-status.md`, texte de merge request. Claude te demande l'autorisation de pousser
   et d'ouvrir la merge request.
4. **Toi** : relis la merge request (en priorité : les tests et leur premier échec, les dépendances ajoutées,
   les contrats modifiés, la section « Left open »), puis merge sur GitHub.
5. Reviens sur `main` (`git switch main && git pull`) et lance le WP suivant. Pour démarrer une phase :
   « Phase P1. Lis prompts/P1.md puis lance /wp-start WP-1.1 ».

Conseil : un WP par session de Claude Code quand c'est possible (`/clear` entre deux WP). Les notes
`.wp-notes/` et le hook de démarrage permettent de reprendre proprement après une compaction ou le lendemain.

## 6. Verrouiller les tests d'acceptation (fin de chaque phase)

Le dernier WP de chaque phase (WP-0.12, 1.12, 2.10…) écrit les tests d'acceptation de la phase suivante
avec **`/phase-lock P<n>`** (commande que toi seul déclenches). Claude livre : les tests, un README
(exigence → tests → raison de l'échec actuel → WP qui les fera passer), les contrats nécessaires
(schéma de rapport, CLI…), et la preuve que tous échouent pour la bonne raison.

**Ta revue** (c'est le moment le plus important du projet) : chaque MUST de la phase est-il couvert ? les valeurs
attendues sont-elles écrites en dur et justes ? un test pourrait-il passer avec une implémentation fausse ?
Puis, dans ton propre terminal (pas via Claude, qui en est empêché), sur la branche du WP de verrouillage :

```bash
just lock p1                 # et `just lock common` au premier verrouillage
git add tests/acceptance && git commit -m "chore(lock): lock p1 acceptance tests"
git tag -s lock-p1 -m "lock p1"      # -s si tu as une clé GPG/SSH de signature, sinon -a
git push origin lock-p1              # (et lock-common la première fois)
git push                             # puis merge de la merge request sur GitHub (rebase ou merge commit)
```
Le tag est posé **avant** le merge, sur le commit de verrouillage : sur `main`, le workflow `rails` exige le
tag et compare le contenu de `LOCK.sha256` à celui du tag (le contenu reste identique après un rebase).
`just lock` refuse un répertoire dont pytest ne collecte pas tous les tests, et enregistre leur nombre :
une porte qui en exécuterait moins échoue.
Si un test verrouillé s'avère faux plus tard : décision tracée, puis
`just relock p1 "raison"` (journalisé dans `tests/acceptance/LOCKLOG.md`), commit, merge, puis `git tag -f -s lock-p1 -m "relock p1"` et `git push -f origin lock-p1`.
Claude ne peut faire aucune de ces actions.

## 7. Passer une porte de phase

1. Lance **`/phase-gate P<n>`** : Claude rassemble les preuves dans `docs/gates/P<n>.md` (tests d'acceptation
   via `just gate p<n>`, traçabilité, couverture, lint, audit, fuzzing, performances, ADR, rétrospective).
2. Vérifie chaque point. Pour P4 et P5, la porte s'exécute sur la machine Debian dédiée.
3. Coche la porte dans `docs/phase-status.md` et change la ligne `Current phase:`. Commit et merge.

## 8. Tes points de contrôle, récapitulés

| Moment | Ce que tu fais |
|---|---|
| Bootstrap | Installer les outils manquants ; ligne sudoers pour les seuls scripts `tools/dev/` (WP-0.2). |
| Chaque `/wp-start` | Valider le plan de tests, répondre aux questions. |
| Demandes « ask » | Push, nouvelles dépendances (licence !), sudo, réseau : accepter ou refuser en connaissance de cause. |
| Demandes de suppression d'avertissement | Le hook te demande : refuse par défaut, sauf justification solide. |
| Chaque merge request | Relire, merger (rebase ou merge commit). |
| Fin de phase | Relire et verrouiller les tests d'acceptation, taguer ; puis porte de phase. |
| Décisions ouvertes | Elles sont listées dans chaque brief de phase et dans `docs/questions.md`. |
| P2 | Machine de référence, téléchargement des modèles EMBER (`just fetch-models`), corpus sain, taux de faux positifs cible, signature des bundles. |
| P4–P5 | Banc Debian, `OSTIA_BENCH_DEVICE`, clés USB de test effaçables, protocole manuel. |
| P8 | Éventuels enregistrements de réponses VirusTotal faits par toi, à la main, avec ta clé. Claude ne voit jamais la clé. |
| P9 | Médium de référence, cérémonie de clé racine TUF, tag `v1.0.0` et publication. |

## 9. Quand un hook bloque Claude

C'est voulu. Le message dit pourquoi. Ne désactive pas les hooks pour « débloquer » : soit Claude
contourne mal un problème (demande-lui d'expliquer et de revenir à la règle), soit une règle est
réellement inadaptée — dans ce cas c'est **toi** qui modifies le kit, dans ton éditeur, dans un commit
`chore(rails): ...`, puis tu relances `python3 -m unittest tools/kit/test_kit.py`.

Les modifications des rails passent toujours par toi : Claude refuse même si tu le lui demandes en session,
car ses outils sont bloqués sur ces chemins. C'est la garantie que les rails ne glissent pas.

Pour modifier un fichier de rails (règle, hook, brief de phase, spec, plan…) :
```bash
# édition dans ton éditeur, puis
python3 -m unittest tools/kit/test_kit.py     # si tu as touché un hook ou un outil
just rails-update                             # ré-enregistre le manifeste RAILS.sha256
git commit -am "chore(rails): <ce qui change et pourquoi>"
```
Même chose pour `deny.toml` (liste des licences autorisées) : après le merge du WP-0.8, lance une fois
`just rails-update` pour l'ajouter au manifeste ; ensuite, quand Claude demande une nouvelle licence, c'est toi
qui modifies `deny.toml`, puis `just rails-update` et commit.

Quand le hook te demande une confirmation (« ask ») : suppression d'avertissement, marqueur `bench`, réglage
pytest, suppression de tests ou d'assertions, commande réservée écrite dans un script… Lis la justification
de Claude ; refuse par défaut. Une confirmation est valable pour cette modification seulement.

## 10. Mesurer et re-planifier

Après P0 et P1, compte les sessions par WP (historique git + notes) et calcule la médiane par taille (S, M).
La rétrospective de chaque porte en tient compte (plan §16). Un WP qui dérive en taille L est découpé avec toi
avant de continuer.

## 11. Ce que le kit ne fait pas

- Il ne garantit pas la justesse des tests : ta revue des tests d'acceptation reste le cœur du dispositif.
- Les hooks réduisent fortement les dérives mais ne sont pas inviolables (un script arbitraire pourrait écrire
  un fichier) : CODEOWNERS, la protection de branche, le tag de verrouillage et le workflow `rails` sont la
  seconde ligne de défense. Garde-les actifs.
- Aucun vrai malware n'entre dans le dépôt, le CI ou les échanges avec Claude ; le banc d'évaluation (WP-9.7)
  tourne chez toi, isolé, hors CI.
