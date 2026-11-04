# Déploiement et administration Cloudflare

## Projet a deployer

La version Cloudflare se trouve dans `cloudflare/`. Dans Workers Builds, definir **Root directory** sur `cloudflare`, `UV_VERSION=0.13.4`, l'installation sur `uv sync --locked` et la commande de deploiement sur `uv run pywrangler deploy`. Le `wrangler.jsonc` a la racine est un stub sans binding D1 ; ne pas l'utiliser en production.

Le Worker utilise Python 3.14 (`python_workers_314`, compatibilite du 22 octobre 2026), fixe aussi par `.python-version`. `uv.lock` fixe les versions resolues. Apres une modification de dependance, mettre a jour le verrou puis deployer avec `--locked`.
## Preparer les secrets

Creer trois cles aleatoires independantes d'au moins 32 octets et les enregistrer comme secrets Cloudflare :

```powershell
uv run pywrangler secret put APP_SECRET_KEY
uv run pywrangler secret put AG_CODE_KEY
uv run pywrangler secret put LEGACY_AG_CODE_KEY
```

`APP_SECRET_KEY` signe les sessions et les jetons CSRF. `AG_CODE_KEY` calcule les empreintes des nouveaux codes. Avant le premier deploiement apres la migration, definir `LEGACY_AG_CODE_KEY` avec la valeur actuelle de `APP_SECRET_KEY`. Cette cle sert uniquement a verifier les codes deja distribues ; la conserver 90 jours apres la migration. La rotation de `APP_SECRET_KEY` invalide sessions, CSRF et anciens cookies d'acces, mais pas les codes tant que la cle historique est conservee. La rotation de `AG_CODE_KEY` invalide les nouveaux codes : prevoir leur remplacement. Ne jamais mettre ces cles dans `vars`, dans Git ou dans les journaux.
## Vérifier la base avant migration

La migration `001` du schéma initial n’est pas dans ce dépôt. Avant d’exécuter une migration, faire une sauvegarde D1 et vérifier le schéma distant :

```sql
SELECT name, sql FROM sqlite_master
WHERE type IN ('table','index')
  AND name IN ('administrateurs','scrutins','choix','codes_vote','votes','ag_votes');
PRAGMA foreign_key_list(choix);
PRAGMA foreign_key_list(votes);
PRAGMA foreign_key_list(codes_vote);
SELECT id,identifiant FROM administrateurs WHERE role='principal';
```

Confirmer que les tables et colonnes attendues par `002_administration.sql` et `003_assemblees.sql` sont présentes et qu’il existe exactement un compte `principal`. Ne pas rejouer `003_assemblees.sql` si elle a déjà été appliquée. La migration `004_durcissement.sql` s’exécute une seule fois, après sauvegarde : elle crée des index manquants, sépare les émargements des bulletins, migre les totaux existants puis supprime l’ancienne table qui associait directement le code au choix. Les codes déjà émis reçoivent une période de grâce de 90 jours à partir de cette migration.

Cette opération modifie les données de vote. La réaliser pendant une fenêtre de maintenance : fermer temporairement l’accès public, sauvegarder, appliquer `004_durcissement.sql`, déployer immédiatement le Worker correspondant, puis rouvrir l’accès. Ne pas lancer ces opérations sur la base de production sans avoir confirmé la sauvegarde et le schéma.

```powershell
uv run pywrangler d1 execute agemocratie-db --remote --file migrations/004_durcissement.sql
uv run pywrangler deploy
```

Après le déploiement, vérifier les totaux des scrutins clôturés et les tables `ag_emargements` et `ag_bulletins`. Les bulletins ne contiennent ni identifiant de code ni heure de vote. Les émargements ne contiennent pas le choix. Les tables historiques `votes` et `codes_vote` sont conservées pour les scrutins antérieurs.

## Creer le compte principal

Apres verification du schema et application des migrations, lancer `python outils/creer_admin_d1.py`. L'outil cree le compte s'il n'existe pas, ou reinitialise son identifiant, son mot de passe et ses sessions s'il existe deja. Cela remplace un ancien hachage incompatible. Le mot de passe doit contenir au moins 16 caracteres. L'outil produit un hachage PBKDF2-HMAC-SHA256 a 600 000 iterations, ecrit le SQL temporairement dans `.wrangler/`, appelle Wrangler puis supprime le fichier. Le mot de passe et le hachage ne sont pas places dans la ligne de commande ni dans la sortie standard.

Les comptes crees depuis l'administration ont aussi un mot de passe minimum de 16 caracteres. Le compte principal doit saisir son mot de passe actuel pour modifier son propre mot de passe.
## Exploitation

- La page d’accueil et les titres des AG/sujets sont publics ; le code personnel protège l’accès à la participation. L’ancien lien `/polls/{id}` ne donne accès qu’à la page publique correspondante.
- Les nouvelles AG et les nouveaux scrutins sont gérés par leur créateur ou le compte principal. La clôture et la suppression d’un scrutin sont enregistrées dans `journal_admin`.
- Les codes ont 12 chiffres, expirent après 90 jours et ne sont révélés qu’une fois par l’écran de création. Les anciens codes à 10 chiffres sont acceptés jusqu’à leur expiration.
- Les URLs de prévisualisation du Worker sont désactivées dans Wrangler. Supprimer aussi les anciennes versions de production depuis le tableau de bord Cloudflare ; un déploiement ne retire pas les versions déjà publiées.
- L’observabilité Cloudflare est activée. Les journaux applicatifs ne doivent jamais inclure les codes, mots de passe, cookies ou en-têtes bruts.
- `secrets.required` est pris en charge par Wrangler pour valider les secrets au deploiement ; le fichier declare les trois cles requises.
