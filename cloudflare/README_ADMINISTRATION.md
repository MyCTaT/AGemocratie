# AGémocratie — Étape 2 : administration D1 (sans toucher à l'original)

Ce dossier `cloudflare/` contient **uniquement** l'adaptation Cloudflare. Ne remplace
pas les fichiers `app.py`, `templates/`, `static/`, `worker.py`,
`wrangler.jsonc` ou `pyproject.toml` de la racine du projet.

## Fonctionnalités de cette étape

- Pages publiques d'origine sur D1 ; affichage des dates en heure de Paris.
- Connexion administrateur avec sessions signées, cookies HTTPS, formulaires CSRF,
  blocage temporaire des tentatives de connexion.
- Gestion des administrateurs par le compte principal (création, suppression, changement de mot de passe).
- Tableau de bord et création de scrutins avec 2 à 10 propositions, dates de Paris.
- Modification des horaires, clôture et suppression des scrutins.
- **NON DISPONIBLE : génération de codes, accès par code, dépôt des bulletins**.
  Ces routes répondent 503. Aucune simulation de vote n'est enregistrée.

Ce code est un **palier de migration**, pas une application de vote prête à être
utilisée pour une consultation réelle. Le déploiement sur ton compte Cloudflare
n'a pas été testé ici : utilise une base/test de scrutins fictifs avant toute
utilisation avec de vrais membres.

## À faire dans cet ordre

### 1. Sauvegarde D1 puis migration SQL

Sauvegarde/exporte D1 au préalable (Cloudflare D1 → Export si disponible, ou
Wrangler). Dans **Cloudflare → Storage & databases → D1 → agemocratie-db → Console**,
exécute **une seule fois** les instructions du fichier, en conservant
les points-virgules (`;`). Si la console colle tout sur une ligne, exécute
chaque instruction séparément :

`migrations/002_administration.sql`

Le schéma initial des cinq tables (`administrateurs`, `scrutins`, `choix`,
`codes_vote`, `votes`) doit déjà être présent.

Vérifie les nouvelles colonnes avec :

```sql
PRAGMA table_info(administrateurs);
PRAGMA table_info(scrutins);
```

Tu dois voir `auth_version` et `ferme_manuellement`.

**Attention** : les deux `ALTER TABLE` échouent si cette migration a déjà été
appliquée. Ne la relance pas sans vérifier les colonnes.

### 2. Définis un secret d'application pour CE Worker

Dans **Workers & Pages → agemocratie → Settings → Variables and Secrets**,
ajoute un **Secret** `APP_SECRET_KEY` d'au moins 32 caractères aléatoires.

Crée-le par exemple dans PowerShell (Python local installé) :

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Ne partage pas et ne committe pas cette valeur.** Ne mets pas de `APP_SECRET_KEY`
dans `wrangler.jsonc` ni dans Git. Ne reprends pas un secret destiné à devenir public.
Si tu changes ce secret, toutes les sessions en cours seront invalidées.

### 3. Ajoute uniquement le dossier cloudflare sur GitHub

Depuis la racine de ton dépôt AGemocratie, copie/remplace **uniquement le dossier
`cloudflare/`** de cette archive (fais-en une sauvegarde avant), puis :

```powershell
git add cloudflare
git diff --cached --name-only
git commit -m "Administration Cloudflare D1 isolee"
git push origin main
```

Ne pousse pas `.env`, de fichiers SQL contenant le hachage de ton mot de passe,
ni `instance/votes.sqlite3`.

Dans Cloudflare, conserve les paramètres qui ont finalement fonctionné :

| Champ | Valeur |
|---|---|
| Root directory | `/` |
| Build command | `python -m pip install uv` |
| Deploy command | `cd cloudflare && uv run pywrangler deploy` |
| Branch | `main` |

`cloudflare/wrangler.jsonc` conserve le binding D1 `DB` de l'archive précédente.
Assure-toi que le nom de la base est bien `agemocratie-db`.

### 4. Initialise le compte administrateur principal

Depuis PowerShell, **en local** :

```powershell
python cloudflare/outils/creer_admin_d1.py
```

Saisis un nouveau mot de passe fort **sans l'afficher dans la console**.
Le script affiche une instruction SQL avec **uniquement un hachage PBKDF2**.
Copie l'instruction dans la console de `agemocratie-db`, puis exécute-la.

Si `admin` existe déjà, la commande `INSERT` échouera sans changer le compte.
**Ne colle pas l'instruction SQL contenant le hachage sur GitHub.**

Vérifie la présence du compte (sans afficher son empreinte de mot de passe) :

```sql
SELECT id, identifiant, role FROM administrateurs;
```

### 5. Teste l'administration

1. `https://agemocratie.lironafriat-pro.workers.dev/health` doit répondre `ok`.
2. `https://agemocratie.lironafriat-pro.workers.dev/admin/login` doit afficher
   le formulaire de connexion de l'interface d'origine.
3. Connecte-toi avec `admin` et le mot de passe choisi à l'étape 4.
4. Crée un scrutin de test dans `/admin/polls/new` ; vérifie qu'il apparaît en
   public sur `/` et sur le tableau de bord `/admin`.
5. Teste la déconnexion et la création d'un administrateur secondaire.

**Important pour le plan gratuit** : Cloudflare Workers Free limite le CPU à
10 ms par requête. Le PBKDF2 est délégué au Web Crypto natif, avec 100 000
itérations (le maximum accepté par Web Crypto sur Cloudflare) ; cela peut malgré
tout poser un problème de quota/latence. Si la
connexion déclenche une erreur **1102** ou **500**, consulte les logs Workers
et arrête les tests de production ; ne baisse pas les itérations pour contourner
le problème de sécurité. Le plan Workers Paid ou une autre architecture
pour l'authentification peuvent être nécessaires.

Les tests ici vérifient la structure et les routes simulées ; ils ne valident
pas la performance de l'API Web Crypto sur Cloudflare réel.

## Sécurité et limites

- Mots de passe stockés au format `pbkdf2_sha256$100000$sel$empreinte` ; le Worker
  n'accepte que 100 000 itérations. Ces empreintes ne sont **pas** reconnues par
  l'application locale (`app.py` exige 150 000 à 1 000 000), et inversement.
- Un compte `admin` créé avec une ancienne version de `creer_admin_d1.py`
  (390 000 itérations) ne peut pas se connecter : recrée son empreinte avec
  l'outil actuel et remplace-la par un `UPDATE administrateurs SET mot_de_passe_hash=...`.
- Sessions HMAC signées, durée 4 h, invalidation après réinitialisation du
  mot de passe ou suppression d'un compte.
- Cookie `Secure`, `HttpOnly`, `SameSite=Lax`, préfixe `__Host-` ; il faut HTTPS.
- Token CSRF signé, vérification de l'origine lorsque le navigateur l'envoie.
- Requêtes SQL paramétrées et `batch()` transactionnel pour les créations.
- Les mots de passe ne sont jamais journalisés dans le code ajouté.
- Aucun code de vote ni bulletin n'est écrit par cette version.
- Les URL publiques et les fichiers HTML/CSS d'origine ne sont pas modifiés.
- Ne pas utiliser avec de vrais électeurs tant que codes uniques, atomicité
  des bulletins, contrôles d'ouverture et tests de sécurité ne sont pas migrés.

## Documentation technique

- https://developers.cloudflare.com/workers/languages/python/packages/fastapi/
- https://developers.cloudflare.com/d1/worker-api/d1-database/
- https://developers.cloudflare.com/workers/runtime-apis/web-crypto/
- https://developers.cloudflare.com/workers/platform/limits/
