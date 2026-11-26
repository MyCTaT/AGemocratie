# Version finale Cloudflare

> **État du 22 novembre 2026 : préparation, pas de conformité globale déclarée.** Les protections techniques sont vérifiées, mais l’anonymat contre l’exploitant n’est pas garanti. Lire la documentation priv?e d?exploitation pour les blocages concernant les consultations sensibles, les contrats et les copies fournisseurs avant toute utilisation réelle.

Le dossier `cloudflare/` contient la version de production. Aucun mode simulation n'est activé par son point d'entrée `worker.py`. L'interface, les styles et le vote sont ceux du site original ; les changements portent sur la vérification universitaire et la délivrance du code personnel.

## Ouvrir avant de publier

Sur cet ordinateur, double-cliquer sur `OUVRIR_EN_LOCAL.bat`, puis ouvrir https://127.0.0.1:8787. Accepter le certificat de développement uniquement pour cette adresse locale. Les outils et la base locale sont préparés automatiquement. Se connecter à `/admin` avec **admin** et l'ancien mot de passe du site, repris depuis le `.env` original. Créer une AG et ses sujets pour prévisualiser le parcours : la base locale est indépendante et démarre vide.

L’aperçu utilise le Worker de production avec une entrée locale privée : `MAIL_MODE=brevo` utilise l’API Brevo comme la production ; `MAIL_MODE=smtp` conserve l’ancien envoi Gmail de test ; `--simulation` n’envoie aucun mail. Le `.env` privé et les outils locaux sont exclus de Git. Le code d’AG n’est jamais envoyé par mail. Si le port 8787 est déjà occupé, fermer l’ancienne fenêtre locale ou utiliser `python .apercu_local/lancer.py --port 8790`, puis ouvrir https://127.0.0.1:8790.

Les données du site en ligne ne sont pas téléchargées. L'ancien mot de passe est conservé dans la base D1 de production : ne pas réinitialiser le compte principal. Le `.env` local n'est pas le système d'authentification de Cloudflare et ne doit pas être publié.

## Mettre sur Git

Depuis cette copie, reprendre les fichiers versionnables dans le dépôt existant. La racine et les règles de build restent celles de la version actuelle : Root directory **cloudflare**, installation `uv sync --locked`, déploiement `uv run pywrangler deploy`. Ne pas utiliser le Worker stub à la racine.

Les changements nécessaires couvrent la vérification mail, les contrôles de sécurité, les dépendances et les modèles concernés. Le parcours et les styles du site sont conservés. Les nouveaux fichiers de sécurité, migrations, tests et documentation doivent aussi être repris.

L’archive `agemocratie_final_cloudflare_pour_git.zip` contient uniquement les fichiers destinés à Git, sans `.env`, base locale, outils ou aperçu privé. Le dossier complet sur cet ordinateur conserve l’aperçu privé pour vérifier le site avant de publier. Ne pas copier le dossier de vérification des anciennes versions dans le dépôt.

## Préparer Cloudflare avant le déploiement automatique

Conserver APP_SECRET_KEY ainsi que le nom du Worker et l'identifiant D1. Configurer une nouvelle AG_CODE_KEY ind?pendante pour les nouveaux codes. LEGACY_AG_CODE_KEY reste facultative : si elle est absente, les anciennes empreintes non pr?fix?es sont v?rifi?es avec APP_SECRET_KEY, comme dans la version historique ; une valeur pr?sente mais invalide est refus?e. Les comptes et mots de passe existants restent inchangés.

1. Utiliser le relais Gmail de cette version : copier `cloudflare/outils/gmail_relais.gs` dans Google Apps Script, activer le service avancé Gmail et reprendre `cloudflare/outils/appsscript.json` comme manifeste. Exécuter une fois `installerNettoyageGmail`, autoriser l’accès au compte expéditeur et vérifier le déclencheur créé. Les permissions Gmail permettent la suppression définitive, mais le code ne vise que les nouveaux messages qu’il a lui-même envoyés et enregistrés.
2. Ajouter une propriété de script `AG_MAIL_SECRET` aléatoire et indépendante d’au moins 32 caractères. Déployer l’application Web exécutée par le propriétaire du compte et accessible par son URL `/exec`. Depuis `cloudflare/`, configurer `AG_MAIL_URL` et `AG_MAIL_SECRET` avec `uv run pywrangler secret put NOM_DU_SECRET`. La configuration de production sélectionne explicitement `AG_MAIL_PROVIDER=gmail`. Un ancien déploiement du script doit être mis à jour : changer uniquement le Worker ne met pas à jour Apps Script.
3. La connexion administrateur utilise uniquement l’identifiant et le mot de passe, conformément à la demande de retour au fonctionnement initial. Aucun code Authenticator ni secret `ADMIN_TOTP_SECRETS` n’est requis. Le mot de passe initial est conservé ; ne pas recréer le compte pour ce changement.
4. Sauvegarder D1 hors du dépôt. Les migrations 002 à 004 doivent déjà être présentes. Appliquer seulement les nouvelles migrations avant publication :

   ```powershell
   uv run pywrangler d1 execute agemocratie-db --remote --file migrations/005_acces_mail.sql
   uv run pywrangler d1 execute agemocratie-db --remote --file migrations/006_confidentialite_mail.sql
   uv run pywrangler d1 execute agemocratie-db --remote --file migrations/007_dates_compatibles_d1.sql
   uv run pywrangler d1 execute agemocratie-db --remote --file migrations/008_securite_acces.sql
   uv run pywrangler d1 execute agemocratie-db --remote --file migrations/009_conservation_ag.sql
   ```

5. Après résolution des blocages de mise en service, pousser le code sur Git pour le déploiement configuré. Si la précédente version mail est déjà en ligne, prévoir une maintenance de l’inscription pendant les migrations et jusqu’à la publication du nouveau Worker. Les migrations ne suppriment pas les votes, mais le cron de cette version supprime ensuite les AG ayant dépassé la conservation de trente jours, résultats compris.

Les migrations 005 à 009 sont rejouables. Appliquer 005/006 si elles ne sont pas déjà présentes, puis 007/008/009. Ne pas rejouer les anciennes migrations 002 à 004. La migration 008 invalide les OTP de vérification d’adresse en attente une seule fois ; sa table historique de rejeu MFA peut rester en place sans être utilisée. Les sessions administrateur sont signées et contrôlées par leur validité et la version du compte, sans obligation de second facteur. Aucune migration ne modifie les comptes administrateurs ou leurs mots de passe. Les anciens codes continuent de fonctionner pour les AG conservées ; les codes anciennement transmis par mail restent exposés dans ces anciens messages.

## Confidentialité

Le mail transmet seulement un code de vérification à six chiffres. Le code d'AG est montré uniquement à l'électeur ; une empreinte de l'adresse empêche les doubles délivrances sans être enregistrée avec le code ou le bulletin. Il faut conserver son code car il n'y a pas de récupération par mail. Ce mécanisme n'est pas une garantie d'anonymat cryptographique contre un administrateur du serveur. Voir la documentation priv?e d?exploitation pour les limites et les obligations à valider.

## Vérifications

Tests Worker : `python -m unittest discover -s cloudflare/tests -v` dans un environnement contenant FastAPI, Jinja2, python-multipart, tzdata et httpx. Relais : `node cloudflare/tests/test_gmail_relais.cjs`.

Validation de cette livraison : 31 tests Worker et tests du relais réussis ; démarrage réel de l’aperçu HTTPS, connexion avec admin et le mot de passe initial, chargement des styles et absence d’AG fictive vérifiés. Aucun déploiement ni réinitialisation de mot de passe distant effectué.

## Après mise à jour

Vérifier le cron toutes les cinq minutes : il retire les OTP et compteurs expirés, et convertit au plus cinq anciennes empreintes d’adresse par passage. Vérifier `SELECT count(*) FROM ag_mail_delivrances` jusqu’à zéro avant de considérer cette conversion achevée. Les empreintes nouvelles sont distinctes par AG. Cela ne supprime pas les sauvegardes historiques ni les corrélations temporelles.

Les résultats publics et administrateur restent masqués jusqu’à la fin programmée, même si un sujet est fermé plus tôt. Ils restent aussi masqués si moins de six votes, moins de deux choix représentés ou un choix représenté par moins de trois votes. Ce seuil réduit des risques de déduction, sans garantir l’anonymat face aux observations extérieures ou à la collusion.

Le responsable (Achille Thibon-Soula), le contact et la conservation active de 30 jours sont renseignés dans la documentation priv?e d?exploitation. Finaliser la base légale, la condition pour les sujets politiques/syndicaux et les conditions des prestataires, puis rendre la notice validée disponible lors de la collecte. Aucun SSO autorisé n’est disponible : le système limite les codes par adresse universitaire, pas par personne physique.

## Conservation à 30 jours — mise à jour du 22 novembre 2026

Appliquer aussi la migration rejouable `009_conservation_ag.sql` avant de déployer le nouveau Worker. Le cron supprime les AG dont la dernière fin programmée des sujets remonte à 30 jours (AG sans sujet : création), par lots de cinq toutes les cinq minutes. Il supprime aussi le journal administrateur au-delà de 30 jours. Les comptes administrateur sont conservés. Les données actives supprimées incluent les sujets, choix, codes, empreintes mail, émargements et bulletins ; les résultats ne restent donc pas publiés au-delà de cette conservation.

Les AG anciennes déjà hors délai deviennent éligibles dès le déploiement ; préparer cette transition avant publication. Une suppression manuelle anticipée reste possible. Vérifier régulièrement le fonctionnement du cron et l’absence de file d’attente anormale. La purge n’efface pas automatiquement les messages envoyés chez Google, les exports ou les sauvegardes fournisseurs : documenter et appliquer séparément leurs durées et les règles de restauration. Aucune production n’a été purgée pendant la préparation locale.

Validation de cette mise à jour : 33 tests réussis, dont les limites exactes des 30 jours, l’usage de la dernière fin de sujet et le nettoyage des données associées. Le point d’entrée local applique automatiquement la migration 009 à la base de prévisualisation.

## Information et exploitation — complément du 22 novembre 2026

Le document destiné aux participants est accessible à `/documents/rgpd.txt`, via un lien discret « Confidentialité » en pied de page et un lien près du formulaire d’adresse. Les longues mentions ne sont pas affichées sur la page de vote. Le fichier public `cloudflare/public/documents/rgpd.txt` est une copie de `POLITIQUE_CONFIDENTIALITE.md` ; actualiser les deux ensemble. Les dossiers d’audit et de suivi restent séparés, hors du répertoire public. La mise en forme du document public ne modifie pas les points juridiques à résoudre avant la collecte réelle, consignés dans le dossier interne. La participation au site est facultative et sans effet sur le droit de participer à l’AG. Le vote demeure définitif ; aucun reçu de retrait ou dispositif de retrait de bulletin n’a été ajouté.

Les journaux applicatifs Cloudflare sont désactivés par `observability.enabled=false` dans la configuration de production. Les erreurs applicatives n’émettent qu’un message constant, sans chemin, paramètres ou trace d’exception. Cela ne supprime pas les traitements techniques et historiques propres aux prestataires. Les réglages d’un compte déjà déployé doivent être vérifiés après publication.

Pour contrôler la conservation sans exporter de données de participants, utiliser, depuis `cloudflare/`, `uv run pywrangler d1 execute agemocratie-db --remote --file outils/verifier_conservation.sql`. Ces requêtes sont en lecture seule. Des compteurs hors délai qui ne baissent pas après le cron nécessitent une investigation ; ne pas se contenter de la présence du fichier Wrangler.

Validation courante : suite de 35 tests, dont les liens vers le dossier public, l’égalité avec son fichier source et la suppression des informations sensibles dans les erreurs. Cloudflare sert le document via le répertoire d’assets public, sans accès à D1 ni formulaire supplémentaire. Les conditions Cloudflare, Google et les références CNIL sont documentées dans le dossier RGPD ; leur lecture ne prouve pas les réglages ou contrats du compte personnel.

## Alternative conservée : Brevo (non sélectionnée)

L’intégration Brevo préparée reste disponible en alternative. Le responsable a choisi de rester sur Gmail avec suppression des nouvelles copies ; aucun compte Brevo n’est nécessaire dans le parcours courant. Les étapes suivantes ne concernent qu’une éventuelle bascule future. Pour la production, cette alternative demanderait aussi de sélectionner `AG_MAIL_PROVIDER=brevo` et d’adapter la liste des secrets requis dans Wrangler.

1. Créer le compte Brevo, valider l’expéditeur et, de préférence, authentifier un domaine que vous contrôlez. Il ne suffit pas d’inventer une adresse `verification@agemocratie.fr` ; elle doit être utilisable et validée.
2. Dans les règles de conservation des emails transactionnels, enregistrer la désactivation des aperçus et une conservation des journaux d’un mois. Désactiver le suivi des ouvertures et clics. La désactivation des aperçus concerne les nouveaux envois ; les anciennes copies ne sont pas supprimées par cette intégration.
3. Depuis la racine de cette copie, exécuter `python cloudflare/outils/configurer_brevo.py`. Saisir la clé API dans le terminal à saisie masquée, jamais dans le chat. L’outil contrôle l’API et la présence d’un expéditeur actif sans envoyer de mail. Il écrit ensuite les paramètres dans le `.env` privé et sélectionne `MAIL_MODE=brevo`. Le fichier `cloudflare/brevo.env.example` décrit les noms des paramètres, sans secret.
4. Vérification sans modification ni envoi : `python cloudflare/outils/configurer_brevo.py --verifier`. Les réglages de confidentialité doivent toujours être vérifiés dans l’interface Brevo : cet outil ne peut pas les attester par l’API.
5. Arrêter l’ancien serveur local, puis relancer `python .apercu_local/lancer.py --port 8790`, sans `--simulation`. Conserver ngrok sur le même port. Le lanceur transmet les paramètres Brevo via le fichier privé `.dev.vars` et n’ouvre pas le relais SMTP Gmail dans ce mode.

Le nouveau circuit transmet directement à Brevo l’adresse destinataire et un OTP, sans code d’AG, nom d’AG, copie/BCC ni ajout à une liste de contacts. Il n’enregistre pas les identifiants de message retournés et ne se replie pas vers Gmail en cas d’échec. Une clé absente ou un défaut de configuration produit une erreur d’envoi ; aucune réussite fictive ni simulation automatique n’est annoncée.

La suppression des aperçus ne supprime pas les métadonnées de livraison conservées par le fournisseur et ne rend pas les réglages inaccessibles au titulaire du compte. Les messages déjà présents dans Gmail ne sont pas supprimés. Aucun compte Brevo, contrat, achat ou réglage distant n’a été créé ou validé pendant la préparation du code.

Validation de l’intégration : 37 tests réussis, notamment le payload sans copie Gmail, le refus des codes d’AG à 12 chiffres, l’absence de repli en cas d’erreur et le contrôle de configuration avant tout envoi.

Sources : [API d’envoi](https://developers.brevo.com/reference/send-transac-email), [expéditeurs](https://developers.brevo.com/reference/get-senders), [règles de conservation](https://help.brevo.com/hc/en-us/articles/4415743225746-Configure-a-custom-retention-period-for-your-transactional-logs-and-email-previews).

## Gmail : nettoyage des nouveaux envois — 22 novembre 2026

Le choix confirmé est de conserver les anciennes copies et de nettoyer uniquement les nouveaux mails de vérification. Aucun nettoyage général de la boîte, du dossier Envoyés ou de la corbeille n’est effectué. Les anciens messages n’ont pas le nouvel identifiant et ne sont pas ajoutés à la file de nettoyage.

En local, le `.env` privé sélectionne `MAIL_MODE=smtp` et `GMAIL_DELETE_SENT=1`. Le lanceur vérifie l’accès IMAP avant d’ouvrir le serveur. Chaque nouveau mail porte un identifiant aléatoire et un marqueur du site. Une file privée `.apercu_local/.state/gmail_cleanup_pending.json` conserve seulement cet identifiant et la date de prise en charge, sans adresse ni OTP. Le nettoyage retrouve la copie exacte, contrôle ses en-têtes et l’identifiant global Gmail, puis supprime uniquement cette copie. Il utilise une suppression par UID et jamais une purge globale de la corbeille. Les opérations non terminées sont réessayées ; surveiller le message « Nettoyage Gmail en attente » dans les journaux locaux privés.

Pour les futurs envois Cloudflare, la nouvelle version du relais utilise l’API Gmail : l’identifiant retourné par l’envoi est contrôlé avant la suppression définitive de la copie. En cas d’échec temporaire, seuls les identifiants nécessaires sont enregistrés dans les propriétés privées du script et repris par le déclencheur toutes les minutes. Un mail déjà envoyé reste valable même si son nettoyage est différé : le script ne le renvoie pas pour cette seule raison.

Une copie peut être visible pendant le délai de nettoyage. La suppression n’est pas une garantie d’impossibilité d’accès par le titulaire du compte et n’efface pas les métadonnées des prestataires ni le message reçu par l’étudiant. Le nettoyage ne remplace pas les autres protections du vote.

Validation : 45 tests Python et les tests Node du relais réussis. Un message technique a été créé uniquement dans la boîte de l’exploitant, sans envoi à un destinataire ; sa suppression ciblée et la conservation des messages préexistants ont été vérifiées sur Gmail. Aucun ancien mail de vérification n’a été supprimé. Le script Apps Script est préparé dans les fichiers, pas mis à jour à distance pendant ce travail.

Sources : [suppression d’un message Gmail](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/delete), [service avancé Gmail](https://developers.google.com/apps-script/advanced/gmail), [identifiants et dossiers IMAP Gmail](https://developers.google.com/workspace/gmail/imap/imap-extensions).

## Préparation du relais via clasp — 25 novembre 2026

Le profil local `agemocratie` de clasp est connecté au compte expéditeur. Un nouveau projet « AGemocratie - relais Gmail » a été créé, sans modifier d’autre projet Google. Sa configuration locale est dans `.apercu_local/.state/apps_script_relais/`, exclue de Git. Le code partagé et le manifeste ont été transférés avec un fichier privé d’initialisation. Ce dernier contient le secret du relais : ne jamais le copier dans le dépôt ni dans le chat.

Dans l’éditeur Google, le propriétaire doit sélectionner `initialiserRelais`, l’exécuter et autoriser les permissions Gmail demandées. Cette fonction vérifie le compte expéditeur, installe les propriétés privées et crée le déclencheur de nettoyage ; elle n’envoie pas de mail et ne traite pas les anciennes copies. Après cette étape, retirer le fichier privé d’initialisation avant de créer la version publique du relais.

Le relais comprend un contrôle signé `action=status` qui vérifie le compte attendu et le déclencheur, sans envoyer de mail ni supprimer de copie. Ce contrôle permettra de vérifier la préparation après déploiement. Les identifiants OAuth restent locaux et ne doivent pas être ajoutés à Git.


## Contr?le de publication ? 25 novembre 2026

Le relais Gmail a ?t? d?ploy? en version 2 et son contr?le sign? a r?ussi ; son URL et son secret sont enregistr?s uniquement dans le `.env` priv?. Le fichier priv? d'initialisation est exclu du code d?ploy?. Aucun mail ?tudiant n'a ?t? envoy? pour ce contr?le.

La base distante a ?t? sauvegard?e hors du d?p?t. La r?p?tition locale des migrations 004 ? 009 sur cette sauvegarde conserve les trois comptes administrateur, les sept codes, l'AG, son sujet et les deux votes ; les cl?s ?trang?res restent valides. Aucune AG distante n'?tait hors d?lai au contr?le. Ces chiffres d?crivent ce contr?le, pas un ?tat permanent.

Les 46 tests Python et les tests Node du relais r?ussissent. La compatibilit? des codes historiques ? dix chiffres avec APP_SECRET_KEY est couverte. Aucune migration ni publication du nouveau Worker n'a encore ?t? effectu?e en production. Avant la bascule, refaire la sauvegarde si le site a re?u de nouvelles donn?es, appliquer les migrations en maintenance, configurer les secrets priv?s, d?ployer puis v?rifier la connexion administrateur et le parcours mail.


## D?ploiement Cloudflare ? 25 novembre 2026

La publication a ?t? autoris?e puis r?alis?e directement depuis cette copie, sans commit ni push Git. Les secrets du relais et la nouvelle cl? des codes ont ?t? configur?s ; APP_SECRET_KEY est conserv?e. Les migrations 004 ? 009 ont ?t? appliqu?es apr?s une nouvelle sauvegarde priv?e : trois comptes, sept codes et deux bulletins sont pr?sents et les cl?s ?trang?res sont valides. Le relais Gmail r?pond au contr?le sign?. Le Worker publi? utilise le cron toutes les cinq minutes.

Le contr?le r?el a r?v?l? que le renforcement automatique ? 600 000 it?rations PBKDF2 d?passait le plafond WebCrypto du Worker. Le co?t de cr?ation est ramen? ? 100 000, comme dans la version de production pr?c?dente ; les mots de passe et empreintes existants sont conserv?s. Cette contrainte de plateforme reste ? prendre en compte dans l'?valuation de s?curit?. Le contr?le de connexion est renouvel? apr?s publication du correctif.

Le d?p?t Git original reste intact : il faut ensuite synchroniser le code versionn? avec cette copie pour qu'un futur d?ploiement automatique ne remette pas l'ancienne version.


Contr?le final : le correctif est publi? (version 86cf034c-816e-4cb8-af9f-3a2d69e951d5). La page d'accueil, le document de confidentialit?, le formulaire universitaire, le refus HTML d'une adresse externe et la connexion administrateur avec le mot de passe initial ont ?t? v?rifi?s sur agemocratie.fr. Les 47 tests Python et les tests Node r?ussissent. Deux demandes de v?rification ont ?t? accept?es par le circuit en ligne ; la r?ception dans les bo?tes universitaires doit encore ?tre confirm?e par les destinataires. Aucun message de non-distribution r?cent n'a ?t? trouv? dans la bo?te de r?ception de l'exp?diteur au contr?le. Cette absence ne garantit pas la livraison.


Relais Gmail version 3 : le nettoyage utilise l?identifiant immuable renvoy? par l?API Gmail, le label SENT et les marqueurs du site. Les nouveaux envois portent aussi un identifiant de requ?te v?rifi?. Le Message-ID r??crit par Gmail ne bloque plus les copies d?j? enregistr?es dans la file de reprise. Les tests reproduisent cette r??criture et contr?lent le refus d?un marqueur incorrect.


## FAQ

Avant de publier la FAQ, appliquer une fois la migration rejouable `010_faq.sql` depuis `cloudflare/` : `npx wrangler d1 execute agemocratie-db --remote --file migrations/010_faq.sql`. Elle ajoute uniquement une table de questions ; ne pas rejouer les anciennes migrations. Publier ensuite les fichiers du site. Les participants utilisent `/faq`, les administrateurs `/admin/faq`. Le cron supprime les questions non publiées après 30 jours. Aucune question n’est publiée automatiquement et aucun mail de notification n’est envoyé. La FAQ est propre à la version Cloudflare.
