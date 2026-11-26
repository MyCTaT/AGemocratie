# Correctifs du 10 novembre 2026

Le rapport RAPPORT_2026-11-10.md décrit l’état **avant** ces correctifs et reste conservé comme historique. Le fonctionnement et les risques actuels doivent être appréciés avec ce document.

| Constat | État après correction |
|---|---|
| S01 Starlette et formulaires | FastAPI 0.162.2 / Starlette 1.10.0, verrou renouvelé ; 64 Kio maximum réellement lus avant parsing ; contrôle de syntaxe Host. OSV : 29 versions, aucun paquet signalé à la vérification du jour. Cela ne prouve pas l’absence de toute vulnérabilité. |
| D02 dates D1 | Nouvelle migration 007 compatible avec la limite des motifs ; dates calendaires invalides refusées ; l’aperçu ne réécrit plus silencieusement les migrations. |
| A03 pseudonyme commun | Nouvelles délivrances distinctes par AG. Compteurs anti-abus avec un domaine et une clé distincts, renouvelés par fenêtre. Les anciens droits sont convertibles sans connaître les adresses : conversion au prochain accès de l’adresse et par lots de maintenance. Les anciennes lignes restent corrélables jusqu’à conversion ; la migration n’efface pas les sauvegardes historiques. |
| D01 IP partagée | 300 demandes de vérification par IP et 15 minutes, au lieu de 5 ; 5 par adresse restent appliquées. Les compteurs sont atomiques. Ces valeurs ne représentent pas une capacité d’envoi Gmail garantie : les quotas du prestataire restent à dimensionner. |
| A02 petits résultats / clôture | Aucun résultat avant la fin programmée, même après clôture anticipée et pour un admin du site. Résultats exacts masqués si moins de 6 bulletins, moins de 2 options non nulles, ou une option non nulle à moins de 3 voix. Ce seuil est une politique de réduction du risque, pas une garantie contre une coalition de votants ou des observations externes. |
| O01 administration | Mot de passe conservé + TOTP obligatoire propre à chaque identifiant ; contrôle anti-rejeu ; invalidation des anciennes sessions sans MFA ; limites atomiques par compte et IP ; coût fictif aligné sur 600 000 itérations. MFA Cloudflare/Google/GitHub et droits d’infrastructure restent à configurer dans les comptes concernés. |
| Conservation technique | Cron toutes les 5 minutes : OTP et compteurs expirés purgés, migration progressive des anciens pseudonymes. Les durées de conservation de l’AG, des sauvegardes et des journaux doivent encore être décidées et appliquées avec l’organisateur. |
| A01 opérateur serveur / instantanés | **Non résolu cryptographiquement.** Le serveur reçoit le vote en clair et les opérations peuvent être rapprochées par un opérateur technique. Les protections de publication ne chiffrent pas les bulletins contre l’hébergeur. Une autre architecture auditée est nécessaire pour cette menace. |
| I01 accès aux mails / I02 plusieurs adresses | **Limites conservées et déclarées.** L’utilisateur n’a pas d’accès autorisé au SSO universitaire. Le logiciel ne peut pas prouver l’unicité d’une personne ni distinguer le véritable destinataire d’un tiers capable de lire ses OTP. Ne pas annoncer une personne/une voix certifiée. |
| RGPD | Brouillon de notice de confidentialit? préparé ; responsable/contact, base légale, contrats/transferts et durée de vie des données d’AG restent à valider. Pas de conformité automatique ni d’identité d’organisateur inventée. |

Le code d’AG reste affiché uniquement sur le site, jamais envoyé par mail. Son mot de passe admin initial n’a pas été publié ou remplacé. Les clés MFA et les configurations locales restent privées et sont exclues de l’archive Git.

## Activer en production

Configurer ADMIN_TOTP_SECRETS avant le push, appliquer 007 puis 008 en maintenance d’inscription et déployer immédiatement la version correspondante. Les vérifications OTP de l’ancien format sont invalidées une seule fois ; les codes d’AG et les bulletins existants sont conservés. L’ancien Worker ne doit pas continuer à délivrer des codes durant cette transition. Voir MISE_EN_LIGNE.md pour les commandes.

La conversion des anciennes délivrances est progressive (au plus 5 par exécution planifiée). Ne pas la qualifier d’achevée tant que `SELECT count(*) FROM ag_mail_delivrances` ne vaut pas zéro. L’empreinte de l’adresse n’est pas liée en colonne à un code, mais cette séparation ne supprime pas la corrélation temporelle A01.

## Vérification

Tests métier et de sécurité dans cloudflare/tests, tests du relais Node, contrôle OSV et validation réelle dans le runtime Cloudflare local. Le test réel a validé le mot de passe initial + MFA, la création d’un sujet D1 sans réécriture de schéma, le mail simulé, le code privé, le vote, la clôture protégée, la limite 64 Kio et la maintenance planifiée. Une particularité des compteurs D1 avec suppressions en cascade a été corrigée après cette validation et couverte par un test de régression.

L’application n’a pas été déployée et aucune base de production n’a été modifiée pendant ce travail.

## Réexamen du 22 novembre 2026 — anonymat

Le test local `risque_residuel.py` a été rejoué après la demande de correction et de retrait du long avertissement public. Il reproduit encore le rapprochement dans le cas d’une seule génération puis d’un seul vote entre deux lectures. Le succès de ce test signifie que le risque existe ; il ne constitue pas une validation de l’anonymat. Aucune correction cryptographique de ce risque n’a été introduite à cette étape.

Le détail suivant est conservé dans le dossier d’audit ; le document public le remplace par une information courte, sans prétendre que le risque est supprimé :

- Le serveur voit l’adresse au moment de l’envoi puis le contexte de vérification et de génération. Un administrateur technique ayant le contrôle du logiciel peut instrumenter les requêtes.
- Des métadonnées, historiques, sauvegardes et observations temporelles peuvent compléter les tables actives ; désactiver les journaux applicatifs n’efface pas toutes les données des prestataires.
- La séparation des tables n’est pas un mélange cryptographique des bulletins. Des observations successives et de faibles effectifs peuvent permettre des déductions.
- Une boîte universitaire compromise peut permettre une usurpation lors d’une nouvelle vérification.
- La mise à jour ne retire pas les anciens codes déjà transmis par mail, leurs copies ni les connaissances déjà acquises.

Une refonte doit définir les adversaires visés, la séparation effective des autorités et la confiance dans le client de vote, puis choisir un protocole établi et faire évaluer sa mise en œuvre. Un chiffrement piloté uniquement par le même serveur ou un délai de stockage ne suffirait pas à démontrer la correction. La possibilité d’une autorité indépendante a été demandée au responsable ; aucune indépendance d’exploitation n’est supposée acquise.

## Retour à la connexion administrateur initiale — 22 novembre 2026

À la demande explicite du responsable, l’obligation de second facteur administrateur est retirée. La connexion utilise l’identifiant et le mot de passe conservé. Le formulaire, le contrôle de connexion et la liste des secrets requis sont adaptés ; le lanceur local ne génère ni n’exige de configuration MFA. Les protections CSRF, le contrôle de session et les limites de tentatives restent actifs. Les mentions historiques de MFA ajouté dans les sections précédentes ne décrivent donc plus la configuration courante.
