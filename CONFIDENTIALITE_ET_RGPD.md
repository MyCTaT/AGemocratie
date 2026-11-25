# Confidentialité et RGPD — consultations informelles d’AG étudiantes

## Suivi opérationnel — 22 novembre 2026

Service confirmé : agemocratie.fr. Responsable déclaré : Achille Thibon-Soula. Contact : agemocratie@gmail.com. Finalité : sonder l’avis des étudiants de Jussieu pour les AG étudiantes. Les consultations peuvent porter sur une grève, une mobilisation ou des positions politiques ou syndicales. L’exploitant déclare être seul à accéder à l’administration, à Gmail et à Cloudflare ; les comptes fournisseurs sont personnels.

Choix courant du circuit d’envoi : le responsable reste sur Gmail et demande le nettoyage automatique des seuls nouveaux mails de vérification. Les anciennes copies sont conservées conformément à son choix explicite. Le test local utilise SMTP et une suppression IMAP ciblée ; la version Cloudflare préparée utilise le relais Apps Script avec suppression par identifiant Gmail. Ce script doit être mis à jour et autorisé dans le compte avant son usage en production. L’intégration Brevo reste une alternative non sélectionnée, sans compte configuré.

Le paramètre `BREVO_PRIVACY_CONFIRMED=1` est un accusé de vérification manuelle, pas une commande qui désactive les aperçus chez le fournisseur. Les journaux de livraison peuvent conserver des métadonnées même lorsque les aperçus sont désactivés. Le nouveau payload n’inclut ni copie/BCC, ni nom d’AG, ni code d’AG. Aucun effacement d’anciens messages Gmail n’a été effectué.

La conservation active de 30 jours a été validée. Le nouveau code de maintenance supprime les AG 30 jours après la dernière fin programmée de leurs sujets (AG vide : création), par lots de cinq à chaque passage du cron toutes les cinq minutes. Cette suppression inclut les résultats, les codes et les données de participation. Le journal administrateur est limité à 30 jours. La migration 009 doit être appliquée avant le déploiement du code. Aucun déploiement ni nettoyage de production n’a été effectué ici. Les anciennes AG dépassant l’échéance seront supprimées dès les premiers passages après déploiement : préparer la transition avant d’activer cette version. Les copies des prestataires, mails, exports et sauvegardes nécessitent encore une politique distincte vérifiée.

La séparation des tables est une pseudonymisation et une réduction du risque, pas une preuve d’anonymisation irréversible. Le serveur traite le vote ; les instantanés de base et observations temporelles peuvent permettre des corrélations. Il faut donc analyser l’article 9 pour les consultations sensibles. L’intérêt légitime de l’article 6 ne suffit pas à lui seul pour autoriser le traitement de données sensibles.

### Base légale : choix encore nécessaire

Décisions complémentaires du 22 novembre : la participation au site est entièrement facultative ; un refus n’entraîne ni exclusion de l’AG ni pénalité. Le responsable demande que le vote reste définitif, sans mécanisme de retrait de bulletin. Ce choix ne vaut ni consentement des étudiants ni exception aux droits RGPD. Aucun dispositif de reçu de retrait n’a été ajouté, conformément à cette demande. Le caractère libre de la participation ne résout pas à lui seul l’article 9 ou la possibilité de retirer un consentement. La piste du consentement n’est donc pas déclarée validée.

Pour l’accès universitaire et l’anti-fraude, l’intérêt légitime est une piste à examiner : intérêt poursuivi, nécessité des données et mise en balance avec les droits des étudiants doivent être documentés. Il n’est pas adopté automatiquement par cette note. Pour les avis politiques ou syndicaux, un consentement explicite peut constituer une piste si toutes ses conditions sont remplies ; l’accord de l’organisateur n’est pas celui des participants. Le site n’a pas encore de dispositif de recueil et de preuve de ce consentement spécifique, ni de procédure de retrait adaptée à sa séparation des données. Une simple case ne résout pas ces difficultés. Faire valider une base article 6 et une condition article 9 avant ces consultations, ou recourir à un système adapté et audité.

Références : [intérêt légitime](https://www.cnil.fr/fr/les-bases-legales/interet-legitime), [données sensibles](https://www.cnil.fr/fr/definition/donnee-sensible). Le but informel ou étudiant ne crée pas d’exemption générale.

### Registre de traitement prérempli

Cette fiche décrit le traitement projeté et les mesures du code ; elle ne prouve ni leur déploiement ni la validation de la licéité. Conserver les preuves contractuelles, décisions et suivis individuels dans `donnees_privees/rgpd/`, exclu de Git.

| Rubrique | État au 22 novembre 2026 |
|---|---|
| Responsable et contact | Achille Thibon-Soula ; agemocratie@gmail.com |
| Traitement | Consultations facultatives d’AG étudiantes à Jussieu, contrôle universitaire, délivrance des codes, prévention des abus et production des résultats |
| Personnes concernées | Participants disposant des adresses admises et administrateur ; ne pas assimiler un domaine de messagerie à une preuve d’inscription à Jussieu |
| Données | Adresse pour l’envoi, empreinte par AG, OTP et jetons sous empreinte, code sous empreinte, accès, émargements, choix, compte et actions administrateur ; données techniques de connexion chez les prestataires |
| Sensibilité | Des thèmes politiques et syndicaux sont prévus ; la séparation des tables ne démontre pas une anonymisation irréversible |
| Habilitations déclarées | Achille seul pour l’administration, le compte Gmail et le compte Cloudflare ; vérifier séparément les habilitations techniques des fournisseurs |
| Base article 6 | Non validée pour la consultation réelle ; analyse de nécessité et mise en balance ci-dessous pour la sécurité |
| Condition article 9 | Non validée ; le choix d’un vote définitif ne crée pas d’exception au RGPD et n’autorise pas à déclarer un consentement retirable non mis en œuvre |
| Conservation active | OTP dix minutes puis purge ; compteurs quinze minutes puis purge ; AG et données associées trente jours après leur dernière fin programmée ; journal administrateur trente jours |
| Fournisseurs | Cloudflare Workers/D1 ; Google Apps Script et Gmail personnel pour le relais. Les rôles et conditions du circuit Google restent à résoudre |
| Transferts et archives | Vérification du compte et des services nécessaire ; ne pas annoncer un hébergement exclusivement français ou européen |
| Droits | Contact public, procédure ci-dessous, délai d’un mois en principe ; aucune reconstruction volontaire identité–bulletin |
| Information | Information des participants accessible à `/documents/rgpd.txt`, liée en pied de page et près du formulaire ; source : `POLITIQUE_CONFIDENTIALITE.md`. Le présent suivi technique n’est pas servi par le site |
| Mesures réalisées dans le code | HTTPS, cookies sécurisés, CSRF, connexion administrateur par identifiant et mot de passe, séparation des empreintes, limites atomiques, protection des petits effectifs, purge ; journalisation fournisseur désactivée dans la configuration et erreurs sans paramètres ni traces détaillées |

### Nécessité et proportionnalité — analyse préparatoire

Le contrôle universitaire vise à réserver le parcours aux domaines admis ; il ne prouve pas l’unicité de la personne. L’adresse ne doit pas servir à la publicité, à l’établissement de listes politiques, au contact ultérieur ou à un rapprochement avec les votes. Les empreintes sont propres à chaque AG pour limiter le suivi transversal. L’OTP doit rester distinct du code de vote.

Pour l’anti-abus, les compteurs limités dans le temps et les cookies nécessaires sont moins intrusifs qu’une collecte de pièces d’identité ou une liste nominative d’opinions. Leur justification ne justifie pas automatiquement le traitement de choix sensibles. Examiner les solutions alternatives : participation hors ligne, absence de consultation sensible, ou système de vote dont le modèle d’anonymat a été évalué indépendamment.

La durée active de trente jours est retenue par le responsable pour permettre la vérification et les contestations, puis supprimer l’AG et ses résultats. Elle doit être réévaluée si ce besoin change. Les historiques fournisseurs demandent une justification et une information distinctes. Les faibles effectifs, la concentration des accès chez un seul exploitant et la possibilité de corrélation pèsent dans la mise en balance ; cette analyse ne conclut pas encore à un fondement suffisant pour les consultations sensibles.

### Risques résiduels et AIPD

| Scénario | Conséquence pour un étudiant | Protection et limite restante |
|---|---|---|
| Corrélation des requêtes et instantanés | Déduction d’une opinion ou d’une participation | Tables séparées et précision temporelle réduite ; pas de protection cryptographique démontrée contre l’exploitant |
| Compromission d’un compte fournisseur | Accès aux messages, historique ou base | Accès déclaré unique ; authentification du site par mot de passe selon la demande du responsable ; paramètres des comptes fournisseurs à vérifier et secrets exposés à renouveler |
| Petits résultats, unanimité, observations successives | Déduction du vote d’une personne | Masquage sous six votants et petites cellules ; pas de garantie contre la collusion ou des observations externes |
| Restauration d’une ancienne base | Réapparition de données supprimées | Ne pas rouvrir la consultation avant de réappliquer les migrations et la purge, puis vérifier les compteurs de conservation |
| Refus ou impossibilité d’exercer un droit | Perte de contrôle sur des données personnelles | Procédure de contact prête ; fondement et articulation avec le vote définitif non résolus |

Les opinions politiques ou syndicales et l’incertitude sur la réidentification justifient une évaluation d’impact documentée avant ces usages. Le nombre prévu d’étudiants et les modalités réelles des AG ne sont pas connus ; ne pas conclure que l’AIPD serait inutile du seul fait du caractère informel. Faire déterminer son obligation, mener l’analyse si nécessaire et, si un risque élevé subsiste malgré les mesures, examiner la consultation préalable prévue par l’article 36. Cette fiche est une préparation, pas une AIPD achevée.

### Vérification des prestataires sur sources officielles

**Cloudflare.** L’article 6.1 des conditions Self-Serve incorpore le DPA pour les contenus personnels concernés. Le DPA prévoit les transferts, sous-traitants et garanties. Archiver en privé la version applicable, la date du contrat du compte et les services réellement utilisés ; vérifier les mécanismes de transfert pertinents au moment de la mise en service. Un compte ouvert par une personne physique n’est pas automatiquement exclu de ce cadre.

**Google.** La politique grand public ne doit pas être présentée comme un engagement de sous-traitance Workspace. Le Cloud Data Processing Addendum couvre les services définis par le contrat applicable et exclut les produits additionnels de ce périmètre. Aucune preuve d’applicabilité au circuit Gmail personnel + Apps Script n’a été constatée ici. Résoudre le rôle juridique et l’encadrement effectif de ce circuit, ou le remplacer par un circuit d’envoi dont le contrat couvre explicitement le service utilisé. Un changement de fournisseur ou de formule payante n’a pas été effectué et aucun engagement n’a été accepté au nom du responsable.

Sources consultées le 22 novembre 2026 : [conditions Cloudflare, §6.1](https://www.cloudflare.com/terms/), [DPA Cloudflare](https://www.cloudflare.com/cloudflare-customer-dpa/), [confidentialité Google](https://policies.google.com/privacy?hl=fr), [Cloud Data Processing Addendum](https://cloud.google.com/terms/data-processing-addendum/). Aucun de ces textes ne dispense le responsable de choisir les fondements de son propre traitement.

### Sauvegardes, mails et reprise

D1 Time Travel est documenté comme actif automatiquement, avec sept jours sur l’offre gratuite et trente jours sur l’offre payante. Des données effacées de la base active peuvent donc rester restaurables pendant cette fenêtre ; le forfait réel doit être relevé, sans prétendre que la purge active supprime cet historique. Ne pas publier une promesse de disparition de toutes les copies à J+30.

La suppression d’un message Gmail le place normalement dans la corbeille pour trente jours, sauf suppression définitive. Ne pas confondre la disparition du dossier « Envoyés » et l’effacement de toutes les copies. Avant l’utilisation réelle, vérifier ce que MailApp conserve, les journaux Apps Script et les règles effectivement disponibles sur le compte ; aucun script de suppression générale de la boîte personnelle n’a été ajouté. Les messages reçus par les étudiants ne sont pas effaçables par le site.

Après restauration, maintenir le service fermé aux participants, réappliquer les migrations nécessaires, exécuter la maintenance jusqu’à disparition des AG et OTP hors délai, contrôler les comptes et secrets puis rouvrir. Toute copie de diagnostic ou export doit rester dans un emplacement privé, avoir une échéance et être supprimée à l’issue du besoin ; ne pas conserver un export de production dans Git, un ticket ou l’archive de livraison.

Sources : [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/), [suppression Gmail](https://support.google.com/mail/answer/7401?hl=fr). Le fichier `cloudflare/outils/verifier_conservation.sql` fournit uniquement des compteurs à examiner, sans exporter d’adresses ou de choix.

### Décision de mise en service

État actuel : **préparation technique, pas de conformité globale déclarée**. La règle de vote définitif est respectée. Les blocages restant avant les consultations sensibles sont le fondement article 6 et la condition article 9 compatibles avec les droits, le circuit Google et ses conditions, les durées vérifiées des copies fournisseurs et l’évaluation d’impact. La mise en service n’est pas autorisée par le seul fait que les tests passent. Ne pas transformer ce statut en « conforme » en supprimant les avertissements de la notice.

Les vérifications des comptes, contrats ou obligations d’AIPD n’ont pas été effectuées en se connectant aux comptes personnels. Rien n’a été publié, aucun mail de participant n’a été envoyé et aucune donnée de production n’a été supprimée pendant cette préparation.

### Traiter une demande de droits

1. Relever la date de réception, la nature de la demande et l’AG concernée dans un suivi privé à accès restreint ; ne jamais commettre ce suivi dans Git.
2. Accuser réception et préciser les informations strictement nécessaires. Ne pas demander de code de vote, de mot de passe ni systématiquement une pièce d’identité. Vérifier l’identité de manière proportionnée en cas de doute raisonnable.
3. Examiner les données effectivement disponibles et les droits applicables à la base légale retenue. Ne pas promettre de retrouver ou supprimer un bulletin individuel lorsque le système ne permet pas de l’identifier. Ne pas créer de nouvelle correspondance identité-bulletin.
4. Répondre en principe sous un mois. Une prolongation de deux mois supplémentaires est possible dans les conditions du RGPD ; informer la personne et expliquer les motifs dans le premier mois. Motiver un refus et indiquer les voies de recours.
5. Conserver une trace minimale du traitement de la demande selon une durée à justifier, puis la supprimer. Le suivi ne doit contenir ni choix de vote ni secrets.

### Fiche de registre à finaliser en privé

Finalités : contrôle d’accès universitaire, délivrance d’un code par adresse et AG, prévention des votes multiples avec le même code, résultats de consultations informelles. Personnes concernées : participants et administrateurs. Catégories de données : celles décrites dans la notice. Prestataires identifiés : Cloudflare et Google pour le relais de messagerie. Mesures : HTTPS, empreintes par AG, séparation des tables, connexion administrateur par mot de passe, limites de requêtes, résultats masqués dans certains cas et purge périodique des OTP/compteurs.

À compléter avant usage réel : identité du ou des responsables, répartition des rôles entre organisateur d’AG et exploitant du site, base légale pour chaque finalité, condition article 9 si nécessaire, habilitations réelles, durées, garanties de transferts et contrats applicables aux comptes utilisés. Évaluer et consigner le besoin d’AIPD selon les risques, notamment en présence d’opinions politiques ou syndicales. Cette fiche n’établit pas à elle seule la conformité.

### Conservation et prestataires

Après décision sur les durées, mettre en œuvre puis tester la suppression effective des données actives. Recenser séparément les mails envoyés, exports, copies locales, sauvegardes et mécanismes de restauration. Vérifier les durées réellement configurées chez les prestataires et le traitement des données supprimées lors d’une restauration. Ne pas conserver des exports sans échéance ni supposer qu’effacer une AG efface les historiques des fournisseurs.

Vérifier le type de compte Google et les engagements contractuels disponibles ; une adresse Gmail personnelle ne prouve pas l’existence d’un accord de sous-traitance adapté. Identifier les personnes habilitées, activer le second facteur des comptes fournisseurs et retirer les accès devenus inutiles.

### Gestion d’un incident

Limiter l’exposition, préserver uniquement les éléments nécessaires à l’analyse dans un espace privé, révoquer les accès compromis et documenter les faits, impacts et mesures. Évaluer les obligations de notification : à la CNIL, si applicable, dans les meilleurs délais et si possible sous 72 heures après prise de connaissance ; aux personnes en cas de risque élevé, sous réserve des exceptions légales. Ne pas publier de secrets ou de données de participants dans un ticket Git.

Références : [information](https://www.cnil.fr/fr/conformite-rgpd-information-des-personnes-et-transparence), [registre](https://www.cnil.fr/fr/RGPD-le-registre-des-activites-de-traitement), [RGPD](https://cnil.fr/fr/reglement-europeen-protection-donnees).

État examiné le 10 novembre 2026. Cette note décrit le code et les points à faire valider ; elle ne constitue ni une certification RGPD ni une validation du secret du scrutin.

## Ce que corrige cette version

Le code personnel d’AG n’est plus envoyé par mail. La messagerie sert seulement à transmettre un OTP de six chiffres, lié à une demande de vérification et expirant après dix minutes. Cet OTP ne permet pas, à lui seul, d’ouvrir l’AG ou de voter. La demande utilise aussi un cookie aléatoire distinct. Le relais ne reçoit pas le nom de l’AG et refuse tout envoi de code d’AG, même avec une signature valide.

Après vérification, le code d’AG est tiré aléatoirement et affiché uniquement sur le site. Il doit être conservé par l’électeur. Il n’existe pas de récupération par mail.

La migration 006 retire l’adresse en clair de la table des vérifications. Les tables utilisées sont séparées :

| Donnée | Contenu conservé | Absence de lien direct |
|---|---|---|
| Vérification temporaire | empreinte de jeton, empreinte avec clé de l’adresse, empreinte OTP, AG, expiration et essais | pas d’adresse en clair ni de code d’AG |
| Anti-doublon | AG et empreinte avec clé de l’adresse | pas d’identifiant de code ni de bulletin |
| Code d’AG | identifiant aléatoire, empreinte du code, jeton d’accès, AG, validité | pas d’adresse ni de son empreinte |
| Émargement | code, sujet et AG | pas de choix exprimé |
| Bulletin | identifiant aléatoire, sujet et choix | pas de code, adresse ou horodatage |

La validité des nouveaux codes est arrondie à une date UTC, jusqu’à 90 jours, afin de ne pas conserver l’heure exacte d’émission dans leur date d’expiration. Les journaux d’invocation automatiques du Worker sont désactivés. Le code applicatif n’enregistre ni corps de formulaire, ni code, ni adresse dans les journaux.

## Protection de la confidentialité

Le mail transmet uniquement un code temporaire de vérification. Le code d’AG n’est pas envoyé par mail et les tables ne contiennent pas de correspondance directe entre adresse et bulletin. Des risques de corrélation subsistent : ces protections constituent une pseudonymisation et ne garantissent pas l’anonymat face à l’exploitant technique. Les données restent soumises au RGPD. L’analyse détaillée et le test de ce risque sont conservés dans le dossier d’audit, hors du document public regroupé.

## Réponse RGPD pour une consultation informelle

Le RGPD continue à s’appliquer : l’adresse, les IP, les données de participation et les empreintes pseudonymisées restent susceptibles de concerner des personnes identifiables. Une empreinte avec clé réduit le risque ; elle n’est pas une anonymisation irréversible. Le fait d’organiser une consultation informelle plutôt qu’une élection officielle ne supprime pas ces obligations.

Avant une utilisation réelle, l’organisateur doit notamment documenter :

1. L’identité et les coordonnées du responsable du traitement, les finalités précises et une base légale adaptée (article 6). Ne pas choisir automatiquement le consentement ni inventer une base légale à partir du code.
2. Une information des participants au moment de la collecte : finalités, base légale, destinataires, durées ou critères, droits et contact pour les exercer, éventuels transferts hors EEE et garanties. Le bref texte technique du formulaire ne remplace pas cette notice complète.
3. Des durées justifiées et un mécanisme réel de purge. Le cron retire les OTP et compteurs expirés et supprime les AG selon la conservation active de 30 jours décrite en tête de document. Il reste à vérifier et appliquer la conservation des historiques, mails, exports et sauvegardes. La validité d’un code n’est pas une durée de conservation.
4. Les accès et contrats de sous-traitance pour l’hébergement et l’envoi, les réglages des comptes Cloudflare/Google, les transferts éventuels, les sauvegardes et la procédure de gestion des incidents. L’usage d’un Gmail personnel ne vaut pas à lui seul contrat de sous-traitance conforme.
5. Le registre des traitements lorsque requis et une analyse des risques. Une AIPD est nécessaire si le traitement est susceptible de présenter un risque élevé ; son obligation n’est pas déterminée par le seul nombre d’électeurs.

Si les thèmes ou la participation révèlent des opinions politiques ou une appartenance syndicale, des données sensibles peuvent être concernées : une condition autorisant leur traitement au titre de l’article 9 doit alors être examinée en plus de la base légale de l’article 6. Ce n’est pas automatique pour toute AG étudiante ; le contenu et l’usage réel comptent.

Cette application vérifie un domaine de messagerie et limite à un code par adresse et par AG. Elle ne certifie pas l’identité, la qualité d’électeur ou l’unicité d’une personne possédant plusieurs adresses. La légalité RGPD et la validité d’un scrutin sont deux questions distinctes.

En l’absence des éléments organisationnels et contractuels ci-dessus, il n’est pas possible de déclarer le dispositif conforme. Faire valider le contexte par le DPO compétent ou un juriste avant de présenter les résultats comme un scrutin secret garanti. La recommandation CNIL publiée en avril 2026 est une référence actuelle pour l’évaluation des systèmes de vote ; le niveau d’exigence doit correspondre aux risques et au type de consultation.

## Sources officielles consultées

- CNIL, anonymisation et pseudonymisation : https://www.cnil.fr/fr/technologies/lanonymisation-de-donnees-personnelles
- CNIL, information et transparence : https://www.cnil.fr/fr/conformite-rgpd-information-des-personnes-et-transparence
- Service public, obligations RGPD : https://entreprendre.service-public.gouv.fr/vosdroits/F24270
- CNIL, données révélant des opinions politiques : https://www.cnil.fr/fr/les-fichiers-de-communication-politique
- CEPD, AIPD : https://www.edpb.europa.eu/topics/accountability-and-compliance-tools/data-protection-impact-assessment_fr
- CNIL, recommandation vote électronique du 24 avril 2026 : https://www.cnil.fr/fr/recommandation-vote-electronique

## Protections compl?mentaires du 10 novembre

Les empreintes des adresses sont propres à chaque AG et distinctes des clés de limitation. Les anciennes empreintes sont converties progressivement par le cron ; les archives historiques ne sont pas modifiées. Le second facteur administrateur ajouté initialement a été retiré le 22 novembre à la demande du responsable : la connexion utilise l’identifiant et le mot de passe. Les résultats restent masqués avant la fin programmée, sous six votes, en cas d’unanimité ou de choix représenté par moins de trois votes. Ces protections réduisent les risques sans éliminer la corrélation par l’exploitant. Voir le rapport de correctifs et la notice à compléter.
