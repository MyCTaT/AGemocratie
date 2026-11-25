SELECT count(*) AS ag_hors_delai FROM assemblees a
WHERE COALESCE((SELECT MAX(unixepoch(s.fin_utc)) FROM scrutins s
                WHERE s.assemblee_id=a.id),unixepoch(a.cree_le))<=unixepoch('now')-2592000;
SELECT count(*) AS otp_expires FROM ag_mail_verifications WHERE expire_le<=unixepoch('now');
SELECT count(*) AS compteurs_expires FROM limites_connexion WHERE debut_fenetre<=unixepoch('now')-900;
SELECT count(*) AS journal_hors_delai FROM journal_admin WHERE unixepoch(le)<=unixepoch('now')-2592000;
SELECT count(*) AS anciennes_empreintes_a_convertir FROM ag_mail_delivrances;
SELECT count(*) AS dates_ag_invalides FROM assemblees a
WHERE unixepoch(a.cree_le) IS NULL OR EXISTS (
 SELECT 1 FROM scrutins s WHERE s.assemblee_id=a.id AND unixepoch(s.fin_utc) IS NULL
);
