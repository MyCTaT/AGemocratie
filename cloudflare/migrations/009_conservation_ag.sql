CREATE TRIGGER IF NOT EXISTS nettoyer_donnees_ag
BEFORE DELETE ON assemblees
BEGIN
 DELETE FROM journal_admin WHERE
   (cible_type='ag' AND cible_id=CAST(OLD.id AS TEXT)) OR
   (cible_type='poll' AND cible_id IN (SELECT CAST(id AS TEXT) FROM scrutins WHERE assemblee_id=OLD.id)) OR
   (cible_type='ag_code' AND cible_id IN (SELECT CAST(id AS TEXT) FROM ag_codes WHERE assemblee_id=OLD.id));
 DELETE FROM votes WHERE scrutin_id IN (SELECT id FROM scrutins WHERE assemblee_id=OLD.id);
 DELETE FROM codes_vote WHERE scrutin_id IN (SELECT id FROM scrutins WHERE assemblee_id=OLD.id);
END;
