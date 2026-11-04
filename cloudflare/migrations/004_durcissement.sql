-- Migration à appliquer après sauvegarde D1 et avant le Worker correspondant.
-- Sépare l'émargement du bulletin pour empêcher de relier un code à son choix.
CREATE UNIQUE INDEX IF NOT EXISTS idx_choix_id_scrutin
    ON choix(id,scrutin_id);
CREATE INDEX IF NOT EXISTS idx_ag_votes_choix ON ag_votes(choix_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_administrateur_principal_unique
    ON administrateurs(role) WHERE role='principal';

ALTER TABLE scrutins ADD COLUMN ferme_par INTEGER REFERENCES administrateurs(id) ON DELETE SET NULL;
ALTER TABLE scrutins ADD COLUMN ferme_le TEXT;

ALTER TABLE ag_codes ADD COLUMN jeton_acces TEXT;
ALTER TABLE ag_codes ADD COLUMN expire_le INTEGER;
ALTER TABLE ag_codes ADD COLUMN revoque_le INTEGER;
ALTER TABLE ag_codes ADD COLUMN revelation_hash TEXT;
UPDATE ag_codes SET jeton_acces=lower(hex(randomblob(24))) WHERE jeton_acces IS NULL;
UPDATE ag_codes SET expire_le=unixepoch('now') + 90*24*60*60 WHERE expire_le IS NULL;
UPDATE ag_codes SET cree_le=substr(cree_le,1,10) || 'T00:00:00Z';
CREATE UNIQUE INDEX idx_ag_codes_jeton_acces ON ag_codes(jeton_acces);

CREATE TRIGGER IF NOT EXISTS ag_codes_precision_jour
AFTER INSERT ON ag_codes
BEGIN
    UPDATE ag_codes SET cree_le=substr(NEW.cree_le,1,10) || 'T00:00:00Z'
    WHERE id=NEW.id;
END;

CREATE TABLE ag_emargements (
    code_id INTEGER NOT NULL,
    scrutin_id INTEGER NOT NULL,
    assemblee_id INTEGER NOT NULL,
    PRIMARY KEY (code_id, scrutin_id),
    FOREIGN KEY (code_id, assemblee_id)
        REFERENCES ag_codes(id, assemblee_id) ON DELETE CASCADE,
    FOREIGN KEY (scrutin_id, assemblee_id)
        REFERENCES scrutins(id, assemblee_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX idx_ag_emargements_scrutin ON ag_emargements(scrutin_id);

CREATE TABLE ag_bulletins (
    bulletin_id TEXT PRIMARY KEY,
    scrutin_id INTEGER NOT NULL,
    choix_id INTEGER NOT NULL,
    FOREIGN KEY (choix_id, scrutin_id)
        REFERENCES choix(id, scrutin_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX idx_ag_bulletins_scrutin ON ag_bulletins(scrutin_id, choix_id);

-- Conserve les participations et les totaux historiques sans conserver le lien code/choix.
INSERT OR IGNORE INTO ag_emargements(code_id, scrutin_id, assemblee_id)
SELECT code_id, scrutin_id, assemblee_id FROM ag_votes;
INSERT INTO ag_bulletins(bulletin_id, scrutin_id, choix_id)
SELECT lower(hex(randomblob(24))), scrutin_id, choix_id FROM ag_votes;
DROP TABLE ag_votes;

CREATE TABLE journal_admin (
    id INTEGER PRIMARY KEY,
    admin_id INTEGER,
    action TEXT NOT NULL,
    cible_type TEXT NOT NULL,
    cible_id TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    le TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_journal_admin_le ON journal_admin(le);
CREATE INDEX idx_journal_admin_cible ON journal_admin(cible_type, cible_id);

CREATE TRIGGER IF NOT EXISTS valider_dates_scrutin_insert
BEFORE INSERT ON scrutins
WHEN NOT (length(NEW.debut_utc)=20 AND NEW.debut_utc GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
      AND length(NEW.fin_utc)=20 AND NEW.fin_utc GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
      AND unixepoch(NEW.debut_utc) IS NOT NULL AND unixepoch(NEW.fin_utc)>unixepoch(NEW.debut_utc))
BEGIN
    SELECT RAISE(ABORT,'invalid poll schedule');
END;

CREATE TRIGGER IF NOT EXISTS valider_dates_scrutin_update
BEFORE UPDATE OF debut_utc,fin_utc ON scrutins
WHEN NOT (length(NEW.debut_utc)=20 AND NEW.debut_utc GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
      AND length(NEW.fin_utc)=20 AND NEW.fin_utc GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
      AND unixepoch(NEW.debut_utc) IS NOT NULL AND unixepoch(NEW.fin_utc)>unixepoch(NEW.debut_utc))
BEGIN
    SELECT RAISE(ABORT,'invalid poll schedule');
END;

-- L'ancienne table est désormais inutile et relie directement le code au choix.
