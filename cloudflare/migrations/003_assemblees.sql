-- AGémocratie / D1 : une AG contient plusieurs sujets.
-- IMPORTANT : sauvegarder la base et exécuter UNE seule fois sur la D1 DISTANTE.
-- Ne pas appliquer la migration avant d'avoir prévu le nouveau Worker.
CREATE TABLE assemblees (
    id INTEGER PRIMARY KEY,
    titre TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    cree_par INTEGER REFERENCES administrateurs(id) ON DELETE SET NULL,
    cree_le TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

ALTER TABLE scrutins ADD COLUMN assemblee_id INTEGER
    REFERENCES assemblees(id) ON DELETE CASCADE;

-- Préserver les sujets existants, même anciens, dans une AG d'archives.
INSERT INTO assemblees (id, titre, description)
SELECT 1, 'AG historique', 'Sujets présents avant le passage aux AG.'
WHERE EXISTS (SELECT 1 FROM scrutins WHERE assemblee_id IS NULL);
UPDATE scrutins SET assemblee_id=1 WHERE assemblee_id IS NULL;

CREATE UNIQUE INDEX idx_scrutins_id_ag ON scrutins(id,assemblee_id);
CREATE INDEX idx_scrutins_ag ON scrutins(assemblee_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_choix_id_scrutin ON choix(id,scrutin_id);

CREATE TABLE ag_codes (
    id INTEGER PRIMARY KEY,
    assemblee_id INTEGER NOT NULL REFERENCES assemblees(id) ON DELETE CASCADE,
    empreinte_code TEXT NOT NULL UNIQUE,
    cree_le TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(id, assemblee_id)
);
CREATE INDEX idx_ag_codes_ag ON ag_codes(assemblee_id);

CREATE TABLE ag_votes (
    id INTEGER PRIMARY KEY,
    assemblee_id INTEGER NOT NULL,
    scrutin_id INTEGER NOT NULL,
    choix_id INTEGER NOT NULL,
    code_id INTEGER NOT NULL,
    vote_le TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(code_id, scrutin_id),
    FOREIGN KEY (code_id,assemblee_id)
        REFERENCES ag_codes(id,assemblee_id) ON DELETE CASCADE,
    FOREIGN KEY (scrutin_id,assemblee_id)
        REFERENCES scrutins(id,assemblee_id) ON DELETE CASCADE,
    FOREIGN KEY (choix_id,scrutin_id)
        REFERENCES choix(id,scrutin_id) ON DELETE CASCADE
);
CREATE INDEX idx_ag_votes_scrutin ON ag_votes(scrutin_id);
CREATE INDEX idx_ag_votes_choix ON ag_votes(choix_id);
