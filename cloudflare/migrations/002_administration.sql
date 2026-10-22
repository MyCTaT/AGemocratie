ALTER TABLE administrateurs ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE scrutins ADD COLUMN ferme_manuellement INTEGER NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_identifiant_sans_casse
    ON administrateurs(lower(identifiant));
CREATE TABLE IF NOT EXISTS limites_connexion (
    empreinte TEXT PRIMARY KEY,
    debut_fenetre INTEGER NOT NULL,
    echecs INTEGER NOT NULL
);
