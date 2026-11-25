CREATE TABLE IF NOT EXISTS ag_mail_verifications (
    token_hash TEXT PRIMARY KEY,
    assemblee_id INTEGER NOT NULL REFERENCES assemblees(id) ON DELETE CASCADE,
    email_hash TEXT NOT NULL,
    email TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    expire_le INTEGER NOT NULL,
    essais INTEGER NOT NULL DEFAULT 0,
    verifie INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ag_mail_expiration ON ag_mail_verifications(expire_le);
CREATE TABLE IF NOT EXISTS ag_mail_delivrances (
    assemblee_id INTEGER NOT NULL REFERENCES assemblees(id) ON DELETE CASCADE,
    email_hash TEXT NOT NULL,
    PRIMARY KEY(assemblee_id, email_hash)
) WITHOUT ROWID;
