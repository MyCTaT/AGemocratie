CREATE TABLE IF NOT EXISTS ag_mail_verifications_sans_adresse (
    token_hash TEXT PRIMARY KEY,
    assemblee_id INTEGER NOT NULL REFERENCES assemblees(id) ON DELETE CASCADE,
    email_hash TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    expire_le INTEGER NOT NULL,
    essais INTEGER NOT NULL DEFAULT 0,
    verifie INTEGER NOT NULL DEFAULT 0
);
INSERT OR REPLACE INTO ag_mail_verifications_sans_adresse
    (token_hash,assemblee_id,email_hash,otp_hash,expire_le,essais,verifie)
SELECT token_hash,assemblee_id,email_hash,otp_hash,expire_le,essais,verifie
FROM ag_mail_verifications;
DROP TABLE ag_mail_verifications;
ALTER TABLE ag_mail_verifications_sans_adresse RENAME TO ag_mail_verifications;
CREATE INDEX IF NOT EXISTS idx_ag_mail_expiration ON ag_mail_verifications(expire_le);
