CREATE TABLE IF NOT EXISTS ag_mail_delivrances_v2 (
 assemblee_id INTEGER NOT NULL REFERENCES assemblees(id) ON DELETE CASCADE,
 email_hash TEXT NOT NULL, PRIMARY KEY(assemblee_id,email_hash)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS app_schema_flags(name TEXT PRIMARY KEY);

DELETE FROM ag_mail_verifications WHERE NOT EXISTS(SELECT 1 FROM app_schema_flags WHERE name='ag-mail-v2');
INSERT OR IGNORE INTO app_schema_flags(name) VALUES ('ag-mail-v2');
CREATE TABLE IF NOT EXISTS admin_mfa_replays (
 admin_id INTEGER PRIMARY KEY REFERENCES administrateurs(id) ON DELETE CASCADE,
 last_step INTEGER NOT NULL
);
