CREATE TABLE IF NOT EXISTS faq_questions (
    id INTEGER PRIMARY KEY,
    question TEXT NOT NULL CHECK(length(question) BETWEEN 10 AND 1000),
    reponse TEXT NOT NULL DEFAULT '' CHECK(length(reponse)<=5000),
    cree_le INTEGER NOT NULL,
    publie_le INTEGER
);
CREATE INDEX IF NOT EXISTS idx_faq_publication ON faq_questions(publie_le,cree_le);
