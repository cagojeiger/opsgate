-- PRECONDITION: users is empty on dev-v3. `sub NOT NULL` on a populated
-- table errors loudly by design (there is no source to backfill sub).
ALTER TABLE users
    ADD COLUMN sub          TEXT NOT NULL,
    ADD COLUMN display_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN is_active    BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE users ADD CONSTRAINT users_sub_key UNIQUE (sub);
