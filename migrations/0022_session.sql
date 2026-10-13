-- Console sessions, each stored as the SHA-256 of its id in lowercase hex, never the id.
-- See src/console/login.rs and docs/engineering_decisions/console-login.md.
--
-- A session ends at `expires_at`, when it is deleted at logout, or when its account is
-- disabled, which the lookup checks. Expired rows are deleted as new sessions are made.
CREATE TABLE session (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES account (id),
    digest     CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX session_by_expiry ON session (expires_at);
