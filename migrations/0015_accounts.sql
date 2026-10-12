-- Accounts, and the proxy tokens that identify them on each request. See
-- docs/engineering_decisions/account-identification.md and docs/admin-plan.md §4.3.
--
-- A token is stored as its SHA-256 in lowercase hex, never as the token. Names follow
-- src/account.rs: 1 to 64 of a-z, 0-9, `.`, `_` and `-`.
CREATE TABLE account (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        VARCHAR(64) NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- When it was disabled. Its tokens stop working then. NULL while it is enabled.
    disabled_at TIMESTAMPTZ
);

CREATE TABLE proxy_token (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES account (id),
    name       VARCHAR(64) NOT NULL,
    digest     CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- When it was revoked. NULL while it works.
    revoked_at TIMESTAMPTZ,
    UNIQUE (account_id, name)
);
