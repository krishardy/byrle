-- Each account's console password, as an Argon2id PHC string, never the password. See
-- src/account/password.rs and docs/engineering_decisions/console-login.md.
--
-- The PHC string carries its own parameters and salt, so a hash made under older
-- parameters is still verified. One row per account with a password.
CREATE TABLE account_password (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id BIGINT NOT NULL UNIQUE REFERENCES account (id),
    hash       VARCHAR(255) NOT NULL,
    set_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
