-- Each OIDC identity, its issuer and subject, and the account it logs in as. Linked by an
-- admin with `byrle account link`; an identity linked to no account is refused. Decided by
-- the user 2026-10-13, who may change it. See docs/engineering_decisions/console-login.md.
CREATE TABLE account_oidc (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES account (id),
    -- `BYRLE_OIDC_ISSUER` as the tokens name it.
    issuer     VARCHAR(512) NOT NULL,
    subject    VARCHAR(255) NOT NULL,
    linked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);
