-- The roles each account holds, by name. See docs/admin-plan.md §4.2 and
-- src/account/role.rs, where each role's permissions are defined.
--
-- No CHECK on `role`: adding a role is a change to the code, not to the schema. A name this
-- build does not know is skipped when read.
CREATE TABLE account_role (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES account (id),
    role       VARCHAR(32) NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id, role)
);
