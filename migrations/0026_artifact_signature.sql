-- What a file's detached PGP signature says, keyed by the digest of the bytes it was
-- checked against: a Maven jar's `.asc`, checked in the claim job beside its claim. See
-- docs/engineering_decisions/0113-maven-signatures.md.
--
-- A key server or repository that could not be asked writes no row, and no claim, so the
-- next request checks both again. A row is read back only by the verifier that wrote it,
-- so a fix to the verifier checks a failure again rather than keep the refusal.
CREATE TABLE artifact_signature (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The Subresource Integrity string of the bytes checked, as in artifact_claim.
    digest     VARCHAR(128) NOT NULL,
    -- `verified`, `failed`, `dropped` or `unsigned`.
    outcome    VARCHAR(16) NOT NULL,
    -- The signing primary key's fingerprint, why it failed, or the earlier version signed.
    -- TEXT, as artifact_attestation.failure is: a failure's message has no bound.
    detail     TEXT,
    -- `pgp <version>; <rules>`, from ecosystem::maven::signature::VERIFIER.
    verifier   VARCHAR(128) NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (digest, verifier),
    CHECK (outcome IN ('verified', 'failed', 'dropped', 'unsigned')),
    CHECK ((outcome = 'unsigned') = (detail IS NULL))
);

-- A Maven claim is `<algorithm>:<hex>`, and a SHA-512 one is 135 characters.
ALTER TABLE artifact_claim ALTER COLUMN claim TYPE VARCHAR(160);
