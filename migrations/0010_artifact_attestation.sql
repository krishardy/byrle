-- What verifying one artifact's attestations found, keyed by the digest they were verified
-- against. The provenance check compares a version's with the version published before it,
-- so the previous version's result is kept too, without its tarball ever being fetched.
-- See docs/engineering_decisions/provenance-check.md.
--
-- One of identity and failure is set. A registry that could not be reached writes no row,
-- so a missing row is "not verified yet" and never "no attestation".
CREATE TABLE artifact_attestation (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The Subresource Integrity string the metadata published, as in artifact_analysis.
    digest      VARCHAR(128) NOT NULL UNIQUE,
    -- The repository and workflow file the certificate names, without the ref:
    -- `github.com/o/r/.github/workflows/release.yml`.
    identity    VARCHAR(1024),
    -- Why the attestation did not verify, as sigstore-verify or the JSON reader said it.
    -- TEXT, as artifact_analysis.unreadable is: the message has no bound.
    failure     TEXT,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((identity IS NULL) <> (failure IS NULL))
);
