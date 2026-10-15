-- The digest of the bytes found to be what a claim names, keyed by the claim: a Go zip's
-- `h1:` from sum.golang.org, and the sha256 of the zip whose files hash to it. The zip is
-- served checked against that sha256 as it streams. See docs/go-plan.md, step 3.
--
-- A check that failed writes no row, so a missing row is "not checked yet".
CREATE TABLE artifact_claim (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The claim as the database wrote it, such as `h1:` and 44 characters of base64.
    claim      VARCHAR(128) NOT NULL UNIQUE,
    -- The Subresource Integrity string of the bytes checked, as in artifact_analysis.
    digest     VARCHAR(128) NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
