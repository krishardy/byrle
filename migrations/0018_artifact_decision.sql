-- Each pinned decision on an artifact, with the features it was decided on and its
-- disposition, and the latest decision on each artifact. See
-- docs/engineering_decisions/artifact-decisions.md.
--
-- One row per pinned audit line the proxy writes about an artifact: a retry the proxy
-- deferred is a row each time, and a body cut short is a row after the one that served it.
CREATE TABLE artifact_decision (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    decided_at  TIMESTAMPTZ NOT NULL,
    -- The Subresource Integrity string the metadata published. NULL when it published no
    -- strong digest, so the bytes were never analysed.
    digest      VARCHAR(128),
    ecosystem   VARCHAR(64) NOT NULL,
    -- The registry name: PyPI's normalised, npm's with its scope.
    name        VARCHAR(512) NOT NULL,
    version     VARCHAR(255) NOT NULL,
    account     VARCHAR(64),
    action      VARCHAR(16) NOT NULL,
    answered    VARCHAR(32) NOT NULL,
    -- analysis::decision::Decided as JSON, which every column above is read from.
    decision    JSONB NOT NULL
);
CREATE INDEX artifact_decision_by_digest ON artifact_decision (digest, id)
    WHERE digest IS NOT NULL;
CREATE INDEX artifact_decision_by_version ON artifact_decision (ecosystem, name, version);
CREATE INDEX artifact_decision_by_time ON artifact_decision (decided_at);

-- The latest decision on each artifact with a digest.
CREATE VIEW artifact_disposition AS
    SELECT DISTINCT ON (digest) *
    FROM artifact_decision
    WHERE digest IS NOT NULL
    ORDER BY digest, id DESC;
