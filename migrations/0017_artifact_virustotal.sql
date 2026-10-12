-- What VirusTotal said about one artifact, keyed by the artifact's digest, and the requests
-- made to it. Report only: see docs/engineering_decisions/virustotal.md.
--
-- A request that was not answered writes no row, so a missing row is "not asked yet".
CREATE TABLE artifact_virustotal (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The Subresource Integrity string the metadata published, as in artifact_analysis.
    digest      VARCHAR(128) NOT NULL UNIQUE,
    -- The SHA-256 of the verified bytes, lowercase hex, which VirusTotal is asked by.
    sha256      CHAR(64) NOT NULL,
    -- `known` with counts, `unknown`, or `queued` with the id of an analysis not finished.
    state       VARCHAR(16) NOT NULL CHECK (state IN ('known', 'unknown', 'queued')),
    analysis    VARCHAR(128),
    malicious   INTEGER,
    suspicious  INTEGER,
    -- Every engine counted, whatever it answered.
    engines     INTEGER,
    asked_at    TIMESTAMPTZ NOT NULL,
    CHECK ((state = 'known') = (malicious IS NOT NULL AND suspicious IS NOT NULL AND engines IS NOT NULL)),
    CHECK ((state = 'queued') = (analysis IS NOT NULL))
);

-- One row per request VirusTotal answered, so a restart counts the day's requests against
-- BYRLE_VIRUSTOTAL_PER_DAY. Rows older than two days are deleted as new ones are written.
CREATE TABLE virustotal_request (
    id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asked_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX virustotal_request_by_time ON virustotal_request (asked_at);
