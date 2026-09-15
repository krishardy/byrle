-- Every stream each `waharoa refresh` loaded or did not, appended and never pruned, so which feed
-- was ingested when, and from which bundle, can be read back for an audit. `waharoa intel
-- history` prints it. See docs/engineering_decisions/ingestion-history.md. Keys and sizes follow
-- 0001_intel.sql.
--
-- A stream that loaded is recorded in the load's own transaction, so a load that rolls back
-- leaves no row saying it loaded.
CREATE TABLE intel_ingestion (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- When the refresh recorded it. Every row one refresh writes has the same value, and for a
    -- refresh that loaded it is the snapshot's `taken_at`.
    taken_at      TIMESTAMPTZ NOT NULL,
    source        VARCHAR(32) NOT NULL,
    stream        VARCHAR(64) NOT NULL,
    -- The bundle, when it was fetched: its hex SHA-256 and the response's headers. The headers
    -- are the upstream's own and have no bound.
    sha256        VARCHAR(64),
    etag          TEXT,
    last_modified TEXT,
    -- `sha256:` and 64 hex digits over the rows loaded, as `intel_source.digest`.
    rows_digest   VARCHAR(71),
    -- The snapshot the store contains after the refresh. NULL when the refresh loaded nothing.
    snapshot      VARCHAR(71),
    -- Why the stream did not load. NULL when it loaded.
    error         TEXT,
    CHECK (error IS NOT NULL
           OR (sha256 IS NOT NULL AND rows_digest IS NOT NULL AND snapshot IS NOT NULL)),
    CHECK (error IS NULL OR rows_digest IS NULL)
);
