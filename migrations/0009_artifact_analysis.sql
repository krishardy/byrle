-- What analysing an artifact found, keyed by the digest of the bytes that were read.
--
-- The fetch path buffers and analyses an artifact nothing has analysed, and streams one
-- that has been analysed straight through, reading its verdict from here. See
-- docs/engineering_decisions/fetch-path-branching.md.
--
-- The key is the content digest, not the package. A registry that repoints a version at
-- different bytes produces a different key, so those bytes are analysed.
--
-- Sizes follow migrations/0001_intel.sql. TEXT is used for the two values with no bound:
-- an npm script body, which package.json does not limit, and the message a read error
-- carries, which comes from serde_json or the tar reader.
CREATE TABLE artifact_analysis (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The Subresource Integrity string the metadata published: `sha512-` and 88 base64
    -- characters, 95 in all.
    digest      VARCHAR(128) NOT NULL UNIQUE,
    -- The package this artifact was most recently fetched as. Read by an operator
    -- querying the table; the fetch path reads the scripts, and keys on the digest.
    ecosystem   VARCHAR(64) NOT NULL,
    name        VARCHAR(512) NOT NULL,
    version     VARCHAR(255) NOT NULL,
    -- What the read error said, when the archive could not be read. NULL when it was
    -- read, which is what separates an archive declaring no script from one nobody could
    -- ask. See src/analysis/store.rs.
    unreadable  TEXT,
    analysed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The scripts one artifact declares run on install, in the order the reader found them,
-- which for npm is the order npm runs them.
CREATE TABLE artifact_install_script (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    analysis_id BIGINT NOT NULL REFERENCES artifact_analysis (id) ON DELETE CASCADE,
    ordinal     SMALLINT NOT NULL,
    name        VARCHAR(64) NOT NULL,
    -- The command npm runs. NULL for a PyPI sdist, where the reader reports a setup.py at
    -- the root of the archive and there is no command to report.
    body        TEXT,
    UNIQUE (analysis_id, name)
);
