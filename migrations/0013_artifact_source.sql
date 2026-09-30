-- What comparing one artifact with the source its metadata names found, keyed by the
-- artifact's digest. Report only: see docs/engineering_decisions/source-diff.md.
--
-- A fetch that could not be made writes no row, so a missing row is "not compared yet".
-- A row is read back only by the comparer that wrote it, so a comparer that changes what
-- it finds compares again.
CREATE TABLE artifact_source (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The Subresource Integrity string the metadata published, as in artifact_analysis.
    digest      VARCHAR(128) NOT NULL UNIQUE,
    -- analysis::source::Sourced as JSON. TEXT: its file lists have no bound.
    result      TEXT NOT NULL,
    -- analysis::source::COMPARER.
    comparer    VARCHAR(64) NOT NULL,
    compared_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
