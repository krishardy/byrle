-- Which reader wrote an analysis. A row is read back only by the reader that wrote it, so a
-- reader that finds something an older one missed reads the artifact again rather than keep
-- the older answer: an analysis is permanently valid for its bytes and its reader, not for
-- its bytes alone. Rows written before this column read as the empty reader, which no build
-- is, and are analysed again. See src/analysis.rs, READER.
ALTER TABLE artifact_analysis ADD COLUMN reader VARCHAR(64) NOT NULL DEFAULT '';
