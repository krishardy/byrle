-- A Maven file with no `.asc` after a version with one keeps its release line's history:
-- whether each of at most 64 earlier versions in the line was signed, newest first, `1` or
-- `0`, which the provenance check weighs. A `dropped` row with none was written before it,
-- and is read as not checked, so it is asked again. See docs/risk-score-plan.md step 6.
ALTER TABLE artifact_signature ADD COLUMN history VARCHAR(64);
