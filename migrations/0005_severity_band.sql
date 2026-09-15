-- The severity band an advisory's score was read from, when it carries no CVSS vector.
--
-- 689 of OSV's npm `GHSA-` records on 2026-09-15 had only `database_specific.severity`: LOW,
-- MODERATE, HIGH or CRITICAL. The score stored for one is the band's upper bound, and this
-- column says so, for `explain`. NULL when the score came from a vector or there is none. See
-- docs/engineering_decisions/osv-ranges-and-scores.md.
ALTER TABLE advisory ADD COLUMN severity_band VARCHAR(16);
