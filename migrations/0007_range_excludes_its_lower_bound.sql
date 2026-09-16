-- An interval whose lower bound is excluded.
--
-- OSV writes only inclusive lower bounds, so `introduced` alone said everything about an
-- OSV range. GitHub writes `vulnerableVersionRange` as `> 4.0.2`, which says 4.0.2 is the
-- last version not affected. Storing that as `introduced: 4.0.2` reports 4.0.2 itself as
-- vulnerable, so the stream dropped those advisories instead: 11 of GitHub's 7,056 npm
-- advisories on 2026-09-16, including all three it holds that OSV's bundle lacks.
--
-- FALSE for every row OSV and Datadog write. See src/intel/range.rs, `Start`.
ALTER TABLE advisory_range
    ADD COLUMN introduced_excluded BOOLEAN NOT NULL DEFAULT FALSE;

-- Excluding a version means naming it.
ALTER TABLE advisory_range
    ADD CONSTRAINT advisory_range_excluded_names_a_version
    CHECK (NOT introduced_excluded OR introduced IS NOT NULL);

-- `>= 1.0.0, < 2.0.0` and `> 1.0.0, < 2.0.0` are different intervals, so the column joins
-- the uniqueness of a row.
DROP INDEX advisory_range_unique;
CREATE UNIQUE INDEX advisory_range_unique ON advisory_range (
    advisory_id, ecosystem, name,
    COALESCE(introduced, ''), introduced_excluded,
    COALESCE(fixed, ''), COALESCE(last_affected, '')
);
