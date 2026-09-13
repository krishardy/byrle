-- Version intervals an advisory is against.
--
-- `advisory_affected` holds "every version" and named versions. A record that gives a range
-- instead, such as `introduced: 1.2.2, fixed: 2.0.0`, is held here, one row per interval,
-- and evaluated when a package is looked up: the loader has no list of versions to expand
-- it against. See src/intel/range.rs.
CREATE TABLE advisory_range (
    advisory_id   TEXT NOT NULL REFERENCES advisory (id) ON DELETE CASCADE,
    ecosystem     TEXT NOT NULL,
    name          TEXT NOT NULL,
    -- NULL is from the first version, OSV's `introduced: "0"`.
    introduced    TEXT,
    -- The first version not affected. Excludes itself.
    fixed         TEXT,
    -- The last version affected. Includes itself.
    last_affected TEXT,
    CHECK (fixed IS NULL OR last_affected IS NULL),
    -- All three NULL is every version, which `advisory_affected` holds as a NULL version.
    CHECK (introduced IS NOT NULL OR fixed IS NOT NULL OR last_affected IS NOT NULL)
);

CREATE UNIQUE INDEX advisory_range_unique ON advisory_range (
    advisory_id, ecosystem, name,
    COALESCE(introduced, ''), COALESCE(fixed, ''), COALESCE(last_affected, '')
);
CREATE INDEX advisory_range_lookup ON advisory_range (ecosystem, name);
