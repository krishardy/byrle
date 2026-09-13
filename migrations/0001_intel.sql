-- What the advisory streams know, normalised.
--
-- Written for the checks that read it. `known_malware` asks one question of a package,
-- `max_cvss` asks for scores, `kev` asks whether an advisory is exploited. The shape below
-- answers those and nothing else yet.
--
-- Every table is keyed by a `BIGINT` identity, and tables join on it. `TEXT` is used only
-- where a value has no bound: `summary`. Every other string is sized from the longest value
-- in OSV's npm bundle of 2026-09-13, with headroom for other ecosystems:
--
-- | column                   | longest measured | size |
-- |--------------------------|------------------|------|
-- | `publisher_id`, `alias`  | 68               | 128  |
-- | `ecosystem`              | 14               | 64   |
-- | `name`                   | 213              | 512  |
-- | a version or range bound | 74               | 255  |
--
-- A longer value fails the load, and the previous load stays in place. See
-- docs/engineering_decisions/intel-schema-keys-and-types.md.
--
-- Timestamps are `TIMESTAMPTZ`, written as RFC 3339 text and cast by Postgres. Nothing reads
-- one back into Rust, so the codebase keeps one date library, jiff, which sqlx 0.8 has no
-- mapping for. Postgres keeps microseconds, so OSV's nanosecond `modified` is rounded.

-- One advisory, whoever published it.
CREATE TABLE advisory (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The publisher's own id: GHSA-xxxx, MAL-xxxx, CVE-xxxx. Different streams use
    -- different id spaces for the same vulnerability, which is what `advisory_alias` is for.
    publisher_id VARCHAR(128) NOT NULL UNIQUE,
    -- Which stream supplied this record. Kept for `explain` and for attribution: GHSA
    -- text is CC-BY-4.0 and has to be credited where it is shown.
    source       VARCHAR(32) NOT NULL,
    summary      TEXT,
    -- NULL where no stream has scored it. Distinct from 0.0, which is a real CVSS score.
    cvss         DOUBLE PRECISION,
    -- Which stream supplied the score. An `enrich` stream may raise it, so the two can
    -- differ from `source`.
    cvss_source  VARCHAR(32),
    -- Known to be exploited. Only an `enrich` stream sets this; see src/intel.rs.
    exploited    BOOLEAN NOT NULL DEFAULT FALSE,
    -- A malware report rather than a vulnerability. Feeds the one check with no exception,
    -- so it is a column rather than something inferred from the id prefix.
    malware      BOOLEAN NOT NULL DEFAULT FALSE,
    modified     TIMESTAMPTZ
);

-- A refresh deletes by source, then reads back the keys it just assigned by source.
CREATE INDEX advisory_by_source ON advisory (source);

-- The other ids this advisory is known by.
--
-- CISA keys on CVE ids and OSV publishes GHSA and MAL ids, so a KEV entry reaches an OSV
-- finding only through this table. Until it is populated, an `enrich` stream matches
-- nothing; see the deduplication item in TODO.md.
CREATE TABLE advisory_alias (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    advisory_id BIGINT NOT NULL REFERENCES advisory (id) ON DELETE CASCADE,
    alias       VARCHAR(128) NOT NULL,
    UNIQUE (advisory_id, alias)
);

CREATE INDEX advisory_alias_by_alias ON advisory_alias (alias);

-- Which package versions an advisory is against.
--
-- `version` NULL means every version of the package, which is how a malware report usually
-- reads: the package itself is the problem. A named version affects only that one.
-- Intervals are in `advisory_range`.
CREATE TABLE advisory_affected (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    advisory_id BIGINT NOT NULL REFERENCES advisory (id) ON DELETE CASCADE,
    ecosystem   VARCHAR(64) NOT NULL,
    name        VARCHAR(512) NOT NULL,
    version     VARCHAR(255)
);

-- The lookup the proxy makes on every package: ecosystem, name, then version or NULL.
CREATE UNIQUE INDEX advisory_affected_unique
    ON advisory_affected (advisory_id, ecosystem, name, COALESCE(version, ''));
CREATE INDEX advisory_affected_lookup ON advisory_affected (ecosystem, name);

-- What the mirror holds, so a verdict can name the intel it was reached against.
--
-- One row per distinct bundle.
CREATE TABLE intel_snapshot (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- What the plan calls `intel_snapshot_id`, the audit log records, and
    -- `policy diff --snapshot` will pin: `sha256:` and 64 hex digits. See
    -- `refresh::snapshot`.
    digest      VARCHAR(71) NOT NULL UNIQUE,
    taken_at    TIMESTAMPTZ NOT NULL,
    -- Per-stream digests, so two proxies can agree they hold the same thing.
    streams     JSONB NOT NULL
);
