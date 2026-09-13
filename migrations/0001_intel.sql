-- What the advisory streams know, normalised.
--
-- Written for the checks that read it. `known_malware` asks one question of a package,
-- `max_cvss` asks for scores, `kev` asks whether an advisory is exploited. The shape below
-- answers those and nothing else yet.

-- One advisory, whoever published it.
--
-- `id` is the publisher's own: GHSA-xxxx, MAL-xxxx, CVE-xxxx. Different streams use
-- different id spaces for the same vulnerability, which is what `advisory_alias` is for.
CREATE TABLE advisory (
    id          TEXT PRIMARY KEY,
    -- Which stream supplied this record. Kept for `explain` and for attribution: GHSA
    -- text is CC-BY-4.0 and has to be credited where it is shown.
    source      TEXT NOT NULL,
    summary     TEXT,
    -- NULL where no stream has scored it. Distinct from 0.0, which is a real CVSS score.
    cvss        DOUBLE PRECISION,
    -- Which stream supplied the score. An `enrich` stream may raise it, so the two can
    -- differ from `source`.
    cvss_source TEXT,
    -- Known to be exploited. Only an `enrich` stream sets this; see src/intel.rs.
    exploited   BOOLEAN NOT NULL DEFAULT FALSE,
    -- A malware report rather than a vulnerability. Feeds the one check with no exception,
    -- so it is a column rather than something inferred from the id prefix.
    malware     BOOLEAN NOT NULL DEFAULT FALSE,
    -- RFC 3339 in UTC, as text. Text rather than TIMESTAMPTZ so the codebase keeps one
    -- date library: jiff, which sqlx has no mapping for. RFC 3339 in UTC sorts
    -- lexicographically, so "modified since" still works for incremental refresh.
    modified    TEXT
);

-- The other ids this advisory is known by.
--
-- CISA keys on CVE ids and OSV publishes GHSA and MAL ids, so a KEV entry reaches an OSV
-- finding only through this table. Until it is populated, an `enrich` stream matches
-- nothing; see the deduplication item in TODO.md.
CREATE TABLE advisory_alias (
    advisory_id TEXT NOT NULL REFERENCES advisory (id) ON DELETE CASCADE,
    alias       TEXT NOT NULL,
    PRIMARY KEY (advisory_id, alias)
);

CREATE INDEX advisory_alias_by_alias ON advisory_alias (alias);

-- Which package versions an advisory is against.
--
-- `version` NULL means every version of the package, which is how a malware report usually
-- reads: the package itself is the problem. A named version affects only that one.
-- Version *ranges* are not expressed here. Evaluating them needs a semver implementation
-- per ecosystem and is its own item.
CREATE TABLE advisory_affected (
    advisory_id TEXT NOT NULL REFERENCES advisory (id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT
);

-- The lookup the proxy makes on every package: ecosystem, name, then version or NULL.
CREATE UNIQUE INDEX advisory_affected_unique
    ON advisory_affected (advisory_id, ecosystem, name, COALESCE(version, ''));
CREATE INDEX advisory_affected_lookup ON advisory_affected (ecosystem, name);

-- What the mirror holds, so a verdict can name the intel it was reached against.
--
-- One row per refresh. `intel_snapshot_id` in the plan is this table's `id`, and it is
-- what `policy diff --snapshot` will pin.
CREATE TABLE intel_snapshot (
    id          TEXT PRIMARY KEY,
    -- RFC 3339 UTC, as above.
    taken_at    TEXT NOT NULL,
    -- Per-stream digests, so two proxies can agree they hold the same thing.
    streams     JSONB NOT NULL
);
