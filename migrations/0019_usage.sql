-- The versions the proxy served each account, and its failures by hour and case, for the
-- console to look up without reading the log files. See docs/admin-plan.md §4.3.
--
-- Written by the proxy beside each audit line, through a bounded queue, in batches; see
-- src/usage.rs. Times are the audit line's `at`, not when the batch was written. Neither
-- table is deleted from: BYRLE_DECISION_RETENTION_DAYS covers artifact_decision only.

-- One row per account and version served. `account` is NULL for a request without a token,
-- with BYRLE_REQUIRE_TOKEN=0, and those share one row per version.
CREATE TABLE served_version (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account      VARCHAR(64),
    ecosystem    VARCHAR(64) NOT NULL,
    -- The registry name: PyPI's normalised, npm's with its scope.
    name         VARCHAR(512) NOT NULL,
    version      VARCHAR(255) NOT NULL,
    first_served TIMESTAMPTZ NOT NULL,
    last_served  TIMESTAMPTZ NOT NULL,
    UNIQUE NULLS NOT DISTINCT (account, ecosystem, name, version)
);
CREATE INDEX served_version_by_version ON served_version (ecosystem, name, version);

-- How many requests each hour were answered with each case other than `served`, by
-- ecosystem. `answered` is the audit log's value, such as `upstream-unreachable`.
CREATE TABLE failure_count (
    id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hour      TIMESTAMPTZ NOT NULL,
    ecosystem VARCHAR(64) NOT NULL,
    answered  VARCHAR(32) NOT NULL,
    count     BIGINT NOT NULL,
    UNIQUE (hour, ecosystem, answered)
);
