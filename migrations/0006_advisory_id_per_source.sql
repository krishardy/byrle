-- An advisory id is unique within the stream that published it, not across streams.
--
-- `publisher_id` carried a global UNIQUE. That holds while every stream uses its own id
-- space: OSV publishes `GHSA-` and `MAL-`, CISA keys on `CVE-`, and `datadog` mints
-- `DATADOG-npm-<name>`. GitHub publishes the same `GHSA-` ids OSV imports, so the second
-- stream to load `GHSA-2h44-8472-frjj` failed the load.
--
-- OSV and GitHub are signal streams checked independently, so both rows are wanted: the
-- decision vector reviews what each stream holds. See
-- docs/engineering_decisions/github-advisory-signal-stream.md.
--
-- `PgIntel::replace` already reads its keys back with `WHERE source = $1`, so nothing above
-- this constraint assumed the id was globally unique.
ALTER TABLE advisory DROP CONSTRAINT advisory_publisher_id_key;
ALTER TABLE advisory ADD CONSTRAINT advisory_source_publisher_id_key
    UNIQUE (source, publisher_id);
