-- Whether a stream was not read because it is not configured, such as GitHub's with no
-- `WAHAROA_GITHUB_TOKEN`. A stream an ecosystem lists that the snapshot does not hold makes
-- the proxy not ready, unless its latest row says it is not configured. See
-- docs/engineering_decisions/uncovered-ecosystem-fails-closed.md.
ALTER TABLE intel_ingestion ADD COLUMN unconfigured BOOLEAN NOT NULL DEFAULT false;

-- Rows written before this column: a refresh without a token recorded exactly this error
-- for GitHub's streams, so those rows are marked, and an upgraded proxy is ready without
-- waiting for its next refresh.
UPDATE intel_ingestion
SET unconfigured = true
WHERE error = 'WAHAROA_GITHUB_TOKEN is unset, so this stream is not read';
