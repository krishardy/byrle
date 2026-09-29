-- Whether a stream was not read because it is not configured, such as GitHub's with no
-- `WAHAROA_GITHUB_TOKEN`. A stream an ecosystem lists that the snapshot does not hold makes
-- the proxy not ready, unless its latest row says it is not configured. Rows written before
-- this column read as configured. See docs/engineering_decisions/readiness-endpoint.md.
ALTER TABLE intel_ingestion ADD COLUMN unconfigured BOOLEAN NOT NULL DEFAULT false;
