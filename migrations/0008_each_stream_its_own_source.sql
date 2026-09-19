-- Each stream is its own source from here: `osv/npm`, `datadog/npm` and `github/npm`, not
-- `osv`, `datadog` and `github`. A load replaces its source's rows whole, so a second OSV
-- stream under the source `osv` would delete the first's rows every time it loaded.
--
-- The rows under the old names are deleted rather than renamed. A source's digest is over
-- its encoded rows, name included, so renamed rows would carry a digest no load
-- reproduces, and a kept snapshot's rows file is named by that digest.
--
-- Every snapshot row goes too. The newest would still list `osv/npm` among its streams
-- over rows that no longer exist, and a lookup would read that as nothing known about any
-- package. With no snapshot the proxy answers 503 until `waharoa refresh` loads the
-- streams under their new names. Kept snapshot files on disk are not touched.
DELETE FROM advisory WHERE source IN ('osv', 'datadog', 'github');
DELETE FROM intel_source WHERE source IN ('osv', 'datadog', 'github');
DELETE FROM intel_snapshot;
