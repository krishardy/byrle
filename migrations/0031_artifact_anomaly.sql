-- What in a tarball's shape no packer writes, as `analysis::Anomaly::code` writes each, such
-- as `gzip_members:2` or `duplicate:package.json`. Empty for an archive with none, and for
-- one that could not be read. See
-- docs/engineering_decisions/0122-tarballs-read-as-the-widest-extractor.md.
ALTER TABLE artifact_analysis ADD COLUMN anomalies TEXT[] NOT NULL DEFAULT '{}';
