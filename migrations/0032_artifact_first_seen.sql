-- When the proxy first decided a file the registry listed but published no time for: the
-- date `cooldown_days` counts from in its place. A file, not a version, so a file added to
-- an old release starts its own wait. Never updated. See
-- docs/engineering_decisions/0129-undated-files-first-seen.md.
CREATE TABLE artifact_first_seen (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The version's purl, such as `pkg:cargo/serde@1.0.0`.
    purl       VARCHAR(512) NOT NULL,
    -- The file's name as the path spells it.
    filename   VARCHAR(512) NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (purl, filename)
);
