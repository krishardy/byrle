-- The largest tree of a Go checksum database the proxy has proved, so a tree it is shown
-- after a restart must extend it as one shown before did. Replaced only by a larger tree.
-- See docs/engineering_decisions/0134-checksum-tree-kept.md.
CREATE TABLE checksum_tree (
    id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The database's key name, such as `sum.golang.org`.
    database VARCHAR(255) NOT NULL UNIQUE,
    -- Its record count, and its root hash in lower-case hex.
    size     BIGINT NOT NULL,
    root     VARCHAR(64) NOT NULL,
    kept     TIMESTAMPTZ NOT NULL DEFAULT now()
);
