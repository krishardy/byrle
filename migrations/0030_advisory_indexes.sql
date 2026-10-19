-- The `id` keys of `advisory_affected` and `advisory_range` and the index on
-- `advisory_alias.alias` are dropped: no query or foreign key reads them. Each row is named
-- by its unique index, led by `advisory_id`, which `ON DELETE CASCADE` from `advisory` reads
-- by, and which a refresh's copy fills in order. See docs/postgres-review.md section 4.
ALTER TABLE advisory_affected DROP COLUMN id;
ALTER TABLE advisory_range DROP COLUMN id;
DROP INDEX advisory_alias_by_alias;
