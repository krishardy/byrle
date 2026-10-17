-- A detector's result is kept by the repository the version was served from, as
-- ecosystem::Repository::name writes it: Central and the Gradle plugin portal list
-- different versions under one artifact's coordinates. See
-- docs/engineering_decisions/0115-gradle-plugin-portal.md.
--
-- Each row so far is of its ecosystem's own repository, whose name is the ecosystem's.
ALTER TABLE version_detection RENAME COLUMN ecosystem TO repository;
