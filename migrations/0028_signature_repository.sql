-- A signature's result is kept by the repository the bytes were served from: an `.asc`
-- is that repository's, and so is the history that makes a file without one `dropped` or
-- `unsigned`. `spring-boot-gradle-plugin-3.5.6.jar` is the same bytes on Central and the
-- Gradle plugin portal. See docs/engineering_decisions/0115-gradle-plugin-portal.md.
--
-- Each row so far was checked against Central, the repository named `maven`.
ALTER TABLE artifact_signature ADD COLUMN repository VARCHAR(64) NOT NULL DEFAULT 'maven';
ALTER TABLE artifact_signature ALTER COLUMN repository DROP DEFAULT;
ALTER TABLE artifact_signature DROP CONSTRAINT artifact_signature_digest_verifier_key;
ALTER TABLE artifact_signature ADD UNIQUE (digest, repository, verifier);
