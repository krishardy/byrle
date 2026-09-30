-- What a detector found about one package version, such as GuardDog's rules that fired. A
-- detector reads the version by name from its registry, not the artifact the proxy served,
-- so the key is the version. Report only: see docs/engineering_decisions/detectors.md.
--
-- A run that could not be made writes no row, so a missing row is "not run yet". A row is
-- read back only for the detector version that wrote it.
CREATE TABLE version_detection (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The detector's name, as WAHAROA_DETECTORS gives it.
    detector         VARCHAR(64) NOT NULL,
    -- What `<program> --version` printed.
    detector_version VARCHAR(128) NOT NULL,
    ecosystem        VARCHAR(64) NOT NULL,
    -- The registry name: PyPI's normalised, npm's with its scope.
    name             VARCHAR(512) NOT NULL,
    version          VARCHAR(255) NOT NULL,
    -- analysis::detector::Detection as JSON. TEXT: its details have no bound in number.
    result           TEXT NOT NULL,
    detected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (detector, ecosystem, name, version)
);
