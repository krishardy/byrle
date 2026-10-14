-- RustSec's kind for an advisory that is no vulnerability: `unmaintained`, `unsound` or
-- `notice`. NULL for a vulnerability or malware. Such an advisory refuses nothing; it is a
-- signal in the risk score. No CHECK: a kind RustSec adds is a change to the code, not to
-- the schema.
ALTER TABLE advisory ADD COLUMN informational VARCHAR(32);
