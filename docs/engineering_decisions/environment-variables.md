# Environment variables: one module

- **Status:** Implemented 2026-09-13. `src/env.rs`.
- **Related:** [cli-parser-clap](cli-parser-clap.md)

## Decision

Every environment variable byrle's Rust code reads has its name, default, help text and
parsing in `src/env.rs`, and nowhere else. Other modules use its `Var` constants, as values
and inside messages, and read values through `env::process()`.

| Question | Decided |
|---|---|
| Which mentions count | Every one: reads, log and panic messages, `doctor` advice, `--help`, doc comments |
| A value that does not parse | Refused: `byrle: BYRLE_MAX_RECORDS: \`5O000\` is not a whole number`, exit 2 |
| A value that parses and names something missing or unusable, such as a policy file or CA bundle | the proxy does not start. A running proxy would read as that setting being in force |
| Which variables | The binary's 20 (`RUST_LOG` and the debug-only `BYRLE_DEFER_TEST` included), the four read by tests, and nine other programs read: `HOME`, `BUN_INSTALL_CACHE_DIR`, `XDG_CONFIG_HOME`, and uv's `UV_DEFAULT_INDEX`, `UV_INDEX_URL`, `UV_EXTRA_INDEX_URL`, `UV_INDEX`, `UV_NO_CONFIG` and `UV_CONFIG_FILE`, which `doctor` reads as uv would |
| Where defaults live | `src/env.rs`. `store`, `verified`, `proxy`, `npm`, `refusal` and `policy::packages` import them |

Shell scripts keep their own copies of the names they set. They cannot import Rust.

## Held by

`a_variable_name_appears_only_in_this_module` reads every `.rs` file under `src/`, `tests/`
and `examples/`. It fails on any variable name in `env::ALL`, or any `BYRLE_` prefix, outside
`src/env.rs`, and on a `BYRLE_` name inside `src/env.rs` that is not in `ALL`.

`--help` is rendered from the same constants the code reads, so
`tests/fixtures/cli/help.txt` is the check that a documented default is the real one. Before,
the help text wrote `(50,000)` and `(32 MiB)` by hand beside the constants.

## What changed in behaviour

| Before | After |
|---|---|
| `BYRLE_MAX_METADATA_BYTES`, `_MAX_RECORDS`, `_MAX_VERIFIED`, `_MAX_CONCURRENT_METADATA` and `_EXPIRY_CEILING_DAYS` fell back to the default on a value that did not parse | refused, exit 2 |
| `BYRLE_CA_BUNDLE_EXCLUSIVE` was on only for `1`; `BYRLE_REWRITE_ARTIFACTS` and `BYRLE_REFUSE_UNSERVABLE` were off only for `0`. Anything else was silently the default | each accepts `0` or `1`, and refuses anything else |
| `BYRLE_LISTEN=` and `BYRLE_UPSTREAM=` were used as the empty string | an empty value is unset, for every variable |
| `RUST_LOG` that did not parse fell back to `byrle=info` | refused, exit 2 |
| `BYRLE_UPSTREAM` was used as text: `policy diff` and `explain` sent every request to `nope`, and the proxy panicked on it, exit 101 | refused unless an http or https URL with a host: `BYRLE_UPSTREAM: \`nope\` is not usable: not a URL`, exit 2, and 4 for `policy diff`. A path is kept |
| `RUST_LOG` was read by tracing and not listed in `--help` | listed, default `byrle=info` |
| `BYRLE_REFUSAL_STATUS` and `BYRLE_DEFER_TEST` panicked on a bad value | exit 2 with the same reason |

`BYRLE_UPSTREAM_NPM` and `BYRLE_UPSTREAM_PYPI` are checked with `npm::normalise_origin`, the check `BYRLE_ARTIFACT_ORIGINS`
already had, and returned as given. Live, with `nope`, `ftp://x` and `http://`, the proxy and
`explain` exit 2 and `policy diff` exits 4. With `https://registry.npmjs.org/some/path/` the
proxy starts with upstream `https://registry.npmjs.org/some/path`. Each mutation below was caught:

| Mutation | Caught by |
|---|---|
| Any upstream accepted | `an_upstream_is_an_http_or_https_url_with_a_host` |
| The origin returned in place of the value | the same |
| The reason dropped from the message | the same |
| An unset upstream defaults to an unusable one | `unset_is_the_default` |

`BYRLE_CA_BUNDLE_EXCLUSIVE` is read only when `BYRLE_CA_BUNDLE` is set, as before, so a bad
value is refused only then.

The log line `deferred by the defer test`, which `scripts/make/retry-matrix.sh` counts,
names the variable in its `variable` field, from `env::DEFER_TEST`. It read
`deferred (BYRLE_DEFER_TEST)` until 2026-09-28, when log values moved into fields.

## Credentials

A variable holding a secret is set from `~/.config/byrle/env`, mode 600, outside the
repository. `make trufflehog` scans the working tree with only `/target/` excluded and does
not read `.gitignore`, so a live token in a file inside the repository fails that gate on
every run. Measured 2026-09-16: a `ghp_`-shaped value in an untracked file at the repository
root was reported as `Detector Type: Github, Token_type: Personal Access Token (classic)` and
the working-tree scan exited 183.

Excluding such a file in `.trufflehog-exclude` was rejected: that file is for build output,
and excluding the file most likely to hold a credential inverts what the scanner is for.
`.env` and `.env.*` are in `.gitignore` anyway, for a token pasted into the repository out of
habit.

Nothing loads the file. byrle reads real environment variables and there is no dotenv
crate or configuration file, decided by the user on 2026-10-13. Whatever starts byrle
loads the file:

| Runner | How |
|---|---|
| a shell | `set -a; . ~/.config/byrle/env; set +a` |
| systemd | `EnvironmentFile=/etc/byrle/env` in the unit's `[Service]` section |
| Docker Compose | `env_file: byrle.env` on the service |

The file is `BYRLE_NAME=value` lines, which all three read.

`BYRLE_GITHUB_TOKEN` is the GitHub Advisory stream's token. It is not in `src/env.rs` yet:
`--help` renders from those constants and `tests/fixtures/cli/help.txt` pins the output, so
the `Var` is added when the stream reads it.

## Rejected

| Alternative | Why not |
|---|---|
| Only the reads go through the module | Names in advice and log text would stay as literals, and a rename would leave them stale |
| Keep silent fallback | An operator who set `BYRLE_MAX_RECORDS=5O000` runs with 50,000 and nothing says so |
| Defaults stay in their modules, referenced from here | Each value defined once, but the item asked for them in the central module |
| A config struct parsed once at startup | Every command would fail on a bad proxy-only variable. `byrle refresh` reads one variable and should not refuse over `BYRLE_MAX_RECORDS` |
| Thousands separators in `--help` (`50,000`), by hand or with `num-format`, `thousands` or `icu_decimal` | Rust's `format!` has no grouping. `num-format` and `thousands` have had no release since 2022 and 2019; `icu_decimal` brings ICU4X locale data for one help line. Defaults print as `50000` |
| `npm::DEFAULT_REGISTRY` moves too | It is npm's registry, which the origin rules in `npm` name whether or not it is the upstream. `env::UPSTREAM_NPM`'s default is it, and `UPSTREAM_PYPI`'s is `pypi::INDEX`. Each `ecosystem::TABLE` row names its variable, and `Upstreams::defaults` reads the default from it |

## One upstream per ecosystem

`BYRLE_UPSTREAM` was one variable holding one registry, which is what a proxy serving npm
alone needs. Serving PyPI as well means two, because the two are different services: npm's
registry answers `/lodash`, PyPI's index answers `/simple/requests/`, and pointing one
variable at both is not expressible.

| Variable | Default | Read by |
|---|---|---|
| `BYRLE_UPSTREAM_NPM` | `https://registry.npmjs.org` | the proxy, `policy diff`, `explain` |
| `BYRLE_UPSTREAM_PYPI` | `https://pypi.org/simple` | the proxy |

`BYRLE_UPSTREAM` is gone rather than kept as an alias. Nothing has been released, and a
variable that silently means one of two ecosystems is the thing the split exists to remove.
An operator who still sets it gets the npm default and no warning, which is the one cost.

`policy diff` and `explain` read the npm variable by name, not a set: both take npm
lockfiles and npm package references and ask npm about them.

PyPI's files come from `files.pythonhosted.org`, which is not `BYRLE_UPSTREAM_PYPI` and is
not a third variable. The simple index gives each file's URL in full, so the artifact host
is read from the document the way `npm::origin_of_url` already reads `dist.tarball`.

The rows above that name `BYRLE_UPSTREAM` record measurements taken before the split.
