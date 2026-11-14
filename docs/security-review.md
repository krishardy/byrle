# Security review

A review of each step in [logic-flow](logic-flow.md), for TODO.md ad-hoc #50. For each
step it asks:

- Is the step vulnerable?
- What does abnormal data do there?
- Can a malicious package be coaxed through?
- Can malicious input make a score ignored or overridden?

Reviewed 2026-10-26 at `5297ab2`. logic-flow.md was drawn at `a199ded`. Since then, the
only change in scope is `PgIntel::package` and `write_source` (`c31aaa6`).

Each finding's cited lines were checked at HEAD. The Evidence column says how far it was
taken:

- **run**: reproduced against a byrle built from HEAD with a loopback upstream, or with
  the client or toolchain named.
- **test**: an existing test shows the behaviour.
- **code**: read from the code and a dependency's source, not run.

Scratch reproductions are not in the repository. A bypass [threat-model](threat-model.md)
already lists is named, and is not a finding.

## Resolved

| # | Commit | What changed | Tested |
|---|---|---|---|
| 1 | `1c150b4` | `walk` decodes every gzip member and reads past a single zero block, as npm and pip do. A tarball's odd shapes are `Anomaly` values, reported as `archive_suspicious`, weight 1. A tarball decompressing past 4 GiB is `TooLarge` | `a_tar_continued_in_a_second_gzip_member_is_read_whole`, `entries_past_a_single_zero_block_are_read`; the first-member decoder and a dropped `set_ignore_zeros` each fail them |
| 2 | `2fc88d1` | `npm_install_scripts` adds `install: node-gyp rebuild` for a root `binding.gyp` when no `package.json` copy has an `install` or `preinstall` npm reads as true and `gypfile` is not `false`, as arborist `#addToBuildSet` does | `a_binding_gyp_is_npm_s_install_script`; 7 hand mutations, each caught: the rule dropped, `gypfile` or `preinstall` ignored, a directory or a nested file counted, any number read as true, only the last copy deciding |
| 3 | `40d5f42`, `12f504b` | `record::Artifact::published_at` holds each PyPI file's `upload-time`; `narrowed_to` dates a pinned fetch by it. A version is dated by its oldest file, or undated when any file is. In a version the policy serves, a file refused under its own `upload-time` is removed from the index alone | `a_file_added_to_an_old_pypi_release_is_dated_by_its_own_upload`, `a_pypi_file_newer_than_its_release_is_refused_alone`, `a_file_refused_alone_is_removed_alone`, `a_version_is_dated_by_its_oldest_file_and_a_file_by_its_own`, `narrowing_takes_the_files_own_publish_time`; hand mutations, each caught: narrowing keeping the version's time, files not dated, files never decided alone, refused files kept in the index, the index left unfiltered when only files are refused, the refused file's check not named, the version dated by its newest file |
| 4 | `c2b49db`, `e922a4a` | Under a cooldown, a Go version is dated by the first tree of sum.golang.org that holds its record (`Heads` in `go/heads.rs`). Rows come from each proved tree head and from index.golang.org entries, read at the cooldown's start and at midpoints until the rows around a record are an hour apart. Below the seed, the earlier of the `.info` `Time` and the seed. `@latest` is dated the same way, and the pinned fetch through `Fetch::version`. Decision 0125. `byrle explain` and `policy diff` still read `.info` `Time` | `a_go_version_with_a_backdated_commit_is_refused_by_its_record` (list, `@latest` 404, zip 403), `a_version_is_dated_by_its_record_not_its_commit`, `a_record_is_dated_by_the_rows_around_it`; 20 hand mutations, each caught, among them the lower bound in place of the upper, `Timestamp − 1 h` in place of `+ 1 h`, `max` in place of `min` below the seed, no seed, `@latest`, `version()` or the list keeping the `.info` `Time` |
| 5 | `674edd8` | `crate_build_scripts` reads `[lib] crate-type` and `crate_type` as well as the two flags. cargo 1.99.1 `cargo metadata` gave kind `proc-macro` for each of the four, and for `proc-macro = false` beside `crate-type = ["proc-macro"]` | `every_way_cargo_reads_a_proc_macro_is_one`; 4 hand mutations, each caught: `crate-type` ignored, `crate_type` ignored, any type string counted, the flags ignored |
| 6 | `1c150b4` | every entry that extracts to `package.json`, after `strip: 1` and with `.` and empty components dropped, is read, and its scripts counted. The same for `Cargo.toml` | `every_package_json_npm_extracts_to_one_path_is_read`, `every_cargo_toml_is_read`; reading only the first copy fails them |
| 7 | `90252e5` | Decision 0129: the file host's `Last-Modified` is asked when the full document's times lack the version; under a cooldown, a listed file nothing dates is dated by its first sighting in `artifact_first_seen`, by purl and filename; with none, `cooldown_unanswered` weighs `risk_threshold` and answers `undated` | `an_undated_file_is_dated_by_its_first_sighting`, `an_undated_file_with_no_store_is_cooldown_unanswered`, `an_undated_file_whose_store_errors_is_not_served`, `a_time_map_without_the_version_asks_the_file_host`, `a_cooldown_is_decided_on_the_file_hosts_last_modified` (no `Last-Modified` and a 404 now refused), `a_file_s_first_sighting_is_kept_once` (Postgres); 8 hand mutations, each caught: the signal dropped, its default weight 0, the sighting overwritten, written before the listing check, not read, the refusal not answered, no cooldown check, the host asked only with no times |
| 8 | `aa5b975` | `handle` answers 400, in every mode, to a path with a `.` or `..` segment before the mount or `route::classify` reads it: `%2e` in any case, split on `/` or `\`, the query not read (`route::rewritten_by_url_parser`). A `#` never reaches `handle`: hyper drops it and the rest of the path | `a_path_the_upstream_url_would_rewrite_is_refused` (the three requests above, a `\` variant, a `..` query forwarded), `a_segment_the_url_parser_removes_is_found`, `a_path_the_url_parser_keeps_is_not`; 6 hand mutations, each caught: no `\` split, `%2e` case-sensitive, the query read, only `..`, only `.`, the check dropped from `handle` |
| 9 | `eb64955` | `method_not_allowed` answers 405, `Allow: GET, HEAD`, to an `Artifact` or `Manifest` asked with another method; forwarded and logged at WARN in observe mode. Metadata and `Other` keep every method, for `npm audit`'s POST | `a_file_asked_with_another_method_is_405` (POST, PUT, OPTIONS, PATCH, DELETE to an npm tarball, a Go zip and a `.mod`; the audit POST and a HEAD forwarded; observe forwarded); 6 hand mutations, each caught: the check dropped, `Manifest` not covered, HEAD refused, every target refused, observe refused, no `Allow` |
| 10 | `f0c4e2d` | `forward_artifact` verifies every 2xx with a digest through `VerifyingStream`, and `respond` checks a manifest's claim on every 2xx, each with the same `digest_mismatch` weighing as a 200 | `a_tarball_answered_with_another_2xx_is_verified` (203 and 206, tampered never complete, honest served), `a_go_mod_answered_with_another_2xx_is_checked` (203 honest served, other bytes 502); 3 hand mutations, each caught: manifest on 200 only, artifact on 200 only, 206 unverified |
| 11 | `6d4faae` | Decision 0130: `byrle refresh` reads each source's stored rows (`PgIntel::stored_rows`); `Read::refuse_shrunk` does not load a stream that parsed to under half of them, and its last load stays. `--force <stream>`, repeatable, loads it | `a_stream_that_parsed_to_under_half_its_stored_rows_is_not_loaded` (2 of 4 loaded, 2 of 5 and 0 of 1 not, forced and unstored loaded); `make smoke-console` step 5: an empty `npm.zip` is refused and is-number stays 403; 8 hand mutations caught by the unit tests, and the guard unwired from `run.rs` caught by the smoke |
| 12 | `3ac59e2` | Decision 0131: `Command::detect` errors when the program did not exit 0, so nothing is stored and it runs again. `of_detections` adds `<detector>.error` for a run whose `errors` lists a rule; `guarddog.error` weighs 1 unless weighed | `what_a_command_cannot_answer_is_an_error` (exit 3 with JSON is an error), `a_detector_rule_is_a_signal_with_its_own_weight`, `a_detectors_rules_are_reported_on_a_later_request` (`guarddog: error` on the audit line); 6 hand mutations, each caught |
| 13 | `2bba5f4` | Decision 0132: `settings::compared` lists each top-level setting and `signal_weights` key two policies give differently, a weight as its share of `risk_threshold`. `policy diff` prints them first and sets bit 1 or 2 for them; `policy check` lists each looser than its default | `a_weight_lowered_is_looser_and_raised_is_stricter` (`known_malware: 0` is LOOSER), `a_weight_is_compared_as_its_share_of_the_threshold`, `each_top_level_setting_is_compared_in_its_own_direction`, `a_setting_that_moved_sets_its_bit_whatever_the_packages_did`, `a_setting_looser_than_its_default_is_listed`; 12 hand mutations, each caught; `make smoke-console` 9 of 9 |
| 14 | `dc9677c` | `guarded` admits an API caller from its headers, then reads its body (`command`) only when its roles permit the route; a page's form (`form`, 8 KiB) is read first for its CSRF token | `an_api_body_is_read_only_once_the_caller_is_admitted` (a body that never ends is 401 with no credential and 403 to `bob`, at once; `alice`'s 3 bytes reach the handler); 2 hand mutations, each caught: body read before the caller, admitted body dropped |
| 15 | `3e2193d` | `Limiter::admits` counts a login as a failure under the lock that checks the limit, before the first await; `forgive` takes it back on success or an unanswered store | `logins_sent_at_once_are_limited_and_a_success_is_not_counted` (8 parallel wrong logins: 5 Refused, 3 Limited); 5 hand mutations, each caught, the old check-then-count order among them |
| 16 | `82e349d` | `BYRLE_MAX_DIFF_VERSIONS` (10,000) caps the versions a remote `policy diff` sends, 400 past it; `Site.diffing` runs one diff at a time, 429 for another. The metadata semaphore is not taken | `a_diff_past_its_cap_or_beside_a_running_one_is_refused` (2 versions past a cap of 1 is 400; a diff sent while one is held is 429; a diff waiting on a registry that never answers holds the lock); 5 hand mutations, each caught |
| 17 | `4a2efcc` | `source::CEILING`: 512 MiB stated and 200,000 members; `tree()` decompresses at most 512 MiB plus 4 KiB per member, `wheel_tree()` checks the entry count first | `an_archive_of_more_members_than_its_ceiling_is_refused` (3 members past a ceiling of 2, tar and zip; a 4 KiB name past 1 member's headers); the zip reader refuses an entry past its stated size; 6 hand mutations, each caught |
| 18 | `0c1ea8b` | `util::blocking::run` sets a `Stop` when its future is dropped; the install-script reader, `read_tree` and the signature check read through `Stop::reading`, which fails each read after with `TimedOut`. Decompressed bytes were capped already: 4 GiB per tarball, and finding 17's source ceiling | `work_stops_reading_once_its_future_is_dropped`, `a_reader_past_its_deadline_stops_reading`, `a_tree_past_its_deadline_stops_reading`, `a_signature_check_past_its_deadline_stops_reading`; 5 hand mutations, each caught |
| 19 | `f9e618f` | `unread_document` answers 502 in enforce mode to a document over `BYRLE_MAX_METADATA_BYTES` or undecodable, and forwards it in observe mode; the threat model's Bypasses lists the observe case. An adapter's `read` returning `None` is unchanged, as Go and Maven return it for documents they do not read on purpose; see 19b | `an_oversized_packument_is_refused_or_forwarded_intact_when_observing`, `a_document_the_proxy_cannot_decode_is_refused_unless_observing`; 5 hand mutations, each caught |
| 19b | `8dc031a` | Found while fixing 19: an npm packument that did not normalize, a PyPI index that did not parse, and either one that could not be filtered or repointed was forwarded, with refused versions or origin URLs in it. A packument whose tarball URLs escape their slashes normalized and was forwarded on the origin. `Registry::read` and `Document::rewrite` return `Err` for each, and `unchecked_document` answers 502, or forwards in observe mode. cargo, Go and Maven never return `Err` | `a_document_the_proxy_cannot_check_is_refused_unless_observing` (undecodable, does not normalize, escaped slashes); 9 hand mutations, one per `Err` site, each caught |
| 20 | `9f1c231` | `rewrite_packument` filters whenever a version was skipped, and `filter_listed` removes any listed version in the removal set, with or without a record. joi 0.1.0 to 0.2.0, whose `scripts` holds objects, are the real case: 5 versions in the full document | `a_version_that_does_not_normalise_is_removed_with_its_tags`; npm corpus, 157 packages, served without an `Err`; 4 hand mutations, each caught |
| 21 | `9e15d7f` | `http::capped_body` and `body_to_limit` read in chunks and stop one byte past the limit. Metadata reads use `BYRLE_MAX_METADATA_BYTES` as sent, before decoding; Go `.info`, Maven checksums and `.asc`, and sumdb answers use `http::MAX_SIDECAR_BYTES`, 64 KiB; key server copies and crates.io pages use 64 MiB. An `.asc` over 64 KiB is kept as its first 64 KiB and 1 byte and fails to verify, so the LRU keeps at most 512 MiB. The parsed signature is not kept instead: one signature packet's subpackets are unbounded, so only the byte cap bounds it. The sidecar's document is cut one byte past the limit, so it is refused as before. The OIDC reader uses the same function. Time is not bounded: a body sent slowly under the cap is read for as long as each read comes within 30 s | `a_body_is_read_no_further_than_its_limit`, `a_sidecar_of_a_document_over_the_limit_is_refused`, the `.asc` case in `a_signature_is_read_once_and_a_failure_says_which`; 6 hand mutations, each caught |
| 22 | `e8af19d` | A key server's copy over `keys::MAX_KEY_BYTES`, 1 MiB, is not used, and the other server's is. Measured on 2026-11-05: the 9 issuers of 10 popular Maven artifacts are 456 to 8,334 bytes; 38DBBDC86092693E, a key with many certifications, is 135,482 bytes on keyserver.ubuntu.com; the 2019 flooded keys are no longer served. The certification half was not a defect: `pgp` 0.21.0 rejects a signature whose issuer is another key before hashing (`types.rs:590`, `:803`, `:478`), so another key's certification costs an issuer comparison | `a_copy_over_the_limit_is_not_used`, `a_signature_naming_another_key_is_not_read`; 2 hand mutations, each caught |
| 23 | `cecc5bf` | `Spooled` keeps the device and inode `write` created, and `Spooled::reader` errors with `<path> is not the file written` when the file it opens has others. Group-writable stays allowed, as [artifact-spool](engineering_decisions/0064-artifact-spool.md) decides for umask `002` and Kubernetes `fsGroup`. The file is `0600`, so a group member cannot write to the inode | `a_file_renamed_over_a_spool_file_is_not_read`; 2 hand mutations, each caught |
| 24 | `dfc17f2` | `startup::upstream_client` takes a redirect policy, and VirusTotal gets a client of its own with `virustotal::redirects()`, none, and the same CA bundle: a 3xx is `answered 307`. `Client::upload` refuses an upload URL whose origin is not the base's. `BYRLE_VIRUSTOTAL_URL` must pass `http::trusted` | `virustotal_s_client_follows_no_redirect`, the origin case in `an_upload_sends_the_file_as_multipart_and_reads_the_analysis_id`, the URL case in the env test; 4 hand mutations, each caught |
| 25, 39 | `b1172f9` | [a-client-for-each-service](engineering_decisions/0133-a-client-for-each-service.md): each upstream service has a `service::Service` that sends only the headers it declares, and panics on another. `X-Byrle-Token` is a `Connection`'s credential, added to each request rather than as a default header. Every service follows at most 10 redirects and none from https to another scheme; one with a credential (`authorization`, `proxy-authorization`, `cookie`, `x-apikey`, `x-byrle-token`) only on its first URL's origin. `scripts/make/clients.py` refuses a raw `reqwest::Client` outside `service.rs` and `tls.rs`. 39's `dated_by_host` HEAD before the unservable check is not changed | `a_credential_follows_a_redirect_only_on_its_origin`, `a_request_is_sent_with_what_it_declares`, `a_redirect_is_followed_within_the_limit_without_a_downgrade`; 8 hand mutations, each caught, and a raw client placed in `remote.rs` refused by the lint |
| 39 | `01b3c76` | `Deciding::dated` is given whether `fetch_plan` found the file on an origin not served, and sends no HEAD for its `Last-Modified` then; it is dated by its first sighting. An origin `BYRLE_ALLOW_DIRECT_ORIGINS` lists is still asked. The watcher's call passes the same, which `watch_version` makes always false, as it returns before for a file not on a reachable origin | `a_file_on_an_origin_not_served_is_not_asked_for_its_date`; 1 hand mutation caught; the watcher's is equivalent |
| 32 | `a7afe1a`, `837a1ef` | `paths::version_in` splits an sdist at the first `-` before which the name normalises to the project, as pip's `_find_name_version_sep` does; another project's sdist is skipped. `wire::parse` and `html::parse` split by the project the request path names (`inspect::asked`). Decision 0135: a file on a hash path whose name fits several projects is keyed by the index that lists it, held ones first, then up to `BYRLE_MAX_INDEXES_PER_FILE` asked in turn, stopping on any failure but a 404. Warehouse never reuses a filename. In the top 1,000 projects on 2026-11-08, 126 of 91,068 sdists split differently, 38 of them a version pip installs, the newest uploaded 2021-09-25 | `a_pypi_sdist_whose_version_holds_a_dash_is_matched_by_its_advisory`, `a_pypi_file_is_placed_by_the_index_that_lists_it`, `placing_a_pypi_file_asks_at_most_the_cap_and_stops_on_a_failure`; 21 hand mutations, each caught; `make mutants` 13 caught and 14 unviable, then 18 caught and 29 unviable |
| 33 | `2fd39d5` | Decision 0136: `Registry::selector_name`, cargo's lowercasing and reading `-` as `_` as crates.io's `canon_crate_name` does, is what `NamePattern::canonical` and `Selector::matches` compare. Intel rows keep `canonical_name`, the spelling a key looks up. A policy entry spelled with the other separator now applies, a loosening one included, and `policy diff` does not show it | `a_cargo_selector_reads_dash_and_underscore_as_one`, `a_row_is_stored_under_the_name_its_package_key_looks_up`; 6 hand mutations, each caught; `make mutants` 4 caught, 5 unviable |
| 34 | `11dad09` | `analysis::zip_annotation_processors` reads a Maven file not named `.jar`, `.pom` or `.module` as a jar when `zip::ZipArchive` opens it, which finds the central directory as javac's `ZipFile` does, so bytes before the zip do not hide it; leading magic bytes were not used for that reason. A file that is not a zip names no processor; a `.jar` that is not one is still `Unreadable`. Every such artifact is now spooled and read | `a_zip_of_any_name_is_read_for_processors`, `one_jar_per_version_and_no_attestations`; 7 hand mutations, each caught; `make mutants` 3 caught, 1 unviable |
| 35 | `f58ba05`, `ecc6b9e` | `Exchange::unread_media_type` answers through `unchecked_document` a metadata GET the proxy would read answered 2xx in a media type the adapter does not read: 502 in enforce mode, forwarded in observe mode, logged `UNINSPECTED` with the `Content-Type` and counted. The 502 was the operator's choice on 2026-11-08, to be watched on a live system for mirrors serving another type | `a_document_in_a_media_type_not_read_is_502`; 9 hand mutations, each caught or showing a redundant guard, removed; `make mutants` 2 caught, then 3 caught and 1 unviable |
| 36 | `fe00c15` | `etag_view` mixes the address, the policy digest and the intel snapshot the document was filtered with into the tag. `current_view` reads the package's snapshot before the upstream is asked, only for a client tag the proxy issued on a rewritten document; another view, or intel that cannot be read, drops the conditional. Decision 0018: later analysis and provenance refusals are not in the view; the pinned fetch is decided | `a_tag_issued_under_another_policy_or_snapshot_is_not_sent_upstream`, `only_a_marked_tag_on_a_rewritten_document_costs_a_lookup`, `a_header_carries_a_mark_when_one_tag_was_issued_here`; 7 hand mutations, each caught; `make mutants` 9 caught, 13 unviable |
| 37 | `ae27369`, `3b0b7bd` | `Attestation.recent`, set in `proxy::attested` from `attestation::recent`: published less than `provenance_window_days` before now, for this version and each prior (`Prior.published`). `attestation_document` stores nothing for a recent version's 404, logged `attestations: not served yet for a recent version, nothing stored`; the version answers 503 under any `provenance` setting until npm serves the document or the window passes. Under `allow` it was served before. Rows stored before are kept | `a_version_is_recent_until_the_window_has_passed`, `a_recent_version_s_missing_attestations_are_asked_for_again` (recent, mixed, old), `attestations_are_verified_and_only_a_real_answer_is_stored`; 1 hand mutation (priors given this version's time), caught; `make mutants` 13 caught, 12 unviable, 1 timeout (`<` to `<=` in `previous`, a version its own prior) |
| 38 | `62e3cf0` | `Spool::write` takes no length: the ceiling is counted on the bytes that arrive, for the scripts analysis, the claim check and the source comparison. A body shorter than its `Content-Length` stores nothing. An artifact over the ceiling costs the ceiling's bytes, once. Bytes past the ceiling are still not hashed, so an `Unreadable` row is not checked against its digest | `a_length_over_the_ceiling_alone_stores_nothing`, which stored `Unreadable` on the old code; `make mutants` 2 caught, 11 unviable, 1 timeout (`spool_hashed` to `None`, a claim never answered) |
| 40 | `e3d3a6e` | `Clients::from_env`, used by `byrle explain <purl>`, `byrle policy diff` and `byrle policy check --fetch`, builds its connection with `startup::connection`, so it reads `BYRLE_CA_BUNDLE` and `BYRLE_CA_BUNDLE_EXCLUSIVE` as the proxy does. It already had the read timeout through `Connection::default()` | `a_client_that_cannot_be_built_or_reach_its_registry_is_an_error` (a bundle that does not load); 1 hand mutation (`Connection::default()` back), caught; `make mutants` 1 unviable |
| 26 | `922d9d2` | `routes::guarded` answers 403, `a request from another site`, to any request but GET or HEAD whose `Origin` is not the console's, before the guard, so a session, a token or Basic is refused alike. The four checks in the login and logout handlers are removed as duplicates | `every_route_that_needs_a_permission_refuses_an_account_without_it` sends each route an admin's token from another site's page; 2 hand mutations, each caught |
| 27 | `801b30c` | `Proxy::watch` analyses the `BYRLE_WATCH_MAX_VERSIONS` highest new versions of each package, 4 by default, in the ecosystem's version order (`highest`), and counts the rest in `Watched::left`. It awaits each analysis before starting the next, so it holds at most one of the 8 slots and queues nothing ahead of clients | `the_watcher_analyses_the_highest_new_versions_one_at_a_time`; 4 of 5 hand mutations caught; startup passing the variable is not tested, the accessor is |
| 28 | `1f833be` | Apart alone did not fix it: 10,000 made-up names evict an account's count at the same cost. An account's failures are now counted in one of 65,536 buckets by a hash keyed at random per process, which nothing evicts, and addresses keep their own LRU of 10,000. Counting only accounts that exist was not done: `Limited` would then say which names exist. Noted: `Lru` eviction scans every entry, so a full address LRU costs 10,000 steps per failure under the limiter's lock | `an_account_s_count_is_kept_through_a_flood_of_other_failures`; 3 hand mutations caught, one of them the shared LRU |
| 29 | `0b4c929` | `decide::total` sums weights with `saturating_add`, used by `Decision::score`, the new `Decision::checks`, `weighs` and `enforce`'s reason; `check_weight` multiplies and adds the surprise's weight saturating. A weight is not capped at `risk_threshold`: the sum stopping at `u32::MAX` already reaches it, and `policy diff` compares the weights as written | `weights_past_a_u32_sum_to_its_top`, the huge cases in `a_drop_weighs_its_rule_and_its_surprise`; 5 hand mutations, each caught |
| 30 | `251807f` | [checksum-tree-kept](engineering_decisions/0134-checksum-tree-kept.md): the largest tree proved is kept per database in `checksum_tree` through `analysis::store::Trees`, read on a client's first lookup; a read that fails fails the lookup, a write that fails is a WARN. `Proving` stages the full tiles a lookup fetches and caches them once both proofs pass | `a_tree_kept_before_a_restart_must_be_extended`, `a_store_that_fails_fails_only_the_read`, `a_tile_whose_proof_fails_is_not_kept`, `the_checksum_database_s_tree_is_kept_in_the_analyser_s_store`, and `a_checksum_tree_is_kept_and_only_grows` against Postgres; 7 hand mutations, each caught |
| 31 | `9e5c6e6` | `Registry::intel_alias`, a new row field: Go's `paths::intel_alias` gives a `github.com/` path in lower case when it is not; the rest give none. `proxy::package_intel` merges the records both names find in one snapshot. Only GitHub: it answered `github.com/Sirupsen/Logrus` 200 on 2026-11-05, and proxy.golang.org served three cases of logrus; another host may hold two modules differing in case. The zip's `go.mod` path was not used: it is read after the decision | `a_go_module_asked_in_another_case_finds_its_lower_case_intel`; 5 hand mutations, each caught |

Measured 2026-10-29 for finding 1, with npm 11.21.1's node-tar and Python's `tarfile`:

| Tarball | node-tar | `tarfile` | before `1c150b4` |
|---|---|---|---|
| a tar with no end blocks, continued in a second gzip member | both entries | both | the first |
| one member, a single zero block between entries | both | the first | the first |
| a whole second tar in a second member | the first | the first | the first |

Finding 6's case also covers `package/./package.json`, `package//package.json` and
`other/package.json`, which node-tar each extracts to `package.json`.

## Findings

Severity:

- **High**: a malicious publisher's version is served with a check it should fail answered
  as passed.
- **Medium**: a version is served with no decision by whoever controls the request, or the
  intel or analysis can be emptied or exhausted.
- **Low**: everything else.

| # | Step | Severity | What breaks | Evidence | Proposed change |
|---|---|---|---|---|---|
| 1 | V8 | High | `analysis.rs:255` `walk` reads a tarball with `flate2::read::GzDecoder`, which decodes the first gzip member only. node-tar decodes every member. A file in a second member, such as `package/binding.gyp` or a second `package/package.json`, is installed and never read | run: node-tar extracted `binding.gyp` and `package.json` from `multi.tgz`; the same walk as byrle's saw `package/package.json` only | **Resolved** in `1c150b4`, decision 0122: every gzip member decoded, and entries read past a zero block |
| 2 | V8 | High | `npm_install_scripts` (`analysis.rs:126`) reads `scripts` only. npm 11 runs `node-gyp rebuild` for a package with a top-level `binding.gyp` and no `install` or `preinstall` (`arborist/rebuild.js` `#addToBuildSet`), and gyp runs `<!(cmd)`. `npm publish` adds that `install` to the registry manifest, so `hasInstallScript` is true. A manifest published by a direct PUT can omit it, and then the metadata and the tarball both say "none" | run, output below | **Resolved** in `2fc88d1`, decision 0123: a root `binding.gyp` with no `install` or `preinstall` is `install: node-gyp rebuild`, unless `gypfile: false` |
| 3 | V3, A4 | High | A PyPI version's `published_at` is its first wheel's `upload-time` (`pypi/normalize.rs:57`, `wire.rs:150` `preferred`). `narrowed_to` (`record.rs:189`) keeps it, and `Deciding::dated` returns at once when it is set (`proxy.rs:2268`). Today, a hijacked account uploads `pkg-1.0-py3-none-manylinux_2_17_x86_64.whl` to a 2024 release whose `pkg-1.0-py3-none-any.whl` is listed first. pip on Linux prefers the new file, and it is dated 2024 | code | **Resolved** in `40d5f42` and `12f504b`, decision 0124: a file is dated by its own `upload-time` on a pinned fetch, and removed alone from the index when that refuses it |
| 4 | V3, A4 | High | Go's date is `.info` `Time` (`go/wire.rs:93`, `go/transport.rs:95`), which the go command fills from `%ct`, the committer date (`codehost/git.go:646`, Go 1.27.3). `GIT_COMMITTER_DATE=2020-01-01T00:00:00Z git commit`, then a new tag, passes any cooldown | code | **Resolved** in `c2b49db` and `e922a4a`, decision 0125: dated by the first sum.golang.org tree that holds its record, placed in time by index.golang.org |
| 5 | V8 | High | A `.crate` declaring `[lib] crate-type = ["proc-macro"]` is not read as a proc-macro: `analysis.rs:205` checks `lib.proc-macro` and `lib.proc_macro` only | run: `cargo build` printed `PROC MACRO RAN AT COMPILE TIME`, and `cargo package` kept the key | **Resolved** in `674edd8`: a `crate-type` or `crate_type` array holding `proc-macro` is a proc-macro |
| 6 | V8 | Medium | `member` returns the first `<top>/package.json` (`analysis.rs:127`); tar extractors keep the last. npm re-reads the extracted manifest only when `hasInstallScript` is already true. Clients that read the extracted manifest run its scripts: pnpm, yarn and bun, not checked here | run: node-tar's extracted `package.json` had `postinstall`; the first entry had none | **Resolved** in `1c150b4`, decision 0122: every copy is read, and the copy is the `archive_suspicious` signal |
| 7 | S3, A4, D5 | Medium | A missing publish date fails the cooldown at S1, and S3 removes the check (`enforce.rs:139`), so the version is served. The pinned path has no `Last-Modified` fallback when the full packument's `time` map lacks the version (`proxy.rs:2276`). The registry or the network controls this, not the publisher | test: `a_cooldown_that_cannot_be_answered_is_dropped_rather_than_failed` (`enforce.rs:856`) asserts `Verdict::Serve` under `cooldown_days: 30` | **Resolved** in `90252e5`, decision 0129: dated by its first sighting, else `cooldown_unanswered` |
| 8 | R3, R11, F2 | Medium; High where only tier 5 stops a direct fetch | Two `Other` shapes accept any suffix: `npm/v1/attestations/` (`npm/paths.rs:123`), and `sumdb/<db>/lookup/` and `tile/` (`go/paths.rs:152`). The URL is handed to reqwest as a string (`proxy.rs:3594`), and reqwest's parser removes `..` and `%2e%2e`. So the fetched path is not the classified one. Anyone with a token can fetch any artifact undecided and unaudited. Node and uv normalise these paths, so a lockfile cannot deliver it | run, output below | **Resolved** in `handle`: 400 for a `.` or `..` segment, `%2e` in any case, split on `/` or `\` |
| 9 | R10, F1 | Medium; High where only tier 5 stops a direct fetch | `artifact_fetch` (`proxy.rs:3422`) fetches every method but GET, and Maven's HEAD, with no decision. proxy.golang.org answers POST, PUT, OPTIONS and PATCH with the zip. npm, files.pythonhosted.org, Central and static.crates.io answered 400 to 405 | run, output below | **Resolved**: 405 to an artifact or manifest asked with a method but GET or HEAD |
| 10 | R12, F5 | Medium | `forward_artifact` (`proxy.rs:3745`) verifies a 200 only. A 203 or 206 with other bytes is forwarded unverified. A manifest's claim is checked on 200 only (`proxy.rs:3667`). `Range` is not in `FORWARDED`, so only an upstream, a mirror or a redirect target answers so. mvn and Gradle check no digest by default | run: the mock answered the analysis 200 with good bytes, and the client 203 with others; `SERVED THE EVIL BYTES` | **Resolved**: every 2xx verified as a 200 is |
| 11 | B9 | Medium | `read_bundle` (`osv/bundle.rs:164`) accepts a zip with no entries. Its digest differs from the stored one, so `replace_rows` runs `DELETE FROM advisory WHERE source = $1` (`intel/postgres.rs:311`). That erases the source's `MAL-` rows. KEV, Datadog and GitHub refuse empty input. A truncated export, or a mirror under `BYRLE_STREAM_URLS`, does the same with a subset | code | **Resolved**: a stream that parses to under half its stored rows is not loaded, unless `byrle refresh --force <stream>` |
| 12 | B8, J4, V9 | Medium | `Command::detect` (`detector.rs:362`) never reads the exit status. A detector's `errors` are stored (`detector.rs:423`) and logged only. The result is never rerun for that detector version (`detecting.rs:136`). A run that errors or times out is "no findings" for that digest, permanently | code | **Resolved**: a non-zero exit is not run; a run with `errors` is stored and fires `<detector>.error` |
| 13 | O6 | Medium | `policy check` (`check.rs` `Report::of`) reads no `signal_weights`, `risk_threshold` or `max_cvss`. `policy diff` decides only the packages in the audit log and lockfiles (`diff.rs:586`), and `decide_under` (`diff.rs:644`) never calls `with_signals`. `signal_weights: { known_malware: 0 }` against a log holding no malware prints no `LOOSER` line. This goes against the threat-model "A known-malicious version" row | code | **Resolved**: the top-level settings and each `signal_weights` key are compared directly |
| 14 | E2 | Medium | `guarded` reads a `Needs` route's body, up to `MAX_COMMAND_BODY` 16 MiB (`console/api.rs:30`), before the caller is checked (`routes.rs:403`, then `:409`). No body timeout or concurrency limit applies. The console shares the proxy's process | code | **Resolved**: an API caller is admitted from its headers before its body is read |
| 15 | E2 | Medium | `attempt` (`console/login.rs:196`) checks the limit, then awaits the store and the 2-slot hashing semaphore, and counts the failure only after them (`:211`). Every login sent before the first failure is counted is checked: N parallel guesses as one account get N checks. This goes against the threat-model "The login form" row | code | **Resolved**: a login is counted as a failure when admitted, before its password is checked |
| 16 | E2 | Medium | `POST api/v1/policy/diff` with `reader`'s `packages.read` reads every rotated audit log (`diff.rs:612`). It then fetches metadata, one after another, for each audited package and each of up to about 150,000 `versions` entries, outside `metadata_slot` (`diff.rs:481`) | code | **Resolved**: versions capped at `BYRLE_MAX_DIFF_VERSIONS`; one diff at a time |
| 17 | B4, J3 | Medium | `tree()` bounds the member sizes the headers state (`source.rs:219`), not the member count. Each member adds a `files` entry (`source.rs:311`). A tarball of millions of empty files holds that many entries, two trees at once and eight cached (`sourcing.rs:24`). The comparison is on by default | code | **Resolved**: members and decompressed bytes capped in `tree()` and `wheel_tree()` |
| 18 | J1, J2, J3 | Medium | The 600 s `timeout` drops the future, not the `spawn_blocking` work under it (`run.rs:478`, `sourcing.rs:314`, `claiming.rs:285`, `:301`). The slot is freed and the next job starts beside it. A gzip that inflates to hundreds of GB holds a blocking thread for hours | code | **Resolved**: blocking reads stop once the future awaiting them is dropped |
| 19 | D1, D2, F4 | Low | A document over `BYRLE_MAX_METADATA_BYTES` (`proxy.rs:3785`) or undecodable (`proxy.rs:1163`) is forwarded with its origin URLs. npm's `replace-registry-host` comes back to the proxy, and the pinned fetch is decided. pnpm, yarn, bun and pip fetch from the origin. [threat-model](threat-model.md) "Attacks on the proxy itself" states the bound, but Bypasses does not list it | run: with `BYRLE_MAX_METADATA_BYTES=300`, `dist.tarball` stayed on the origin, and the pinned fetch through the proxy was 502 | **Resolved**: 502 in enforce mode; forwarded in observe mode, listed in Bypasses |
| 20 | V1, D7 | Low | An npm version that fails `WireVersion`, such as `"scripts":{"n":1}` (`npm/wire.rs:41`), is skipped (`npm/normalize.rs:43`) and stays in the document. Its URL is not repointed (`npm/rewrite.rs:115`), and a `dist-tags` entry naming it stays. npm's pinned fetch refuses it as not listed (`proxy.rs:2052`). pnpm and yarn fetch it from the origin. `npm publish` normalises `scripts`, so it takes a direct PUT | code | **Resolved**: skipped versions and the tags naming them are removed |
| 21 | B1b | Low | `.bytes()` reads the whole body before any limit: `npm/transport.rs:106`, `go/transport.rs:79` and `:169`, `maven/transport.rs:156`, `:361`, `:381` and `:404`, `cargo/transport.rs:47`. These run on the artifact path, outside `metadata_slot` and the deadline. A Maven `.asc`, a publisher's upload, is kept whole in an LRU of 8,192 (`maven/transport.rs:50`) | code | **Resolved**: one capped reader for every `Clients` read; sidecars capped at 64 KiB |
| 22 | B7 | Low | `KeyServers::copy` reads the whole key (`keys.rs:86`), and every certification on it is verified. keyserver.ubuntu.com accepts certifications from anyone, and the publisher picks the issuer | code | **Resolved**: the key text capped at 1 MiB; certifications were not verified |
| 23 | B12 | Low | `judged` allows a group-writable spool directory (`spool.rs:327`). `Spooled::reader` reopens the file by path (`spool.rs:293`) after the digest was taken from the stream. A group member can rename another file over it in that gap. This goes against the threat-model "Other users on the host" row | code | **Resolved**: a reader opens only the inode written |
| 24 | B5 | Low | reqwest 0.13.5 removes `Authorization`, `Cookie`, `Proxy-Authorization` and `WWW-Authenticate` on a redirect to another host (`redirect.rs:239`), not `x-apikey`. `upload()` sends the key and the bytes to the `upload_url` VirusTotal answered (`virustotal.rs:240`). `BYRLE_VIRUSTOTAL_URL` is not checked with `http::trusted` (`env.rs:1463`) | code | **Resolved**: VirusTotal's own client, no redirects; the upload URL on the API's origin; the base `https` or loopback |
| 25 | E4 | Low | `token_client` (`http.rs:81`) follows redirects, and `X-Byrle-Token` is not a header reqwest removes. A 3xx from `BYRLE_REMOTE_URL` or `BYRLE_PROXY_URL` sends the token to its target, past the https-or-loopback check (`remote.rs:131`). `byrle warm` uses the same client (`warm.rs:79`) | code | **Resolved**: the token is a connection's credential, on the first URL's origin only |
| 26 | E2 | Low | The Origin check is in the login and logout handlers only (`api.rs:320`, `:390`; `pages.rs:295`, `:345`), not in `guarded`. A token skips CSRF (`api.rs` `caller_sending`), and the gate accepts Basic (`gate.rs:27`). On a shared listener, a browser holding Basic credentials for the proxy sends them on a cross-site POST to `policy/diff`, giving finding 16 to another site. This goes against the threat-model "A request from another site" row | code | **Resolved**: `site.foreign()` in `guarded` for every method but GET and HEAD |
| 27 | E6 | Low | The watcher calls `analyser.start` for each new version (`proxy.rs:4274`). Each waits for one of 8 slots, and the deadline does not count the wait. 1,000 versions published between passes queue ahead of clients, which get 503 meanwhile | code | **Resolved**: the highest `BYRLE_WATCH_MAX_VERSIONS` per package per pass, one at a time |
| 28 | E2 | Low | The limiter's LRU holds 10,000 keys (`login.rs:32`). Failures from 500 IPv6 /64s, 20 each, evict an account's count | code | **Resolved**: accounts counted in 65,536 buckets nothing evicts, apart from addresses |
| 29 | S4 | Low | `Decision::score` (`decide.rs:342`) and `check_weight` (`:443`) add `u32` with `+` and `sum`. Release builds wrap, and no weight has an upper bound. `known_malware: 4294967295`, which reads as a tightening, plus any signal of weight 1 wraps to under the threshold | code | **Resolved**: saturating sums and products; no weight cap |
| 30 | B2 | Low | `latest` is held in memory only (`sumdb.rs:33`), so a restart accepts a rolled-back tree. Full tiles are cached before the proof is checked (`sumdb.rs:166`), so one bad tile answers 503 until restart | code | **Resolved**: `latest` kept in `checksum_tree`; a tile cached once its proof passes |
| 31 | V4 | Low | `go/paths.rs:92` keeps a module path's case. Intel for `github.com/evil/pkg` misses `github.com/Evil/Pkg`, which serves for a repository with no `go.mod` | code | **Resolved**: a `github.com/` path is also looked up in lower case |
| 32 | V4 | Low | `pypi/paths.rs:85` splits an sdist name at its last `-`. `foo-1.0-1.tar.gz` is version `1`; pip reads `1.0-1`, which is `1.0.post1`. An advisory for `1.0.post1` misses it | code | **Resolved**: an sdist split after the project asked for; a hash path's file placed by the index listing it |
| 33 | S1 | Low | `cargo/paths.rs:30` lowercases a crate name and does not treat `-` and `_` as one. A `denials` or `packages` entry spelled `foo_bar` matches nothing for the crate `foo-bar` | code | **Resolved**: a policy selector reads a crate name's `-` as `_`, as crates.io does |
| 34 | V8 | Low | A Maven file whose name does not end `.jar` is not read for annotation processors (`maven/mod.rs:69`). A Gradle `.module` can name any file for a processor variant, and javac reads it as a zip | code | **Resolved**: any Maven artifact that opens as a zip is read for processors |
| 35 | R12 | Low | A metadata 2xx with a `Content-Type` no adapter reads goes to `forward_artifact` (`proxy.rs:3671`). It is not rewritten, and is logged as `proxied` with no `UNINSPECTED` count | run | **Resolved**: 502 in enforce mode, forwarded in observe mode, counted `UNINSPECTED` |
| 36 | R12 | Low | `mark_etag` (`http.rs:296`) tags the ETag with the base only. A 304 keeps a filtered document from before a new refusal. The pinned fetch is still decided | code | **Resolved**: the tag carries the policy digest and the package's intel snapshot |
| 37 | B3 | Low | An attestation fetch answered 404, which npm can answer just after a publish, is stored as `Attested::Failed` for good: a false refusal | code | **Resolved**: a 404 within `provenance_window_days` of the publish stores nothing |
| 38 | J1 | Low | An artifact over the spool's ceiling by `Content-Length` alone is stored as `Unreadable` with no digest check (`run.rs:367`, `:430`). A wrong header from a mirror marks a clean digest as running install scripts: a false refusal | code | **Resolved**: the header is not read; the bytes are counted |
| 39 | B1 to B7 | Low | No client sets a redirect policy, and `https_only` is off, so a redirect from https to http is followed. `dated_by_host` sends a HEAD to the metadata's artifact URL before the unservable check (`proxy.rs:1554`, `:4111`). No first URL was found that a publisher controls | code | **Resolved**: at most 10 redirects, none from https; no HEAD to an origin not served |
| 40 | E3 | Low | `Clients::from_env` is `reqwest::Client::new()` (`ecosystem.rs:278`): no timeouts, and `BYRLE_CA_BUNDLE` is not read | code | **Resolved**: built with `startup::connection` |

### Reproduction output

Finding 1. `multi.tgz` holds two gzip members: the first `package/package.json` with no
scripts, the second `package/binding.gyp`.

```text
== node-tar multi:   binding.gyp  package.json
== byrle-style walk: member package/package.json   (nothing else)
```

Finding 2, npm 11.21.1 against a registry serving `hasInstallScript: false` and no
`scripts`, with a tarball holding `binding.gyp`. node-gyp stopped when it could not download
the node headers, before reading `binding.gyp`. With network access, it then reads
`binding.gyp` and runs its `<!(...)` commands:

```text
info run gyptest@1.0.0 install node_modules/gyptest node-gyp rebuild
npm error command sh -c node-gyp rebuild
```

Finding 10. The mock answered the analysis's fetch 200 with the published bytes, and the
client's fetch 203 with others:

```text
try 1: 503
try 2: 203
SERVED THE EVIL BYTES
```

Finding 19, with `BYRLE_MAX_METADATA_BYTES=300`:

```text
WARN UNINSPECTED: metadata document exceeds the size limit, forwarded without rewriting
WARN could not fetch metadata ... decompressed body exceeds 300 bytes
```

Finding 8, through a byrle built from HEAD with a logging upstream:

```text
REQ /npm/-/npm/v1/attestations/../../../../evil/-/evil-6.6.6.tgz -> 200 body=EVIL-BYTES-/evil/-/evil-6.6.6.tgz
REQ /npm/-/npm/v1/attestations/%2e%2e/%2e%2e/%2e%2e/%2E%2e/evil/-/evil-6.6.6.tgz -> 200
REQ /go/sumdb/x/tile/%2e%2e/%2e%2e/%2e%2e/github.com/evil/mod/@v/v6.6.6.zip -> 200
REQ /npm/evil/-/evil-6.6.6.tgz -> 502 (decided)
UPSTREAM GET /evil/-/evil-6.6.6.tgz
UPSTREAM GET /github.com/evil/mod/@v/v6.6.6.zip
```

No audit line was written for the first three.

Finding 9, the same setup:

```text
GET -> 502 ... cannot be assessed
POST -> 200 EVIL-BYTES-/github.com/evil/mod/@v/v6.6.6.zip
OPTIONS -> 200 EVIL-BYTES-...
```

## Each step

| ID | Finding | Checked and found nothing |
|---|---|---|
| E1 | 8, 9, 10 | |
| E2 | 14, 15, 16, 26, 28 | all 35 routes: the 24 `Needs` routes are GET but check and diff, which change nothing; no state change answers GET; check and diff clone the policy in force and never install one (`commands.rs:338`); maud escapes every value, no `PreEscaped`, and no `href` takes registry or log text |
| E2a | | `state` from a `__Host-` cookie; nonce, PKCE S256, the issuer compared exactly; HMAC algorithms refused; the key's family fits the algorithm; `aud` and `azp`; keys refetched at most once a minute; no `next` parameter |
| E3 | 40 | event-log lines are JSON strings, so a name cannot add a line. `account password` echoes a password typed at a terminal, and logs are created under the umask, not 0640 |
| E4 | 25 | `127.0.0.1.evil.com`, `localhost@evil` and `[::ffff:127.0.0.1]` are refused as loopback (`http.rs:100`) |
| E5 | | a bad file keeps the old policy (`startup.rs:592`); a request reads one policy through `current()` |
| E6 | 27 | a held decision is not stored; `refresh` replaces the metadata as a client's fetch would |
| E7 | | clients bounded by `BYRLE_MAX_TRAFFIC_CLIENTS`; hyper refuses CR and LF in `User-Agent` |
| E8 | | retention 0 refused (`env.rs`); `artifact_decision` is read by `byrle artifact` only, never when deciding |
| E9 | 11 | |
| R1 | | `/registryX` is 404; the query is kept |
| R2 | | exact match, any method; health holds no credentials |
| R3 | 8 | npm and cargo version or `..` tricks in an `Artifact` path miss `store.lookup` and are refused; a Maven `..` in the group decides a key with no metadata and fails closed |
| R4 | | the token looked up by SHA-256, revoked and disabled excluded; `X-Byrle-Token` over `Authorization`; non-UTF-8 is 401; a Basic user must equal the account; no token in a query; `BYRLE_RP_KEY` compared by digest |
| R5 | | HEAD and GET may redirect apart; the digest holds either way |
| R6 | | `Host` unchecked while `BYRLE_PROXY_URL` is unset changes the asker's own URLs only |
| R7 | | an unread document forwards upstream's `.sha1`, which then fails the client |
| R8 | | threat-model row `BYRLE_MODE=observe` |
| R9 | 19 | a client's own `Accept-Encoding: br, identity;q=0` unrewrites its own answer only |
| R10 | 9 | |
| R11 | 8, 39 | only `FORWARDED` headers go upstream, with no body |
| R12 | 10, 35, 36 | |
| B1a | | the digest is checked and the last chunk held; 30 s per read |
| B1b | 21 | |
| B1c | 38 | over 1 GiB is `Unreadable`, which counts as install scripts |
| B2 | 30 | signature, inclusion and consistency proved before an `h1:` is used; the answer must hold the `module version` line |
| B3 | 37 | the URL is rebuilt onto the upstream (`proxy.rs:2776`); a metadata `attestation_url` alone is never believed |
| B4 | 17 | owner, repository and reference validated; the host fixed |
| B5 | 24 | |
| B6 | | `next_page` is appended to a fixed base (`trustpub.rs:149`) |
| B7 | 22 | a key neither server holds fails closed, 503 |
| B8 | 12 | no shell; a leading `-` refused; 16 MiB of output; the process group killed on timeout |
| B9 | 11 | nothing extracted to disk; entries capped at 16 MiB |
| B10 | | 256 KiB per answer (`oidc.rs:291`); `Authorization` removed on a redirect to another host |
| B11 | | the one `format!` query takes constant columns (`intel/postgres.rs:342`); COPY CSV doubles quotes |
| B12 | 23 | `create_new`, 0600, a random name, a symlink refused |
| V1 | 20 | |
| V2 | | a file the record does not name is decided on the first file's digest, and the requested bytes then fail it at A7 |
| V3 | 3, 4, 7 | |
| V4 | 31, 32 | PyPI names PEP 503-normalised on both sides (`rows.rs:44`, `pypi/paths.rs:14`); cargo lowercased on both; SemVer build metadata, PEP 440 trailing zeros and Maven `1.0` against `1.0.0` each match more, not less; an unparseable stored bound is a 503 |
| V5 | | merged by id, highest score kept (`facts.rs:129`); rows deduplicated by source and id (`store.rs:136`), so one source cannot shadow another |
| V6 | | weights are `u32` and only add |
| V7 | | a metadata attestation URL is `NOT_VERIFIED` until verified, and verification binds the digest (`attestation.rs:52`) |
| V8 | 1, 2, 5, 6, 34 | |
| V9 | 12 | GuardDog downloads its own copy: threat-model "Detectors" |
| V10 | | an external detector named after a built-in is refused (`detector.rs:230`) |
| V11 | | from the fetch plan and the claim only |
| S1 | 33 | |
| S2 | | each key added once |
| S3 | 7 | install scripts, provenance and intel end up answered before a pinned serve; KEV with no stream is the operator's configuration |
| S4 | 29 | a tie refuses; a NaN `max_cvss` behaves as one over 10 |
| A1 | | an unlisted version is refused |
| A2 | | B2's proofs |
| A3 | | an SRI that does not parse is no strong digest: threat-model row "An artifact with no strong digest" |
| A4 | 3, 4, 7 | |
| A5 | | an intel error is 503 |
| A6 | | the only early serves are no strong digest, and own signals weighed under the threshold |
| A7 | 10 | |
| A8 | not reviewed | |
| D1, D2 | 19 | |
| D3 | | a Go version after the cutoff takes the cutoff's time; the pinned fetch reads its own `.info` |
| D4 | | the pinned fetch answers 503 through `intel_for` in `Deciding::refusal` |
| D5 | 7 | |
| D6 | | an unreadable `@latest` leaves the zip's decision |
| D7 | 20 | PyPI filename versions match exactly; a cargo, Go or Maven line that does not parse is kept, and its pinned fetch refused |
| D8 | | headers only |
| J1 | 18, 38 | |
| J2 | 18 | a mismatch is remembered as `Failed` |
| J3 | 17, 18 | |
| J4 | 12 | |
| J5 | | nothing stored on failure |
| J6 | | a row dropped on a full queue is counted (`batched.rs:70`); only `byrle artifact` reads the rows |
| O1 to O5 | | `packages::check` refuses a tightening entry and an undated loosening one; `ignored_vuln_advisory_ids` excuses `max_cvss` only; a stored score wins over `advisory_scores` |
| O6 | 13 | |
| O7 | 7 | |
| O8 to O10 | | the operator's settings |
| F1 | 9 | |
| F2 | 8 | PyPI `.metadata`, Go `.info` and Maven sidecars must be the last segment; a refused version's `.metadata` or `.info` is served, and its file still decided |
| F3 | | threat-model row `BYRLE_MODE=observe` |
| F4 | 19 | |
| F5 | 10 | |
| F6 | | threat-model row "An artifact with no strong digest" |

## Corrections to logic-flow.md

| Row | It said | The code |
|---|---|---|
| S1 | an unknown publish date fails a non-zero cooldown | it fails at S1, and S3 then drops the check, so the version is served (finding 7) |
| B4, J3 | only with `BYRLE_SOURCE_ARCHIVES` | on by default, `https://codeload.github.com`; `off` turns it off (`env.rs:538`) |
| B8 | URL from the spooled artifact | the detector is given the ecosystem, name and version as arguments, and fetches its own copy |
