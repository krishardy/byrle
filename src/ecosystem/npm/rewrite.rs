//! Removing versions from a packument, and pointing the rest at the proxy.

use std::collections::{BTreeMap, HashSet};

use tracing::warn;

use crate::origin::{
    Disposition, OriginPolicy, RewriteError, reachable_path, rewrite_artifact_origins,
};
use crate::record::PackageMetadata;

///
/// This is the only control that works on an off-origin artifact. The client fetches
/// `dist.tarball` from whatever host it names, so a refusal at the artifact request never
/// happens: the request goes somewhere else. The packument is the last point at which the
/// version is visible, and dropping it there is what decision #4 already settles for
/// quarantine, letting the client's own resolver pick a version the proxy can see.
///
/// Structural, so unlike [`rewrite_artifact_origins`] it parses the document. That cost
/// is paid only when there is something to remove: zero of the 24,852 artifact URLs
/// measured on registry.npmjs.org were off-origin, so this path is not the normal one.
///
/// Versions with no `dist.tarball` at all are left alone. They produce no record, so
/// nothing can install them anyway, and removing them would be a second behaviour hiding
/// behind this one.
///
/// `refuse_unservable` says what happens to an artifact on an origin the proxy does not
/// front: dropped when true, and when false kept and left exactly as published, because
/// the operator chose to let the client fetch it directly.
///
/// A version is dropped for either of two reasons: its artifact is published somewhere
/// the proxy cannot see, or the package policy refuses it. They are separate questions
/// and share one pass because both remove from the same `versions` map and both leave a
/// `dist-tags` entry pointing at nothing.
pub fn filter_unservable_versions(
    json: &[u8],
    artifacts: impl IntoIterator<Item = (String, String)>,
    policy: &OriginPolicy,
    refused_by_policy: &HashSet<String>,
    refuse_unservable: bool,
    public_base: &str,
) -> Result<Filtered, RewriteError> {
    let mut document: serde_json::Value =
        serde_json::from_slice(json).map_err(RewriteError::NotJson)?;
    let base = public_base.trim_end_matches('/');

    let mut removed = Vec::new();
    let mut rewritten = 0;
    let mut allowed = 0;
    if let Some(versions) = document
        .get_mut("versions")
        .and_then(serde_json::Value::as_object_mut)
    {
        for (version, url) in artifacts {
            // Asked first, because the policy's answer does not depend on where the
            // artifact lives. A version refused here is gone whatever its origin is.
            if refused_by_policy.contains(&version) {
                versions.remove(&version);
                removed.push(version);
                continue;
            }
            match policy.disposition(&url) {
                Disposition::Served => {
                    let Some(path) = reachable_path(&url, policy.reachable()) else {
                        continue;
                    };
                    if let Some(tarball) = versions
                        .get_mut(&version)
                        .and_then(|entry| entry.get_mut("dist"))
                        .and_then(|dist| dist.get_mut("tarball"))
                    {
                        *tarball = serde_json::Value::String(format!("{base}{path}"));
                        rewritten += 1;
                    }
                }
                // Left exactly as published, so the client fetches it where the registry
                // said. That is the point of allowing it.
                Disposition::AllowedDirect(_) => allowed += 1,
                Disposition::Refused(_) if refuse_unservable => {
                    versions.remove(&version);
                    removed.push(version);
                }
                Disposition::Refused(_) => allowed += 1,
            }
        }
    }

    // A tag pointing at a version that is gone would resolve to nothing. Dropping the tag
    // lets the resolver fall back to a version that is still there.
    let removed_set: HashSet<&str> = removed.iter().map(String::as_str).collect();
    if let Some(tags) = document
        .get_mut("dist-tags")
        .and_then(serde_json::Value::as_object_mut)
    {
        tags.retain(|_, value| value.as_str().is_none_or(|v| !removed_set.contains(v)));
    }

    removed.sort();
    Ok(Filtered {
        body: serde_json::to_vec(&document).map_err(RewriteError::NotJson)?,
        removed,
        rewritten,
        allowed,
    })
}

/// The result of removing versions the proxy will not serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filtered {
    pub body: Vec<u8>,
    /// Versions no longer in the document, sorted.
    pub removed: Vec<String>,
    /// Versions kept, with their artifact pointed at the proxy.
    pub rewritten: usize,
    /// Versions kept with their artifact left as published, because the operator allows
    /// that origin to be fetched directly.
    pub allowed: usize,
}

/// What the packument path needs to decide what to send back.
pub struct Rewrite<'a> {
    pub decoded: &'a [u8],
    pub packument: &'a PackageMetadata,
    /// Where artifact URLs are pointed, when they are pointed anywhere.
    pub base: Option<&'a str>,
    pub origins: &'a OriginPolicy,
    /// Versions the policy refuses, which are removed.
    pub refused_by_policy: &'a HashSet<String>,
    pub refuse_unservable: bool,
    pub path: &'a str,
}

/// Point a packument's artifacts at the proxy, or explain why it was left alone.
///
/// Returns `None` when the document is forwarded as it came, which always means some
/// artifacts for this package will be fetched without the proxy seeing them.
pub fn rewrite_packument(r: Rewrite<'_>) -> Option<Vec<u8>> {
    let (allowed_direct, refused) = r.packument.unserved_origins(r.origins);
    warn_allowed_direct(r.path, &allowed_direct);
    // Either reason to drop a version puts this on the structural path. The byte rewrite
    // cannot remove anything, only repoint URLs.
    if !r.refused_by_policy.is_empty() || (r.refuse_unservable && !refused.is_empty()) {
        return filtered(&r, &refused);
    }
    warn_unserved(r.path, &refused, r.packument.records.len());
    repointed(&r)
}

/// Warn about artifacts on origins the operator allowed clients to fetch directly.
fn warn_allowed_direct(path: &str, allowed_direct: &BTreeMap<String, usize>) {
    if allowed_direct.is_empty() {
        return;
    }
    warn!(
        url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
        waharoa.package.versions = allowed_direct.values().sum::<usize>(),
        waharoa.package.origins = ?allowed_direct.keys().collect::<Vec<_>>(),
        "UNINSPECTED: artifacts fetched directly by the client, allowed by configuration"
    );
}

/// The document with the versions the policy refuses, and those on an origin the proxy
/// does not serve, removed. `refused` is those origins, with their version counts.
/// Returns `None` when the document cannot be filtered.
fn filtered(r: &Rewrite<'_>, refused: &BTreeMap<String, usize>) -> Option<Vec<u8>> {
    let origins: Vec<&String> = refused.keys().collect();
    let artifacts = r.packument.records.iter().filter_map(|record| {
        Some((
            record.package.version().to_owned(),
            record.artifact()?.url.clone(),
        ))
    });
    match filter_unservable_versions(
        r.decoded,
        artifacts,
        r.origins,
        r.refused_by_policy,
        r.refuse_unservable,
        r.base.unwrap_or(""),
    ) {
        // Always the filtered body, even when nothing survived. Forwarding the original
        // would put every refused version straight back into the document.
        Ok(filtered) => {
            warn!(
                url.path = %crate::http::url_path(r.path), url.query = crate::http::url_query(r.path),
                waharoa.package.removed = filtered.removed.len(),
                waharoa.package.removed_by_policy = r.refused_by_policy.len(),
                waharoa.package.kept = filtered.rewritten,
                waharoa.package.allowed_direct = filtered.allowed,
                waharoa.package.origins = ?origins,
                "REFUSED versions removed from the document so the resolver picks \
                 another"
            );
            Some(filtered.body)
        }
        Err(e) => {
            warn!(url.path = %crate::http::url_path(r.path), url.query = crate::http::url_query(r.path), error.message = %e, "UNINSPECTED: packument could not be filtered");
            None
        }
    }
}

/// Warn about artifacts left on an origin the proxy does not serve, saying whether that
/// is every one of the document's `records` versions.
fn warn_unserved(path: &str, refused: &BTreeMap<String, usize>, records: usize) {
    if refused.is_empty() {
        return;
    }
    let versions: usize = refused.values().sum();
    let origins: Vec<&String> = refused.keys().collect();
    if versions == records {
        warn!(
            url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
            waharoa.package.versions = versions,
            waharoa.package.origins = ?origins,
            "UNINSPECTED: every artifact in this packument is on an origin the proxy \
             does not front"
        );
    } else {
        warn!(
            url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
            waharoa.package.versions = versions,
            waharoa.package.origins = ?origins,
            "UNINSPECTED: some artifacts left on an origin the proxy does not front"
        );
    }
}

/// The document with its artifact URLs pointed at the proxy.
/// Returns `None` when URLs are not repointed, nothing was, or the rewrite failed.
fn repointed(r: &Rewrite<'_>) -> Option<Vec<u8>> {
    let base = r.base?;
    let artifacts = r
        .packument
        .records
        .iter()
        .filter_map(|record| Some(record.artifact()?.url.as_str()));
    match rewrite_artifact_origins(r.decoded, artifacts, r.origins.reachable(), base) {
        Ok(rewritten) => (rewritten.rewritten > 0).then_some(rewritten.body),
        Err(e) => {
            warn!(url.path = %crate::http::url_path(r.path), url.query = crate::http::url_query(r.path), error.message = %e, "UNINSPECTED: packument could not be rewritten");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ecosystem::npm::{fixture, normalize_packument};
    use crate::identity::{Ecosystem, PackageKey};
    use crate::origin::{ReachableOrigins, Rewritten, rewrite_artifact_origins};
    use crate::record::DocumentDetail;
    use crate::route::RequestTarget;

    use super::super::classify_path;

    const UPSTREAM: &str = "https://registry.npmjs.org";
    const PROXY: &str = "http://127.0.0.1:8080";

    fn origins(additional: &[&str]) -> ReachableOrigins {
        ReachableOrigins::new([UPSTREAM], additional.iter().copied()).expect("valid origins")
    }

    /// Normalise, then rewrite with the artifact URLs that came out of it. This is
    /// the real sequence: the rewrite never parses the document itself.
    fn rewrite_with(json: &[u8], reachable: &ReachableOrigins, base: &str) -> Rewritten {
        let p = normalize_packument(json, DocumentDetail::Abbreviated)
            .expect("fixture should normalise");
        let artifacts: Vec<String> = p
            .records
            .iter()
            .map(|r| r.artifact().expect("one file").url.clone())
            .collect();
        rewrite_artifact_origins(json, artifacts.iter().map(String::as_str), reachable, base)
            .expect("should rewrite")
    }

    fn rewrite(json: &str) -> Rewritten {
        rewrite_with(json.as_bytes(), &origins(&[]), PROXY)
    }

    /// Only the origin moves. The path is kept so the request that comes back is one
    /// `classify_path` understands and the proxy forwards upstream unchanged.
    #[test]
    fn the_origin_changes_and_the_path_does_not() {
        let out = rewrite(
            r#"{"name":"lodash","versions":{"4.17.21":{"version":"4.17.21","dist":{
                "tarball":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}}}}"#,
        );
        assert_eq!(out.rewritten, 1);
        assert_eq!(out.left_alone, 0);

        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["versions"]["4.17.21"]["dist"]["tarball"],
            serde_json::json!("http://127.0.0.1:8080/lodash/-/lodash-4.17.21.tgz")
        );
    }

    /// `dist.integrity` is what npm checks the downloaded bytes against, and what the
    /// registry signature covers. Touching it would break both.
    #[test]
    fn integrity_and_every_other_field_survive() {
        let original = fixture("sigstore-5.0.0.abbrev.json");
        let out = rewrite_with(&original, &origins(&[]), PROXY);
        assert_eq!(out.rewritten, 1);

        let served: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        let mut expected: serde_json::Value = serde_json::from_slice(&original).unwrap();
        expected["versions"]["5.0.0"]["dist"]["tarball"] =
            served["versions"]["5.0.0"]["dist"]["tarball"].clone();
        assert_eq!(served, expected);
        assert!(
            served["versions"]["5.0.0"]["dist"]["signatures"][0]["sig"].is_string(),
            "signatures have to come through untouched"
        );
    }

    /// An origin the proxy does not front is left alone. Rewriting it would mean the
    /// proxy fetching from an arbitrary host on a client's behalf.
    #[test]
    fn unreachable_origins_are_left_alone_and_counted() {
        let out = rewrite(
            r#"{"name":"widget","versions":{
                "1.0.0":{"version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}},
                "1.0.1":{"version":"1.0.1","dist":{"tarball":"https://elsewhere.example/widget-1.0.1.tgz"}}}}"#,
        );
        assert_eq!(out.rewritten, 1);
        assert_eq!(out.left_alone, 1);

        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["versions"]["1.0.1"]["dist"]["tarball"],
            serde_json::json!("https://elsewhere.example/widget-1.0.1.tgz")
        );
    }

    /// A private registry's own artifacts are reachable, so they are rewritten too.
    #[test]
    fn a_private_registrys_own_artifacts_are_rewritten() {
        let out = rewrite_with(
            br#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0","dist":{
                "tarball":"https://npm.corp.example/w/-/w-1.0.0.tgz"}}}}"#,
            &origins(&["https://npm.corp.example"]),
            PROXY,
        );
        assert_eq!(out.rewritten, 1);
    }

    /// A query string is part of how the artifact is addressed, so it is kept.
    #[test]
    fn a_query_string_is_preserved() {
        let out = rewrite(
            r#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0","dist":{
                "tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz?token=abc"}}}}"#,
        );
        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["versions"]["1.0.0"]["dist"]["tarball"],
            serde_json::json!("http://127.0.0.1:8080/w/-/w-1.0.0.tgz?token=abc")
        );
    }

    /// Documents with nothing to rewrite come back intact and say so.
    #[test]
    fn documents_with_no_artifacts_are_unchanged() {
        for json in [
            r#"{"name":"w","versions":{}}"#,
            r#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0"}}}"#,
            r#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0","dist":{}}}}"#,
            r#"{"name":"w"}"#,
        ] {
            let out = rewrite(json);
            assert_eq!(out.rewritten, 0, "{json}");
            assert_eq!(out.left_alone, 0, "{json}");
        }
    }

    fn policy(served: &[&str], allowed: &[&str]) -> OriginPolicy {
        OriginPolicy::new(origins(served), allowed.iter().copied()).expect("valid policy")
    }

    fn filter(json: &str, policy: &OriginPolicy) -> Filtered {
        filter_refusing(json, policy, &HashSet::new())
    }

    /// The same, with versions the package policy refuses.
    fn filter_refusing(
        json: &str,
        policy: &OriginPolicy,
        refused_by_policy: &HashSet<String>,
    ) -> Filtered {
        let p = normalize_packument(json.as_bytes(), DocumentDetail::Abbreviated)
            .expect("should normalise");
        let artifacts: Vec<(String, String)> = p
            .records
            .iter()
            .map(|r| {
                (
                    r.package.version().to_owned(),
                    r.artifact().expect("one file").url.clone(),
                )
            })
            .collect();
        filter_unservable_versions(
            json.as_bytes(),
            artifacts,
            policy,
            refused_by_policy,
            true,
            PROXY,
        )
        .expect("should filter")
    }

    const MIXED: &str = r#"{"name":"w","dist-tags":{"latest":"1.0.2","old":"1.0.0"},
        "versions":{
            "1.0.0":{"version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz"}},
            "1.0.1":{"version":"1.0.1","dist":{"tarball":"https://elsewhere.example/w-1.0.1.tgz"}},
            "1.0.2":{"version":"1.0.2","dist":{"tarball":"https://elsewhere.example/w-1.0.2.tgz"}}}}"#;

    fn refusing(versions: &[&str]) -> HashSet<String> {
        versions.iter().map(|v| (*v).to_string()).collect()
    }

    /// `rewrite_packument` over `json`, the way the proxy calls it.
    fn rewrite_document(
        json: &str,
        origins: &OriginPolicy,
        base: Option<&str>,
        refused_by_policy: &HashSet<String>,
        refuse_unservable: bool,
    ) -> Option<serde_json::Value> {
        let packument = normalize_packument(json.as_bytes(), DocumentDetail::Abbreviated)
            .expect("should normalise");
        rewrite_packument(Rewrite {
            decoded: json.as_bytes(),
            packument: &packument,
            base,
            origins,
            refused_by_policy,
            refuse_unservable,
            path: "/w",
        })
        .map(|body| serde_json::from_slice(&body).expect("json"))
    }

    const ON_REGISTRY: &str = r#"{"name":"w","versions":{
        "1.0.0":{"version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz"}}}}"#;

    const OFFSITE: &str = r#"{"name":"w","versions":{
        "1.0.0":{"version":"1.0.0","dist":{"tarball":"https://elsewhere.example/w-1.0.0.tgz"}}}}"#;

    #[test]
    fn a_packument_on_the_registry_is_pointed_at_the_proxy() {
        let out = rewrite_document(
            ON_REGISTRY,
            &policy(&[], &[]),
            Some(PROXY),
            &HashSet::new(),
            true,
        )
        .expect("rewritten");
        assert_eq!(
            out["versions"]["1.0.0"]["dist"]["tarball"],
            "http://127.0.0.1:8080/w/-/w-1.0.0.tgz"
        );
    }

    /// Nothing rewritten is nothing sent: the upstream's bytes go through as they came.
    #[test]
    fn a_packument_with_nothing_to_repoint_is_forwarded_as_it_came() {
        let origins = policy(&[], &[]);
        assert_eq!(
            rewrite_document(OFFSITE, &origins, Some(PROXY), &HashSet::new(), false),
            None,
            "the only artifact is on an origin the proxy does not front"
        );
        assert_eq!(
            rewrite_document(ON_REGISTRY, &origins, None, &HashSet::new(), true),
            None,
            "rewriting is off and nothing is refused"
        );
    }

    /// What rewriting `json` warns about.
    fn warned(json: &str, origins: &OriginPolicy) -> String {
        let (guard, buf) = crate::util::test_support::capture(tracing::Level::WARN);
        rewrite_document(json, origins, Some(PROXY), &HashSet::new(), false);
        drop(guard);
        crate::util::test_support::text(&buf)
    }

    /// An artifact the client fetches without the proxy is warned about, saying whether
    /// the operator allowed it and whether it is every artifact or some.
    #[test]
    fn an_artifact_the_proxy_does_not_see_is_warned_about() {
        let allowed = warned(OFFSITE, &policy(&[], &["https://elsewhere.example"]));
        assert!(allowed.contains("allowed by configuration"), "{allowed}");
        assert!(!allowed.contains("does not front"), "{allowed}");

        let every = warned(OFFSITE, &policy(&[], &[]));
        assert!(
            every.contains("every artifact in this packument"),
            "{every}"
        );

        let mixed = r#"{"name":"w","versions":{
            "1.0.0":{"version":"1.0.0","dist":{"tarball":"https://elsewhere.example/w-1.0.0.tgz"}},
            "2.0.0":{"version":"2.0.0","dist":{"tarball":"https://registry.npmjs.org/w/-/w-2.0.0.tgz"}}}}"#;
        let some = warned(mixed, &policy(&[], &[]));
        assert!(some.contains("some artifacts left"), "{some}");
        assert!(!some.contains("every artifact"), "{some}");

        let none = warned(ON_REGISTRY, &policy(&[], &[]));
        assert!(none.is_empty(), "{none}");
    }

    /// Either reason to drop a version sends the filtered body, even with rewriting off.
    #[test]
    fn a_refused_version_is_removed_whether_or_not_urls_are_repointed() {
        let origins = policy(&[], &[]);
        let by_policy = rewrite_document(ON_REGISTRY, &origins, None, &refusing(&["1.0.0"]), true)
            .expect("filtered");
        assert!(by_policy["versions"].get("1.0.0").is_none(), "{by_policy}");
        let unservable = rewrite_document(OFFSITE, &origins, Some(PROXY), &HashSet::new(), true)
            .expect("filtered");
        assert!(
            unservable["versions"].get("1.0.0").is_none(),
            "{unservable}"
        );
    }

    /// Decision #4's resolution half: the version is gone, so the client's own
    /// resolver picks another and nobody is told no.
    #[test]
    fn a_version_the_package_policy_refuses_is_removed() {
        let out = filter_refusing(
            MIXED,
            &policy(&["https://elsewhere.example"], &[]),
            &refusing(&["1.0.0"]),
        );

        assert_eq!(out.removed, ["1.0.0"]);
        assert_eq!(out.rewritten, 2, "the other two are kept and repointed");
        let body: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert!(body["versions"].get("1.0.0").is_none());
        assert!(body["versions"].get("1.0.1").is_some());
    }

    /// A tag naming a removed version resolves to nothing, so the tag goes too.
    #[test]
    fn a_tag_pointing_at_a_refused_version_is_dropped() {
        let out = filter_refusing(
            MIXED,
            &policy(&["https://elsewhere.example"], &[]),
            &refusing(&["1.0.2"]),
        );

        let body: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert!(
            body["dist-tags"].get("latest").is_none(),
            "`latest` named the refused version"
        );
        assert_eq!(body["dist-tags"]["old"], "1.0.0", "other tags survive");
    }

    /// The policy's answer does not depend on where the artifact lives, so a version
    /// it refuses goes whether or not the origin is one the proxy fronts.
    #[test]
    fn policy_removes_a_version_the_origin_check_would_have_kept() {
        let out = filter_refusing(
            MIXED,
            &policy(&[], &["https://elsewhere.example"]),
            &refusing(&["1.0.1"]),
        );

        assert_eq!(out.removed, ["1.0.1"]);
        assert_eq!(out.allowed, 1, "1.0.2 is still allowed direct");
    }

    /// Both reasons at once, in one pass over one document.
    #[test]
    fn the_two_reasons_to_drop_a_version_compose() {
        let out = filter_refusing(MIXED, &policy(&[], &[]), &refusing(&["1.0.0"]));

        assert_eq!(
            out.removed,
            ["1.0.0", "1.0.1", "1.0.2"],
            "one by policy and two off-origin"
        );
        assert_eq!(out.rewritten, 0);
    }

    /// With the origin check off, an off-origin version stays and is left as
    /// published, and only the policy removes anything.
    #[test]
    fn keeping_off_origin_versions_still_lets_policy_remove_one() {
        let p = normalize_packument(MIXED.as_bytes(), DocumentDetail::Abbreviated)
            .expect("should normalise");
        let artifacts: Vec<(String, String)> = p
            .records
            .iter()
            .map(|r| {
                (
                    r.package.version().to_owned(),
                    r.artifact().expect("one file").url.clone(),
                )
            })
            .collect();
        let out = filter_unservable_versions(
            MIXED.as_bytes(),
            artifacts,
            &policy(&[], &[]),
            &refusing(&["1.0.0"]),
            false,
            PROXY,
        )
        .expect("should filter");

        assert_eq!(out.removed, ["1.0.0"]);
        assert_eq!(
            out.allowed, 2,
            "both off-origin versions are kept as published"
        );
    }

    /// The only control that works on an off-origin artifact: the client fetches it
    /// from whatever host the packument names, so refusing the artifact request never
    /// happens. Dropping the version is what decision #4 settles for quarantine.
    #[test]
    fn versions_the_proxy_cannot_serve_are_removed() {
        let out = filter(MIXED, &policy(&[], &[]));
        assert_eq!(out.removed, ["1.0.1", "1.0.2"]);
        assert_eq!(out.rewritten, 1);

        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        let versions = v["versions"].as_object().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions["1.0.0"]["dist"]["tarball"],
            serde_json::json!("http://127.0.0.1:8080/w/-/w-1.0.0.tgz"),
            "what is left still points at the proxy"
        );
    }

    /// Three states, not two. Before the allow list the only escape from a refusal
    /// was turning refusing off everywhere, which trades one origin's exemption for
    /// every origin's.
    #[test]
    fn an_allowed_origin_is_kept_exactly_as_published() {
        let out = filter(MIXED, &policy(&[], &["https://elsewhere.example"]));
        assert!(out.removed.is_empty(), "allowed, so nothing is removed");
        assert_eq!(out.allowed, 2);
        assert_eq!(
            out.rewritten, 1,
            "the servable one still points at the proxy"
        );

        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["versions"]["1.0.1"]["dist"]["tarball"],
            serde_json::json!("https://elsewhere.example/w-1.0.1.tgz"),
            "left where the registry published it, which is the point of allowing it"
        );
        assert_eq!(v["dist-tags"]["latest"], serde_json::json!("1.0.2"));
    }

    /// Served, allowed and refused are distinguished, and an unparseable URL is
    /// refused under its own text: it names no origin that could be served or
    /// allowed, and an artifact that cannot be located cannot be examined.
    #[test]
    fn the_policy_distinguishes_all_three_states() {
        let p = policy(&["https://cdn.example"], &["https://allowed.example"]);
        assert_eq!(
            p.disposition("https://registry.npmjs.org/a/-/a-1.0.0.tgz"),
            Disposition::Served
        );
        assert_eq!(
            p.disposition("https://cdn.example/a-1.0.0.tgz"),
            Disposition::Served
        );
        assert_eq!(
            p.disposition("https://allowed.example/a-1.0.0.tgz"),
            Disposition::AllowedDirect("https://allowed.example".into())
        );
        assert_eq!(
            p.disposition("https://elsewhere.example/a-1.0.0.tgz"),
            Disposition::Refused("https://elsewhere.example".into())
        );
        assert_eq!(
            p.disposition("not a url"),
            Disposition::Refused("not a url".into())
        );
    }

    /// An accepted gap has to stay countable, or it stops being reported and outlives
    /// the reason it was added.
    #[test]
    fn allowed_and_refused_origins_are_counted_separately() {
        let doc = normalize_packument(MIXED.as_bytes(), DocumentDetail::Abbreviated).unwrap();

        let (allowed, refused) = doc.unserved_origins(&policy(&[], &[]));
        assert!(allowed.is_empty());
        assert_eq!(refused.get("https://elsewhere.example"), Some(&2));

        let (allowed, refused) = doc.unserved_origins(&policy(&[], &["https://elsewhere.example"]));
        assert_eq!(allowed.get("https://elsewhere.example"), Some(&2));
        assert!(refused.is_empty());
    }

    /// An origin the proxy serves is not "allowed direct" as well: serving it means
    /// the proxy sees it, which is the opposite of the exemption.
    #[test]
    fn serving_an_origin_wins_over_allowing_it() {
        let p = policy(&["https://both.example"], &["https://both.example"]);
        assert_eq!(
            p.disposition("https://both.example/a-1.0.0.tgz"),
            Disposition::Served
        );
    }

    #[test]
    fn an_unusable_allowed_origin_is_an_error() {
        let result = OriginPolicy::new(origins(&[]), ["ftp://nope.example"]);
        let Err(e) = result else {
            panic!("ftp is not an origin this can serve or reason about");
        };
        assert_eq!(e.reason, "scheme is not http or https");
    }

    /// When nothing survives, the document still has to be the filtered one. An
    /// empty `versions` map says there is no installable version; forwarding the
    /// original would put every refused version straight back.
    #[test]
    fn a_document_where_nothing_survives_is_still_filtered() {
        let json = r#"{"name":"w","dist-tags":{"latest":"1.0.0"},"versions":{
            "1.0.0":{"version":"1.0.0","dist":{"tarball":"https://elsewhere.example/w-1.0.0.tgz"}}}}"#;
        let out = filter(json, &policy(&[], &[]));
        assert_eq!(out.removed, ["1.0.0"]);
        assert_eq!(out.rewritten, 0);

        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert!(v["versions"].as_object().unwrap().is_empty());
        assert!(v["dist-tags"].as_object().unwrap().is_empty());
    }

    /// A tag naming a version that is gone resolves to nothing. Dropping the tag lets
    /// the resolver fall back to one that is still there.
    #[test]
    fn tags_pointing_at_removed_versions_are_dropped() {
        let out = filter(MIXED, &policy(&[], &[]));
        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        let tags = v["dist-tags"].as_object().unwrap();
        assert!(
            !tags.contains_key("latest"),
            "latest named a removed version"
        );
        assert_eq!(
            tags["old"],
            serde_json::json!("1.0.0"),
            "this one still resolves"
        );
    }

    /// Configuring the origin makes the same document install in full.
    #[test]
    fn configuring_the_origin_keeps_every_version() {
        let out = filter(MIXED, &policy(&["https://elsewhere.example"], &[]));
        assert!(out.removed.is_empty());
        assert_eq!(out.rewritten, 3);

        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(v["versions"].as_object().unwrap().len(), 3);
        assert_eq!(v["dist-tags"]["latest"], serde_json::json!("1.0.2"));
    }

    /// A version with no artifact produces no record, so nothing can install it. It is
    /// left alone rather than removed, so this does not become two behaviours.
    #[test]
    fn versions_without_an_artifact_are_left_alone() {
        let json = r#"{"name":"w","versions":{
            "1.0.0":{"version":"1.0.0"},
            "1.0.1":{"version":"1.0.1","dist":{"tarball":"https://registry.npmjs.org/w/-/w-1.0.1.tgz"}}}}"#;
        let out = filter(json, &policy(&[], &[]));
        assert!(out.removed.is_empty());

        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(v["versions"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn filtering_a_body_that_is_not_json_is_an_error() {
        let result = filter_unservable_versions(
            b"<html>",
            std::iter::empty(),
            &policy(&[], &[]),
            &HashSet::new(),
            true,
            PROXY,
        );
        assert!(matches!(result, Err(RewriteError::NotJson(_))));
    }

    /// npm's `_resolved` repeats `dist.tarball` verbatim. A rewrite that only touched
    /// `dist.tarball` would leave it pointing at the registry. Measured in the corpus:
    /// 2 of 49,704 URLs appear twice, both this way.
    #[test]
    fn a_url_repeated_elsewhere_is_rewritten_everywhere() {
        let out = rewrite(
            r#"{"name":"react","versions":{"1.0.0":{"version":"1.0.0",
                "_resolved":"https://registry.npmjs.org/react/-/react-1.0.0.tgz",
                "dist":{"tarball":"https://registry.npmjs.org/react/-/react-1.0.0.tgz"}}}}"#,
        );
        assert_eq!(out.rewritten, 1, "one distinct URL");
        assert_eq!(out.occurrences, 2, "changed in both places");

        let text = String::from_utf8(out.body).unwrap();
        assert!(!text.contains("registry.npmjs.org/react"), "got: {text}");
        assert_eq!(
            text.matches("http://127.0.0.1:8080/react/-/react-1.0.0.tgz")
                .count(),
            2
        );
    }

    /// Other strings on the same origin are not artifacts and must survive. Only the
    /// URLs the records named are replaced.
    #[test]
    fn other_urls_on_the_same_origin_are_untouched() {
        let out = rewrite(
            r#"{"name":"w","homepage":"https://registry.npmjs.org/w",
                "bugs":{"url":"https://registry.npmjs.org/-/issues"},
                "versions":{"1.0.0":{"version":"1.0.0","dist":{
                    "tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz"}}}}"#,
        );
        assert_eq!(out.occurrences, 1);
        let text = String::from_utf8(out.body).unwrap();
        assert!(
            text.contains(r#""homepage":"https://registry.npmjs.org/w""#),
            "got: {text}"
        );
        assert!(
            text.contains(r#""url":"https://registry.npmjs.org/-/issues""#),
            "got: {text}"
        );
    }

    /// A URL that only appears as part of a longer string is not a whole JSON string,
    /// so it is not an artifact reference and is left alone.
    #[test]
    fn a_url_embedded_in_prose_is_not_rewritten() {
        let out = rewrite(
            r#"{"name":"w",
                "description":"download it from https://registry.npmjs.org/w/-/w-1.0.0.tgz today",
                "versions":{"1.0.0":{"version":"1.0.0","dist":{
                    "tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz"}}}}"#,
        );
        assert_eq!(out.occurrences, 1, "only the artifact reference");
        let text = String::from_utf8(out.body).unwrap();
        assert!(
            text.contains("download it from https://registry.npmjs.org/w/-/w-1.0.0.tgz today"),
            "prose was rewritten: {text}"
        );
    }

    /// Everything the rewrite does not change has to come through byte for byte. This
    /// is what re-serialising could not promise.
    #[test]
    fn the_document_is_unchanged_apart_from_the_urls() {
        let original = fixture("@babel_traverse-8.0.5.full.json");
        let out = rewrite_with(&original, &origins(&[]), PROXY);
        assert_eq!(out.rewritten, 1);

        let restored = String::from_utf8(out.body).unwrap().replace(
            "http://127.0.0.1:8080/@babel/traverse/-/traverse-8.0.5.tgz",
            "https://registry.npmjs.org/@babel/traverse/-/traverse-8.0.5.tgz",
        );
        assert_eq!(
            restored.as_bytes(),
            original.as_slice(),
            "putting the URL back should give the original bytes"
        );
    }

    /// A document whose artifact URLs are not there to be found is refused outright.
    /// Half a rewrite would send some artifacts to the proxy and leave the rest
    /// pointing at the registry.
    #[test]
    fn a_url_that_cannot_be_found_fails_the_whole_rewrite() {
        let absent = ["https://registry.npmjs.org/ghost/-/ghost-1.0.0.tgz"];
        let result = rewrite_artifact_origins(
            br#"{"name":"w","versions":{}}"#,
            absent,
            &origins(&[]),
            PROXY,
        );
        let Err(e) = result else {
            panic!("a URL that is not in the document cannot be rewritten");
        };
        assert!(matches!(
            e,
            RewriteError::Incomplete {
                expected: 1,
                found: 0
            }
        ));
        assert!(e.to_string().contains("found 0 of 1"), "got: {e}");
    }

    #[test]
    fn a_body_that_is_not_utf8_is_an_error() {
        let result =
            rewrite_artifact_origins(&[0xff, 0xfe], std::iter::empty(), &origins(&[]), PROXY);
        assert!(matches!(result, Err(RewriteError::NotUtf8(_))));
    }

    /// A trailing slash on the base must not produce a doubled one in the URL.
    #[test]
    fn a_trailing_slash_on_the_base_does_not_double_up() {
        let out = rewrite_with(
            br#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0","dist":{
                "tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz"}}}}"#,
            &origins(&[]),
            "http://127.0.0.1:8080/",
        );
        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["versions"]["1.0.0"]["dist"]["tarball"],
            serde_json::json!("http://127.0.0.1:8080/w/-/w-1.0.0.tgz")
        );
    }

    /// A rewritten URL has to classify back to the package it came from, or the
    /// artifact request arrives as something the proxy does not recognise.
    #[test]
    fn a_rewritten_url_still_classifies_as_its_own_artifact() {
        let out = rewrite(
            r#"{"name":"@babel/core","versions":{"7.0.0":{"version":"7.0.0","dist":{
                "tarball":"https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz"}}}}"#,
        );
        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        let url = v["versions"]["7.0.0"]["dist"]["tarball"].as_str().unwrap();
        let path = url.strip_prefix(PROXY).unwrap();

        assert_eq!(
            classify_path(path),
            RequestTarget::Artifact {
                key: PackageKey::from_registry_name(Ecosystem::Npm, "@babel/core").unwrap(),
                claimed_version: "7.0.0".into(),
                filename: "core-7.0.0.tgz".into()
            }
        );
    }
}
