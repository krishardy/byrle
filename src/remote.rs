//! The analysis commands asked of a deployed byrle's console when [`crate::env::REMOTE_URL`]
//! is set, and what its routes answer. See
//! docs/engineering_decisions/0118-remote-analysis-commands.md.

use std::ffi::OsString;

use serde::{Deserialize, Serialize};

use crate::env::{DATABASE_URL, Env, POLICY, REMOTE_URL, TOKEN};

/// What a command printed on the deployment, and the code it exited with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Printed {
    pub stdout: String,
    pub stderr: String,
    pub code: u8,
}

impl Printed {
    /// `stdout` and `code`, with each of `notes` as `byrle <command>` prints one.
    pub fn of(command: &str, notes: &[String], stdout: String, code: u8) -> Self {
        Self {
            stdout,
            stderr: notes
                .iter()
                .map(|note| format!("byrle {command}: {note}\n"))
                .collect(),
            code,
        }
    }

    /// Stopped before the deployment answered, saying `why`.
    fn stopped(command: &str, why: &str) -> Self {
        Self::of(command, &[why.to_owned()], String::new(), 2)
    }

    /// Print it, and return the code to exit with.
    pub fn print(&self) -> u8 {
        eprint!("{}", self.stderr);
        print!("{}", self.stdout);
        self.code
    }
}

/// A deployment the commands ask, and the client that sends its token.
pub struct Remote {
    base: String,
    http: reqwest::Client,
    /// The local inputs set, which a remote command does not read.
    ignored: Vec<&'static str>,
}

impl Remote {
    /// The deployment `environment` names, `None` when [`REMOTE_URL`] is unset. Errors when
    /// it is not https, or http to loopback, as the token is sent to it, or no token is set.
    pub fn from_env<L: Fn(&str) -> Option<OsString>>(
        environment: &Env<L>,
    ) -> Result<Option<Self>, String> {
        let Some((url, _)) = environment.remote_url().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let secure =
            reqwest::Url::parse(&url).is_ok_and(|parsed| crate::http::secure_or_loopback(&parsed));
        if !secure {
            return Err(format!(
                "{REMOTE_URL} is {url}: the token is sent to it, so it is https, or http to \
                 loopback"
            ));
        }
        let token = environment.token().map_err(|e| e.to_string())?;
        let Some(token) = token else {
            return Err(format!(
                "{REMOTE_URL} is set and {TOKEN} is not: set it to a token from `byrle token \
                 create`"
            ));
        };
        Ok(Some(Self {
            base: url.trim_end_matches('/').to_owned(),
            http: crate::http::token_client(Some(token))?,
            ignored: [POLICY, DATABASE_URL]
                .into_iter()
                .filter(|var| environment.is_set(*var))
                .map(|var| var.name)
                .collect(),
        }))
    }

    /// What `command` printed on the deployment, asked as `GET path?query`.
    pub async fn get(&self, command: &str, path: &str, query: &[(&str, String)]) -> Printed {
        let mut url = reqwest::Url::parse(&format!("{}{path}", self.base))
            .expect("a URL that parsed with a path appended parses");
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let shown = format!("{}{path}", self.base);
        self.printed(command, &shown, self.http.get(url)).await
    }

    /// The answer to `request`, sent to `url`, with a note for each local input not read.
    async fn printed(&self, command: &str, url: &str, request: reqwest::RequestBuilder) -> Printed {
        let mut printed = match request.send().await {
            Err(e) => Printed::stopped(command, &format!("{url} did not answer: {e}")),
            Ok(response) => {
                let status = response.status();
                let body = response.bytes().await.unwrap_or_default();
                if status.is_success() {
                    serde_json::from_slice::<Printed>(&body).unwrap_or_else(|e| {
                        Printed::stopped(
                            command,
                            &format!("{url} answered with no command's output: {e}"),
                        )
                    })
                } else {
                    let error = serde_json::from_slice::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|body| body["error"].as_str().map(str::to_owned))
                        .unwrap_or_default();
                    Printed::stopped(command, &format!("{url} answered {status}: {error}"))
                }
            }
        };
        let notes: String = self
            .ignored
            .iter()
            .map(|var| {
                format!("byrle {command}: {var} is not read: {REMOTE_URL} is set, so the deployment answers\n")
            })
            .collect();
        printed.stderr = notes + &printed.stderr;
        printed
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::env::testing::with;

    /// Unset, the commands run here; set, the URL is https or loopback and a token is set.
    #[test]
    fn a_deployment_is_named_with_a_token_over_https_or_loopback() {
        assert!(Remote::from_env(&with(&[])).unwrap().is_none());
        let insecure = Remote::from_env(&with(&[
            (REMOTE_URL, "http://h/admin/"),
            (TOKEN, "byrle_t"),
        ]));
        assert!(
            insecure
                .as_ref()
                .err()
                .is_some_and(|e| e.contains("https, or http to loopback")),
            "{:?}",
            insecure.err()
        );
        let tokenless = Remote::from_env(&with(&[(REMOTE_URL, "https://h/admin/")]));
        assert!(
            tokenless
                .as_ref()
                .err()
                .is_some_and(|e| e.contains(&format!("{TOKEN} is not"))),
            "{:?}",
            tokenless.err()
        );
        let bad_header =
            Remote::from_env(&with(&[(REMOTE_URL, "https://h/admin/"), (TOKEN, "a\nb")]));
        assert!(bad_header.is_err());
        for url in ["not a url", "https://u:p@h/admin/"] {
            let refused = Remote::from_env(&with(&[(REMOTE_URL, url), (TOKEN, "t")]));
            assert!(refused.is_err(), "{url}");
        }
        let unreadable: crate::env::Process = Env::from_lookup(Box::new(|name: &str| {
            use std::os::unix::ffi::OsStringExt;
            match name == REMOTE_URL.name {
                true => Some(OsString::from("https://h/admin/")),
                false => Some(OsString::from_vec(vec![0x66, 0xff])),
            }
        }));
        assert!(
            Remote::from_env(&unreadable).is_err(),
            "a token that is not UTF-8"
        );
    }

    /// A local policy or database set is not read, and each says so before the answer; an
    /// answer that is no command's output, and a deployment that does not answer, exit 2.
    #[tokio::test]
    async fn what_is_not_a_commands_output_exits_2() {
        let router = axum::Router::new()
            .route(
                "/admin/printed",
                axum::routing::get(|| async { r#"{"stdout":"out\n","stderr":"","code":1}"# }),
            )
            .route(
                "/admin/garbled",
                axum::routing::get(|| async { "not json" }),
            );
        let base = crate::proxy::testing::serve(router).await;
        let url = format!("{base}/admin/");
        let remote = Remote::from_env(&with(&[
            (REMOTE_URL, &url),
            (TOKEN, "byrle_t"),
            (POLICY, "/etc/byrle/policy.yaml"),
            (DATABASE_URL, "postgres://h/byrle"),
        ]))
        .unwrap()
        .unwrap();
        let printed = remote.get("explain", "/printed", &[]).await;
        assert_eq!((printed.stdout.as_str(), printed.code), ("out\n", 1));
        assert_eq!(printed.print(), 1, "the code to exit with");
        let unread = |var| {
            format!(
                "byrle explain: {var} is not read: {REMOTE_URL} is set, so the deployment \
                 answers\n"
            )
        };
        assert_eq!(printed.stderr, unread(POLICY) + &unread(DATABASE_URL));
        let garbled = remote.get("explain", "/garbled", &[]).await;
        assert_eq!(garbled.code, 2);
        assert!(
            garbled.stderr.contains("answered with no command's output"),
            "{garbled:?}"
        );
        let gone = Remote::from_env(&with(&[(REMOTE_URL, "http://127.0.0.1:9/"), (TOKEN, "t")]))
            .unwrap()
            .unwrap()
            .get("explain", "/printed", &[])
            .await;
        assert_eq!(gone.code, 2);
        assert!(gone.stderr.contains("did not answer"), "{gone:?}");
    }
}
