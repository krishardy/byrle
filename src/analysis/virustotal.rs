//! VirusTotal's answer about an artifact, by the SHA-256 of its verified bytes: the client,
//! what is stored, and the limiter that keeps every request within the quota. Report only.
//! See docs/engineering_decisions/virustotal.md.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::StreamExt as _;
use reqwest::StatusCode;
use serde::Deserialize;

/// The API's base URL, unless [`crate::env::VIRUSTOTAL_URL`] names another.
pub const API: &str = "https://www.virustotal.com/api/v3";

/// The largest file `POST /files` takes; a larger one goes through `/files/upload_url`.
pub const DIRECT_UPLOAD_BYTES: u64 = 32 * 1024 * 1024;

/// The largest file VirusTotal takes at all. A larger one is looked up only.
pub const MAX_UPLOAD_BYTES: u64 = 650 * 1024 * 1024;

/// The public API's quota: requests a minute.
pub const PUBLIC_PER_MINUTE: u32 = 4;

/// The public API's quota: requests a day.
pub const PUBLIC_PER_DAY: u32 = 500;

/// The origins an artifact may be uploaded from: public registries, with no credential.
pub const PUBLIC_ORIGINS: [&str; 3] = [
    "https://registry.npmjs.org/",
    "https://files.pythonhosted.org/",
    "https://pypi.org/",
];

const MINUTE: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(86_400);

/// Whether VirusTotal is asked by hash only, or also sent a file it does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Hash,
    Upload,
}

impl Mode {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "hash" => Some(Self::Hash),
            "upload" => Some(Self::Upload),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Upload => "upload",
        }
    }
}

/// How VirusTotal is reached and how often, from the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub key: String,
    pub mode: Mode,
    pub base: String,
    pub per_minute: u32,
    pub per_day: u32,
    /// The URL prefixes an artifact may be uploaded from: [`PUBLIC_ORIGINS`].
    pub uploads_from: Vec<String>,
}

/// Whether an artifact at `url` may be uploaded: it starts with one of `origins`, which
/// leaves no room for user information. Anything else is looked up by hash only.
pub fn uploadable_from(url: &str, origins: &[String]) -> bool {
    origins
        .iter()
        .any(|origin| url.starts_with(origin.as_str()))
}

/// What VirusTotal's engines said about a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub malicious: u32,
    pub suspicious: u32,
    /// Every engine counted, whatever it answered.
    pub engines: u32,
}

impl Counts {
    fn of(stats: &BTreeMap<String, u32>) -> Self {
        let named = |key: &str| stats.get(key).copied().unwrap_or(0);
        Self {
            malicious: named("malicious"),
            suspicious: named("suspicious"),
            engines: stats.values().sum(),
        }
    }
}

/// What is known about a file, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Known(Counts),
    /// VirusTotal had never seen it, and it was not uploaded.
    Unknown,
    /// Uploaded, and the analysis with this id had not finished.
    Queued(String),
}

/// VirusTotal's answer about one artifact, kept under the artifact's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    pub sha256: String,
    pub verdict: Verdict,
    /// When it was asked, in Unix seconds.
    pub asked: i64,
}

impl Scanned {
    /// Whether to ask again at `now`, Unix seconds: a week for counts, a day for a file
    /// VirusTotal did not know, 5 minutes for an analysis still queued.
    pub fn due(&self, now: i64) -> bool {
        let wait = match self.verdict {
            Verdict::Known(_) => 7 * 86_400,
            Verdict::Unknown => 86_400,
            Verdict::Queued(_) => 300,
        };
        now - self.asked >= wait
    }
}

/// Why a request was not answered. The key is never part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// 429: the quota is spent.
    Quota,
    /// 401 or 403: the key was refused.
    Key,
    /// Anything else, and what it was.
    Other(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quota => write!(f, "VirusTotal's quota is spent"),
            Self::Key => write!(f, "VirusTotal refused {}", crate::env::VIRUSTOTAL_API_KEY),
            Self::Other(why) => write!(f, "VirusTotal: {why}"),
        }
    }
}

#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Deserialize)]
struct Attributed<T> {
    attributes: T,
}

#[derive(Deserialize)]
struct FileAttributes {
    last_analysis_stats: BTreeMap<String, u32>,
}

#[derive(Deserialize)]
struct Identified {
    id: String,
}

#[derive(Deserialize)]
struct AnalysisAttributes {
    status: String,
    stats: BTreeMap<String, u32>,
}

/// One request at a time to VirusTotal's API. The caller asks the [`Limiter`] first.
pub struct Client {
    http: reqwest::Client,
    base: String,
    key: String,
}

impl Client {
    /// A client for the API at `settings.base` with `settings.key`, sending through `http`.
    pub fn new(http: reqwest::Client, settings: &Settings) -> Self {
        Self {
            http,
            base: settings.base.trim_end_matches('/').to_owned(),
            key: settings.key.clone(),
        }
    }

    /// What VirusTotal's engines said about the file with `sha256`.
    /// Returns `None` for a file it has never seen.
    /// Errors with why it did not answer.
    pub async fn lookup(&self, sha256: &str) -> Result<Option<Counts>, Failure> {
        let response = self.get(&format!("{}/files/{sha256}", self.base)).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let file: Envelope<Attributed<FileAttributes>> = json(answered(response)?).await?;
        Ok(Some(Counts::of(&file.data.attributes.last_analysis_stats)))
    }

    /// Where to upload a file larger than [`DIRECT_UPLOAD_BYTES`].
    /// Errors with why it did not answer.
    pub async fn upload_url(&self) -> Result<String, Failure> {
        let response = answered(self.get(&format!("{}/files/upload_url", self.base)).await?)?;
        Ok(json::<Envelope<String>>(response).await?.data)
    }

    /// Upload `file`, `len` bytes, as `name` to `to`: `/files`, or an [`Client::upload_url`].
    /// Returns the analysis id. Errors with why it did not answer.
    pub async fn upload(
        &self,
        to: Option<&str>,
        file: std::fs::File,
        len: u64,
        name: &str,
    ) -> Result<String, Failure> {
        let boundary = format!("byrle-{}", crate::util::hex(&random()));
        let head = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n",
            name.replace(['"', '\r', '\n'], "_")
        );
        let tail = format!("\r\n--{boundary}--\r\n");
        let length = head.len() as u64 + len + tail.len() as u64;
        let body = futures_util::stream::iter([Ok(Bytes::from(head))])
            .chain(file_stream(tokio::fs::File::from_std(file)))
            .chain(futures_util::stream::iter([Ok(Bytes::from(tail))]));
        let default = format!("{}/files", self.base);
        let response = self
            .http
            .post(to.unwrap_or(&default))
            .header("x-apikey", &self.key)
            .header(
                reqwest::header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header(reqwest::header::CONTENT_LENGTH, length)
            .body(reqwest::Body::wrap_stream(body))
            .send()
            .await
            .map_err(sent)?;
        let id: Envelope<Identified> = json(answered(response)?).await?;
        Ok(id.data.id)
    }

    /// The counts of the analysis with `id`. Returns `None` while it is not completed.
    /// Errors with why it did not answer.
    pub async fn analysis(&self, id: &str) -> Result<Option<Counts>, Failure> {
        let response = answered(self.get(&format!("{}/analyses/{id}", self.base)).await?)?;
        let analysis: Envelope<Attributed<AnalysisAttributes>> = json(response).await?;
        let attributes = analysis.data.attributes;
        Ok((attributes.status == "completed").then(|| Counts::of(&attributes.stats)))
    }

    async fn get(&self, url: &str) -> Result<reqwest::Response, Failure> {
        self.http
            .get(url)
            .header("x-apikey", &self.key)
            .send()
            .await
            .map_err(sent)
    }
}

/// `file` read in chunks, as a body.
fn file_stream(
    file: tokio::fs::File,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    futures_util::stream::unfold(file, |mut file| async move {
        use tokio::io::AsyncReadExt as _;
        let mut chunk = vec![0; 64 * 1024];
        match file.read(&mut chunk).await {
            Ok(0) => None,
            Ok(read) => {
                chunk.truncate(read);
                Some((Ok(Bytes::from(chunk)), file))
            }
            Err(e) => Some((Err(e), file)),
        }
    })
}

fn random() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the operating system supplies random bytes");
    bytes
}

/// A request that could not be sent, without its URL, which holds no secret but is long.
fn sent(error: reqwest::Error) -> Failure {
    Failure::Other(format!("not answered: {}", error.without_url()))
}

/// `response` when it is a success. Errors with the failure its status means.
fn answered(response: reqwest::Response) -> Result<reqwest::Response, Failure> {
    match response.status() {
        status if status.is_success() => Ok(response),
        StatusCode::TOO_MANY_REQUESTS => Err(Failure::Quota),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(Failure::Key),
        status => Err(Failure::Other(format!("answered {}", status.as_u16()))),
    }
}

/// `response`'s body read as `T`. Errors when it is not.
async fn json<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T, Failure> {
    let body = response
        .bytes()
        .await
        .map_err(|e| Failure::Other(format!("body not read: {e}")))?;
    serde_json::from_slice(&body).map_err(|e| Failure::Other(format!("body not understood: {e}")))
}

/// The requests made in the last minute and day, held below their limits.
pub struct Limiter {
    per_minute: usize,
    per_day: usize,
    minute: Duration,
    day: Duration,
    pub(crate) asked: tokio::sync::Mutex<VecDeque<Instant>>,
}

impl Limiter {
    /// `per_minute` and `per_day` requests, with `asked`, how many seconds ago each request
    /// in the last day was made, already counted.
    pub fn new(per_minute: u32, per_day: u32, asked: &[u64]) -> Self {
        Self::windows(per_minute, per_day, MINUTE, DAY, asked)
    }

    /// [`Limiter::new`] over windows of `minute` and `day`, which a test shortens.
    fn windows(
        per_minute: u32,
        per_day: u32,
        minute: Duration,
        day: Duration,
        asked: &[u64],
    ) -> Self {
        let now = Instant::now();
        let mut held: Vec<Instant> = asked
            .iter()
            .filter_map(|ago| now.checked_sub(Duration::from_secs(*ago)))
            .collect();
        held.sort();
        Self {
            per_minute: per_minute as usize,
            per_day: per_day as usize,
            minute,
            day,
            asked: tokio::sync::Mutex::new(held.into()),
        }
    }

    /// Wait until a request fits under both limits, and count it.
    pub async fn ask(&self) {
        loop {
            let mut asked = self.asked.lock().await;
            let now = Instant::now();
            while asked.front().is_some_and(|at| now - *at >= self.day) {
                asked.pop_front();
            }
            let in_minute: Vec<Instant> = asked
                .iter()
                .copied()
                .filter(|at| now - *at < self.minute)
                .collect();
            let minute_wait = (in_minute.len() >= self.per_minute)
                .then(|| in_minute[in_minute.len() - self.per_minute] + self.minute - now);
            let day_wait = (asked.len() >= self.per_day)
                .then(|| asked[asked.len() - self.per_day] + self.day - now);
            match minute_wait.max(day_wait) {
                None => {
                    asked.push_back(now);
                    return;
                }
                Some(wait) => {
                    drop(asked);
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }
}

/// The upload's name for an artifact at `url`: its last path segment.
pub fn file_name(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or(url)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::util::test_support::{Answer, recorded, scripted, tempdir};

    /// A key no scanner reads as a credential.
    pub const KEY: &str = "test-key";

    pub fn settings(base: String) -> Settings {
        Settings {
            key: KEY.to_owned(),
            mode: Mode::Hash,
            base,
            per_minute: PUBLIC_PER_MINUTE,
            per_day: PUBLIC_PER_DAY,
            uploads_from: PUBLIC_ORIGINS.map(str::to_owned).to_vec(),
        }
    }

    fn client(addr: std::net::SocketAddr) -> Client {
        Client::new(reqwest::Client::new(), &settings(format!("http://{addr}/")))
    }

    /// A file object whose last analysis counted these.
    pub fn file(malicious: u32, suspicious: u32, undetected: u32) -> Vec<u8> {
        format!(
            r#"{{"data":{{"id":"x","type":"file","attributes":{{"last_analysis_stats":
            {{"malicious":{malicious},"suspicious":{suspicious},"undetected":{undetected},"harmless":0}}}}}}}}"#
        )
        .into_bytes()
    }

    pub fn analysis(status: &str, malicious: u32) -> Vec<u8> {
        format!(
            r#"{{"data":{{"id":"an-1","type":"analysis","attributes":{{"status":"{status}",
            "stats":{{"malicious":{malicious},"suspicious":0,"undetected":9}}}}}}}}"#
        )
        .into_bytes()
    }

    pub const UPLOADED: &[u8] = br#"{"data":{"type":"analysis","id":"an-1"}}"#;

    fn text(request: &[u8]) -> String {
        String::from_utf8_lossy(request).into_owned()
    }

    #[test]
    fn a_mode_is_hash_or_upload_and_an_origin_must_be_listed() {
        assert_eq!(Mode::parse("hash"), Some(Mode::Hash));
        assert_eq!(Mode::parse("upload"), Some(Mode::Upload));
        assert_eq!(Mode::parse("Upload"), None);
        assert_eq!(
            (Mode::Hash.as_str(), Mode::Upload.as_str()),
            ("hash", "upload")
        );
        let public = PUBLIC_ORIGINS.map(str::to_owned).to_vec();
        assert!(uploadable_from(
            "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
            &public
        ));
        assert!(uploadable_from(
            "https://files.pythonhosted.org/packages/x.whl",
            &public
        ));
        assert!(!uploadable_from(
            "https://u:p@registry.npmjs.org/a/-/a-1.0.0.tgz",
            &public
        ));
        assert!(!uploadable_from(
            "https://registry.npmjs.org.evil.test/a.tgz",
            &public
        ));
        assert!(!uploadable_from(
            "https://npm.mycompany.test/a.tgz",
            &public
        ));
        assert_eq!(file_name("https://r.test/a/-/a-1.0.0.tgz"), "a-1.0.0.tgz");
    }

    /// Counts sum every engine, and a key the answer lacks counts 0.
    #[test]
    fn counts_and_when_to_ask_again() {
        let stats: BTreeMap<String, u32> =
            [("malicious".to_owned(), 2), ("timeout".to_owned(), 5)].into();
        assert_eq!(
            Counts::of(&stats),
            Counts {
                malicious: 2,
                suspicious: 0,
                engines: 7
            }
        );
        let asked = |verdict| Scanned {
            sha256: String::new(),
            verdict,
            asked: 1000,
        };
        let known = asked(Verdict::Known(Counts::of(&stats)));
        assert!(!known.due(1000 + 7 * 86_400 - 1));
        assert!(known.due(1000 + 7 * 86_400));
        assert!(!asked(Verdict::Unknown).due(1000 + 86_399));
        assert!(asked(Verdict::Unknown).due(1000 + 86_400));
        assert!(!asked(Verdict::Queued("a".to_owned())).due(1299));
        assert!(asked(Verdict::Queued("a".to_owned())).due(1300));
    }

    /// No failure names the key itself.
    #[test]
    fn a_failure_says_what_it_was_and_never_the_key() {
        assert_eq!(Failure::Quota.to_string(), "VirusTotal's quota is spent");
        assert_eq!(
            Failure::Key.to_string(),
            format!("VirusTotal refused {}", crate::env::VIRUSTOTAL_API_KEY)
        );
        assert_eq!(
            Failure::Other("why".to_owned()).to_string(),
            "VirusTotal: why"
        );
    }

    /// The hash is looked up with the key in `x-apikey`; each status is told apart.
    #[tokio::test]
    async fn a_lookup_reads_the_counts_or_says_why_not() {
        let (addr, requests) = recorded(vec![Answer::body(file(3, 1, 60))]).await;
        let counts = client(addr).lookup("ab12").await.expect("answers");
        assert_eq!(
            counts,
            Some(Counts {
                malicious: 3,
                suspicious: 1,
                engines: 64
            })
        );
        let request = text(&requests.lock().unwrap()[0]);
        assert!(request.starts_with("GET /files/ab12 "), "{request}");
        assert!(request.contains(&format!("x-apikey: {KEY}")), "{request}");

        let asked =
            |answer| async move { client(scripted(vec![answer]).await).lookup("ab12").await };
        assert_eq!(asked(Answer::Status(404)).await, Ok(None));
        assert_eq!(asked(Answer::Status(429)).await, Err(Failure::Quota));
        assert_eq!(asked(Answer::Status(401)).await, Err(Failure::Key));
        assert_eq!(asked(Answer::Status(403)).await, Err(Failure::Key));
        assert_eq!(
            asked(Answer::Status(500)).await,
            Err(Failure::Other("answered 500".to_owned()))
        );
        let garbled = asked(Answer::body(b"not json".to_vec())).await;
        assert!(
            matches!(&garbled, Err(Failure::Other(why)) if why.starts_with("body not understood")),
            "{garbled:?}"
        );
        let cut = asked(Answer::cut_short()).await;
        assert!(
            matches!(&cut, Err(Failure::Other(why)) if why.starts_with("body not read")),
            "{cut:?}"
        );
        let closed = asked(Answer::Close).await;
        assert!(
            matches!(&closed, Err(Failure::Other(why)) if why.starts_with("not answered")),
            "{closed:?}"
        );
    }

    /// The file goes as the `file` field of a multipart body, to `/files` or the URL given.
    #[tokio::test]
    async fn an_upload_sends_the_file_as_multipart_and_reads_the_analysis_id() {
        let dir = tempdir("virustotal-upload");
        let path = dir.join("artifact");
        std::fs::write(&path, b"the artifact bytes").unwrap();
        let open = || std::fs::File::open(&path).unwrap();

        let (addr, requests) = recorded(vec![Answer::body(UPLOADED.to_vec())]).await;
        let id = client(addr)
            .upload(None, open(), 18, "a\"b.tgz")
            .await
            .expect("answers");
        assert_eq!(id, "an-1");
        let request = text(&requests.lock().unwrap()[0]);
        assert!(request.starts_with("POST /files "), "{request}");
        assert!(request.contains(&format!("x-apikey: {KEY}")), "{request}");
        assert!(
            request.contains("content-type: multipart/form-data; boundary=byrle-"),
            "{request}"
        );
        assert!(
            request.contains("name=\"file\"; filename=\"a_b.tgz\""),
            "{request}"
        );
        assert!(
            request.contains("\r\n\r\nthe artifact bytes\r\n--byrle-"),
            "{request}"
        );

        let (addr, requests) = recorded(vec![Answer::body(UPLOADED.to_vec())]).await;
        let to = format!("http://{addr}/upload-here");
        client(addr)
            .upload(Some(&to), open(), 18, "a.tgz")
            .await
            .expect("answers");
        let request = text(&requests.lock().unwrap()[0]);
        assert!(request.starts_with("POST /upload-here "), "{request}");

        let refused = client(scripted(vec![Answer::Status(429)]).await)
            .upload(None, open(), 18, "a.tgz")
            .await;
        assert_eq!(refused, Err(Failure::Quota));
        let closed = client(scripted(vec![Answer::Close]).await)
            .upload(None, open(), 18, "a.tgz")
            .await;
        assert!(matches!(closed, Err(Failure::Other(_))), "{closed:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_upload_url_and_an_analysis_are_read() {
        let (addr, requests) = recorded(vec![Answer::body(
            br#"{"data":"https://up.test/x"}"#.to_vec(),
        )])
        .await;
        assert_eq!(
            client(addr).upload_url().await,
            Ok("https://up.test/x".to_owned())
        );
        assert!(text(&requests.lock().unwrap()[0]).starts_with("GET /files/upload_url "));
        assert_eq!(
            client(scripted(vec![Answer::Status(401)]).await)
                .upload_url()
                .await,
            Err(Failure::Key)
        );

        let (addr, requests) = recorded(vec![Answer::body(analysis("completed", 2))]).await;
        assert_eq!(
            client(addr).analysis("an-1").await,
            Ok(Some(Counts {
                malicious: 2,
                suspicious: 0,
                engines: 11
            }))
        );
        assert!(text(&requests.lock().unwrap()[0]).starts_with("GET /analyses/an-1 "));
        let queued = client(scripted(vec![Answer::body(analysis("queued", 0))]).await);
        assert_eq!(queued.analysis("an-1").await, Ok(None));
        assert_eq!(
            client(scripted(vec![Answer::Status(429)]).await)
                .analysis("an-1")
                .await,
            Err(Failure::Quota)
        );
        for answer in [Answer::Close, Answer::body(b"not json".to_vec())] {
            let failing = client(scripted(vec![answer]).await);
            assert!(matches!(failing.upload_url().await, Err(Failure::Other(_))));
            assert!(matches!(
                failing.analysis("an-1").await,
                Err(Failure::Other(_))
            ));
        }
    }

    /// A file that cannot be read ends the upload's body with the error.
    #[tokio::test]
    async fn a_file_that_cannot_be_read_ends_the_body_with_an_error() {
        let dir = tempdir("virustotal-unreadable");
        let path = dir.join("artifact");
        let write_only = std::fs::File::create(&path).unwrap();
        let mut chunks = std::pin::pin!(file_stream(tokio::fs::File::from_std(write_only)));
        assert!(matches!(chunks.next().await, Some(Err(_))));
        std::fs::write(&path, b"x").unwrap();
        let garbled = client(scripted(vec![Answer::body(b"not json".to_vec())]).await)
            .upload(None, std::fs::File::open(&path).unwrap(), 1, "a.tgz")
            .await;
        assert!(matches!(garbled, Err(Failure::Other(_))), "{garbled:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A request waits while the minute's or the day's limit is reached, counting the
    /// requests a restart was told of.
    #[tokio::test]
    async fn the_limiter_holds_requests_to_both_limits() {
        let short = Duration::from_millis(80);
        let long = Duration::from_millis(300);
        let minute = Limiter::windows(2, 10, short, long, &[]);
        let start = Instant::now();
        minute.ask().await;
        minute.ask().await;
        assert!(start.elapsed() < short, "two fit in the minute");
        minute.ask().await;
        assert!(start.elapsed() >= short, "the third waits for the minute");

        let day = Limiter::windows(10, 2, short, long, &[0]);
        let start = Instant::now();
        day.ask().await;
        assert!(start.elapsed() < short, "one more fits in the day");
        day.ask().await;
        assert!(
            start.elapsed() >= long - short,
            "the day's limit waits for the oldest"
        );

        let seeded = Limiter::new(4, 500, &[10, 20, u64::MAX]);
        assert_eq!(
            seeded.asked.lock().await.len(),
            2,
            "one too old to place is dropped"
        );
    }
}
