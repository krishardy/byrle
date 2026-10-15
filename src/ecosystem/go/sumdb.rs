//! Asking Go's checksum database for a module version's `h1:` lines, and believing the
//! answer only when its tree head is signed, the record is proved in that tree, and the tree
//! extends every tree this client saw before. See docs/go-plan.md, Q3.

use std::sync::Mutex;

use super::note::{Tree, Verifier};
use super::paths::escape;
use super::tlog::{self, Fetching, HEIGHT, Hash, Tiles};
use crate::util::lru::Lru;

/// The checksum database the go command asks.
pub const DEFAULT: &str = "https://sum.golang.org";

/// Full tiles kept, each 8 KiB: they never change.
pub const MAX_TILES: usize = 1024;

/// What the checksum database says of a module version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The `h1:` of its zip and of its `go.mod`.
    Known { zip: String, go_mod: String },
    /// It holds no record of it: 404 or 410.
    Unknown,
}

/// A client of one checksum database.
pub struct Client {
    http: reqwest::Client,
    base: String,
    verifier: Verifier,
    /// The largest tree verified so far. Every later one has to extend it.
    latest: tokio::sync::Mutex<Option<Tree>>,
    tiles: Mutex<Lru<(u32, u64), Vec<Hash>>>,
}

/// A tile's path: its index in groups of three digits, all but the last after an `x`.
fn tile_path(level: u32, index: u64, width: u64) -> String {
    let mut n = index;
    let mut path = format!("{:03}", n % 1000);
    while n >= 1000 {
        n /= 1000;
        path = format!("x{:03}/{path}", n % 1000);
    }
    let partial = if width == 1 << HEIGHT {
        String::new()
    } else {
        format!(".p/{width}")
    };
    format!("tile/{HEIGHT}/{level}/{path}{partial}")
}

impl Client {
    /// A client of the database at `base`, whose tree heads `key` signs.
    pub fn new(http: reqwest::Client, base: &str, key: &str) -> Result<Self, String> {
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_owned(),
            verifier: Verifier::parse(key)?,
            latest: tokio::sync::Mutex::new(None),
            tiles: Mutex::new(Lru::new(MAX_TILES)),
        })
    }

    /// The body at `path`, `None` for 404 or 410. Errors when it is not answered.
    async fn get(&self, path: &str) -> Result<Option<bytes::Bytes>, String> {
        let url = format!("{}/{path}", self.base);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        match response.status().as_u16() {
            404 | 410 => return Ok(None),
            status if !(200..300).contains(&status) => {
                return Err(format!("{url} answered {status}"));
            }
            _ => {}
        }
        response
            .bytes()
            .await
            .map(Some)
            .map_err(|e| format!("{url}: body not read: {e}"))
    }

    /// What the database says of `module` at `version`, proved. Errors when it does not
    /// answer, or its answer does not prove itself.
    pub async fn lookup(&self, module: &str, version: &str) -> Result<Answer, String> {
        let path = format!("lookup/{}@{}", escape(module), escape(version));
        let Some(body) = self.get(&path).await? else {
            return Ok(Answer::Unknown);
        };
        let body = std::str::from_utf8(&body).map_err(|_| format!("{path}: not UTF-8"))?;
        let not = || format!("{path}: not a lookup answer");
        let (id, rest) = body.split_once('\n').ok_or_else(not)?;
        let id: u64 = id.parse().map_err(|_| not())?;
        let (data, note) = rest.split_once("\n\n").ok_or_else(not)?;
        let data = format!("{data}\n");
        let tree = Tree::parse(self.verifier.open(note)?)?;
        if !tlog::includes(self, tree.size, &tree.root, id, data.as_bytes()).await? {
            return Err(format!("{path}: record {id} is not in the signed tree"));
        }
        self.extend(tree).await?;
        let line = |suffix: &str| {
            let prefix = format!("{module} {version}{suffix} ");
            data.lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .map(str::to_owned)
                .ok_or_else(|| format!("{path}: no `{prefix}` line"))
        };
        Ok(Answer::Known {
            zip: line("")?,
            go_mod: line("/go.mod")?,
        })
    }

    /// Keep `tree` when it extends the largest tree seen, or is extended by it. Errors when
    /// neither is a prefix of the other: the database showed two histories.
    async fn extend(&self, tree: Tree) -> Result<(), String> {
        let mut latest = self.latest.lock().await;
        let consistent = match *latest {
            None => true,
            Some(seen) => {
                let (old, new) = match seen.size <= tree.size {
                    true => (seen, tree),
                    false => (tree, seen),
                };
                tlog::consistent(self, (old.size, &old.root), (new.size, &new.root)).await?
            }
        };
        if !consistent {
            return Err(format!(
                "the tree of {} records does not extend the one of {} seen before",
                tree.size.max(latest.map_or(0, |seen| seen.size)),
                tree.size.min(latest.map_or(0, |seen| seen.size))
            ));
        }
        if latest.is_none_or(|seen| seen.size < tree.size) {
            *latest = Some(tree);
        }
        Ok(())
    }

    /// The tile at `level` and `index`, `width` hashes wide. A full tile never changes, and
    /// is kept.
    async fn tile(&self, level: u32, index: u64, width: u64) -> Result<Vec<Hash>, String> {
        let full = width == 1 << HEIGHT;
        if full && let Some(kept) = self.tiles.lock().expect("tile lock").get(&(level, index)) {
            return Ok(kept.clone());
        }
        let path = tile_path(level, index, width);
        let body = self
            .get(&path)
            .await?
            .ok_or_else(|| format!("{path}: not found"))?;
        if body.len() as u64 != width * 32 {
            return Err(format!("{path}: {} bytes, not {}", body.len(), width * 32));
        }
        let hashes: Vec<Hash> = body.as_chunks::<32>().0.to_vec();
        if full {
            self.tiles
                .lock()
                .expect("tile lock")
                .insert((level, index), hashes.clone());
        }
        Ok(hashes)
    }
}

impl Tiles for Client {
    fn tile(&self, level: u32, index: u64, width: u64) -> Fetching<'_> {
        Box::pin(Client::tile(self, level, index, width))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::ecosystem::go::tlog::tests::{Log, data};
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::routing::get;
    use base64::Engine as _;
    use std::sync::Arc;

    /// A checksum database of `log` signing with `pair`, answering `example.com/m@v<i>`.
    struct Database {
        log: Log,
        pair: Ed25519KeyPair,
        size: Mutex<u64>,
        root: Mutex<Option<Hash>>,
        /// Text signed in place of the tree head, when set.
        head: Mutex<Option<String>>,
        /// A tile answered 500.
        refused: Mutex<Option<(u32, u64, u64)>>,
    }

    const NAME: &str = "sum.test";

    /// `pair`'s public key with its algorithm byte, and the first four bytes of its hash.
    fn key_parts(pair: &Ed25519KeyPair) -> (Vec<u8>, Vec<u8>) {
        let mut public = vec![1];
        public.extend_from_slice(pair.public_key().as_ref());
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, format!("{NAME}\n").as_bytes());
        sha2::Digest::update(&mut hasher, &public);
        let hash = sha2::Digest::finalize(hasher)[..4].to_vec();
        (public, hash)
    }

    fn key(pair: &Ed25519KeyPair) -> String {
        let (public, hash) = key_parts(pair);
        format!(
            "{NAME}+{}+{}",
            crate::util::hex(&hash),
            base64::engine::general_purpose::STANDARD.encode(public)
        )
    }

    /// Record `i`, which for 13 has no `go.mod` line.
    fn record(i: u64) -> String {
        match i {
            13 => "example.com/m v13 h1:zip13=\n".to_owned(),
            _ => format!("example.com/m v{i} h1:zip{i}=\nexample.com/m v{i}/go.mod h1:mod{i}=\n"),
        }
    }

    impl Database {
        fn note(&self) -> String {
            let size = *self.size.lock().unwrap();
            let root = self
                .root
                .lock()
                .unwrap()
                .unwrap_or_else(|| self.log.root(size));
            let text = self.head.lock().unwrap().clone().unwrap_or_else(|| {
                format!(
                    "go.sum database tree\n{size}\n{}\n",
                    base64::engine::general_purpose::STANDARD.encode(root)
                )
            });
            let (_, mut signed) = key_parts(&self.pair);
            signed.extend_from_slice(self.pair.sign(text.as_bytes()).as_ref());
            format!(
                "{text}\n\u{2014} {NAME} {}\n",
                base64::engine::general_purpose::STANDARD.encode(signed)
            )
        }
    }

    /// The log's records are [`record`]s here, so the leaves are rebuilt from them.
    fn database(size: u64) -> Arc<Database> {
        Arc::new(Database {
            log: Log::from_data(70_000, |i| record(i).into_bytes()),
            pair: Ed25519KeyPair::generate().unwrap(),
            size: Mutex::new(size),
            root: Mutex::new(None),
            head: Mutex::new(None),
            refused: Mutex::new(None),
        })
    }

    async fn lookup(
        State(db): State<Arc<Database>>,
        Path(at): Path<String>,
    ) -> Result<String, StatusCode> {
        let (module, version) = at.split_once('@').ok_or(StatusCode::BAD_REQUEST)?;
        let i: u64 = version
            .strip_prefix('v')
            .and_then(|v| v.parse().ok())
            .ok_or(StatusCode::GONE)?;
        if module != "example.com/m" || i >= *db.size.lock().unwrap() {
            return Err(StatusCode::NOT_FOUND);
        }
        Ok(format!("{i}\n{}\n{}", record(i), db.note()))
    }

    async fn tile(
        State(db): State<Arc<Database>>,
        Path((level, rest)): Path<(u32, String)>,
    ) -> Result<Vec<u8>, StatusCode> {
        let (digits, width) = match rest.split_once(".p/") {
            Some((digits, width)) => (digits.to_owned(), width.parse().unwrap()),
            None => (rest.clone(), 1 << HEIGHT),
        };
        let index: u64 = digits.replace(['x', '/'], "").parse().unwrap();
        if *db.refused.lock().unwrap() == Some((level, index, width)) {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let hashes = db
            .log
            .tile(level, index, width)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;
        Ok(hashes.concat())
    }

    async fn serve(db: Arc<Database>) -> String {
        let router = axum::Router::new()
            .route("/lookup/{*at}", get(lookup))
            .route("/tile/8/{level}/{*rest}", get(tile))
            .with_state(db);
        crate::proxy::testing::serve(router).await
    }

    fn known(i: u64) -> Answer {
        Answer::Known {
            zip: format!("h1:zip{i}="),
            go_mod: format!("h1:mod{i}="),
        }
    }

    #[tokio::test]
    async fn a_record_in_the_signed_tree_is_its_versions_h1_lines() {
        let db = database(70_000);
        let base = serve(db.clone()).await;
        let client = Client::new(reqwest::Client::new(), &base, &key(&db.pair)).unwrap();
        assert_eq!(
            client.lookup("example.com/m", "v1234").await,
            Ok(known(1234))
        );
        assert_eq!(
            client.lookup("example.com/m", "v69999").await,
            Ok(known(69_999))
        );
        assert_eq!(
            client.lookup("example.com/other", "v1").await,
            Ok(Answer::Unknown),
            "404"
        );
        assert_eq!(
            client.lookup("example.com/m", "latest").await,
            Ok(Answer::Unknown),
            "410"
        );
    }

    /// The client keeps the largest tree it proved: a larger one replaces it, a smaller one
    /// does not.
    #[tokio::test]
    async fn the_largest_tree_proved_is_the_one_kept() {
        let db = database(60_000);
        let base = serve(db.clone()).await;
        let client = Client::new(reqwest::Client::new(), &base, &key(&db.pair)).unwrap();
        let kept = || async { client.latest.lock().await.map(|tree| tree.size) };
        client.lookup("example.com/m", "v1").await.unwrap();
        assert_eq!(kept().await, Some(60_000));
        *db.size.lock().unwrap() = 70_000;
        client.lookup("example.com/m", "v1").await.unwrap();
        assert_eq!(kept().await, Some(70_000));
        *db.size.lock().unwrap() = 65_536;
        client.lookup("example.com/m", "v1").await.unwrap();
        assert_eq!(kept().await, Some(70_000));
    }

    /// Trees that grow are each checked against the last; a tree that does not extend it,
    /// or a second root for one size, is refused, and so is a root the record is not under.
    #[tokio::test]
    async fn a_tree_that_does_not_extend_the_last_one_is_refused() {
        let db = database(60_000);
        let base = serve(db.clone()).await;
        let client = Client::new(reqwest::Client::new(), &base, &key(&db.pair)).unwrap();
        assert_eq!(client.lookup("example.com/m", "v7").await, Ok(known(7)));
        *db.size.lock().unwrap() = 70_000;
        assert_eq!(
            client.lookup("example.com/m", "v65000").await,
            Ok(known(65_000))
        );
        *db.size.lock().unwrap() = 65_536;
        assert_eq!(
            client.lookup("example.com/m", "v8").await,
            Ok(known(8)),
            "an older tree"
        );

        *db.size.lock().unwrap() = 70_000;
        *db.root.lock().unwrap() = Some([9; 32]);
        let error = client.lookup("example.com/m", "v9").await.unwrap_err();
        assert!(error.contains("not in the signed tree"), "{error}");

        let fresh = Client::new(reqwest::Client::new(), &base, &key(&db.pair)).unwrap();
        *db.root.lock().unwrap() = None;
        *db.size.lock().unwrap() = 300;
        fresh.lookup("example.com/m", "v1").await.unwrap();
        *fresh.latest.lock().await = Some(Tree {
            size: 300,
            root: [3; 32],
        });
        *db.size.lock().unwrap() = 70_000;
        let error = fresh.lookup("example.com/m", "v2").await.unwrap_err();
        assert!(error.contains("does not extend"), "{error}");
        *db.size.lock().unwrap() = 200;
        let error = fresh.lookup("example.com/m", "v2").await.unwrap_err();
        assert!(error.contains("does not extend"), "{error}");
    }

    /// A tree head signed by another key, an answer that is not a lookup's, and a database
    /// that does not answer are each an error.
    #[tokio::test]
    async fn an_answer_that_does_not_prove_itself_is_an_error() {
        let db = database(1000);
        let base = serve(db.clone()).await;
        let other = Ed25519KeyPair::generate().unwrap();
        let stranger = Client::new(reqwest::Client::new(), &base, &key(&other)).unwrap();
        let error = stranger.lookup("example.com/m", "v1").await.unwrap_err();
        assert!(error.contains("no signature by sum.test"), "{error}");

        for answer in [
            crate::util::test_support::Answer::body("not a number\n"),
            crate::util::test_support::Answer::body("5"),
            crate::util::test_support::Answer::body("5\nno blank line"),
            crate::util::test_support::Answer::body(vec![0xff, 0xfe]),
            crate::util::test_support::Answer::Status(500),
            crate::util::test_support::Answer::Close,
            crate::util::test_support::Answer::cut_short(),
        ] {
            let addr = crate::util::test_support::scripted(vec![answer]).await;
            let client = Client::new(
                reqwest::Client::new(),
                &format!("http://{addr}"),
                &key(&db.pair),
            )
            .unwrap();
            assert!(client.lookup("example.com/m", "v1").await.is_err());
        }
    }

    /// A record the tree proves but that names another version, or has no `go.mod` line,
    /// gives no `h1:` lines; a signed note that is no tree head names no tree.
    #[tokio::test]
    async fn a_proved_record_without_both_lines_is_an_error() {
        let db = database(1000);
        let base = serve(db.clone()).await;
        let client = Client::new(reqwest::Client::new(), &base, &key(&db.pair)).unwrap();
        let error = client.lookup("example.com/m", "v01").await.unwrap_err();
        assert!(error.contains("no `example.com/m v01 ` line"), "{error}");
        let error = client.lookup("example.com/m", "v13").await.unwrap_err();
        assert!(
            error.contains("no `example.com/m v13/go.mod ` line"),
            "{error}"
        );
        *db.head.lock().unwrap() = Some("something else\n".to_owned());
        let error = client.lookup("example.com/m", "v1").await.unwrap_err();
        assert!(error.contains("not a tree head"), "{error}");
    }

    /// A tile that fails while an inclusion or a consistency proof is read fails the lookup.
    #[tokio::test]
    async fn a_tile_that_fails_fails_the_lookup() {
        let db = database(70_000);
        let base = serve(db.clone()).await;
        let client = Client::new(reqwest::Client::new(), &base, &key(&db.pair)).unwrap();
        *db.refused.lock().unwrap() = Some((0, 273, 112));
        let error = client.lookup("example.com/m", "v69999").await.unwrap_err();
        assert!(error.contains("answered 500"), "{error}");
        *db.refused.lock().unwrap() = None;
        client.lookup("example.com/m", "v69999").await.unwrap();
        *db.size.lock().unwrap() = 300;
        *db.refused.lock().unwrap() = Some((0, 273, 112));
        let error = client.lookup("example.com/m", "v1").await.unwrap_err();
        assert!(
            error.contains("answered 500"),
            "the consistency proof's tile: {error}"
        );
    }

    /// Full tiles are kept; a tile of the wrong length, or missing, is an error.
    #[tokio::test]
    async fn full_tiles_are_kept_and_a_bad_tile_is_an_error() {
        let db = database(70_000);
        let base = serve(db.clone()).await;
        let client = Client::new(reqwest::Client::new(), &base, &key(&db.pair)).unwrap();
        client.lookup("example.com/m", "v100").await.unwrap();
        let asked = db.log.asked.lock().unwrap().len();
        client.lookup("example.com/m", "v101").await.unwrap();
        let again = db.log.asked.lock().unwrap().len() - asked;
        assert!(again < asked, "{again} of {asked} tiles asked again");

        let addr =
            crate::util::test_support::scripted(vec![crate::util::test_support::Answer::body(
                vec![0; 31],
            )])
            .await;
        let bad = Client::new(
            reqwest::Client::new(),
            &format!("http://{addr}"),
            &key(&db.pair),
        )
        .unwrap();
        assert!(bad.tile(0, 0, 1).await.unwrap_err().contains("31 bytes"));
        let addr =
            crate::util::test_support::scripted(vec![crate::util::test_support::Answer::Status(
                404,
            )])
            .await;
        let gone = Client::new(
            reqwest::Client::new(),
            &format!("http://{addr}"),
            &key(&db.pair),
        )
        .unwrap();
        assert!(gone.tile(0, 0, 1).await.unwrap_err().contains("not found"));
    }

    /// Against sum.golang.org itself: two lookups, the second's tree proved consistent with
    /// the first's. Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "asks sum.golang.org"]
    async fn sum_golang_org_proves_rsc_io_quote() {
        let client = Client::new(
            reqwest::Client::new(),
            DEFAULT,
            crate::ecosystem::go::note::SUM_GOLANG_ORG,
        )
        .unwrap();
        assert_eq!(
            client.lookup("rsc.io/quote", "v1.5.2").await,
            Ok(Answer::Known {
                zip: "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=".to_owned(),
                go_mod: "h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=".to_owned(),
            })
        );
        assert!(matches!(
            client.lookup("golang.org/x/text", "v0.20.0").await,
            Ok(Answer::Known { .. })
        ));
        assert_eq!(
            client.lookup("rsc.io/quote", "v99.0.0").await,
            Ok(Answer::Unknown)
        );
    }

    #[test]
    fn paths_are_spelled_as_the_go_command_spells_them() {
        assert_eq!(tile_path(0, 5, 256), "tile/8/0/005");
        assert_eq!(tile_path(2, 1_234_567, 17), "tile/8/2/x001/x234/567.p/17");
        assert_eq!(tile_path(1, 1000, 256), "tile/8/1/x001/000");
        assert!(Client::new(reqwest::Client::new(), DEFAULT, "not a key").is_err());
        let _ = data(0);
    }
}
