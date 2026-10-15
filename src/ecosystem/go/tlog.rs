//! Go's checksum database log, read as `golang.org/x/mod/sumdb/tlog` reads it: RFC 6962
//! hashes, with every node at a level that is a multiple of [`HEIGHT`] published in tiles
//! of `2^HEIGHT` hashes. Proves a record is in a tree, and a tree is a prefix of another,
//! each from the hashes of one proof, as RFC 9162 checks them.

use std::future::Future;
use std::pin::Pin;

use sha2::{Digest, Sha256};

/// A SHA-256 hash in the log.
pub type Hash = [u8; 32];

/// The levels a tile spans: sum.golang.org's tiles are 8 high, 256 hashes wide.
pub const HEIGHT: u32 = 8;

/// The hashes of one tile, asked for as its level, its index and its width.
pub type Fetching<'a> = Pin<Box<dyn Future<Output = Result<Vec<Hash>, String>> + Send + 'a>>;

/// Where tiles come from: `tile(level, index, width)` is `tile/8/<level>/<index>[.p/<width>]`.
pub trait Tiles: Sync {
    fn tile(&self, level: u32, index: u64, width: u64) -> Fetching<'_>;
}

/// A log record's leaf hash.
pub fn record_hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0]);
    hasher.update(data);
    hasher.finalize().into()
}

/// An interior node's hash.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The hash of the complete subtree at `level` and `index`, covering records
/// `index << level` up to the next, in a tree of `size` records.
async fn subtree(tiles: &dyn Tiles, level: u32, index: u64, size: u64) -> Result<Hash, String> {
    let tile_level = level / HEIGHT;
    let below = level % HEIGHT;
    let first = index << below;
    let count = 1_u64 << below;
    let tile_index = first >> HEIGHT;
    let offset = (first % (1 << HEIGHT)) as usize;
    let available = size >> (tile_level * HEIGHT);
    let width = (available - (tile_index << HEIGHT)).min(1 << HEIGHT);
    let hashes = tiles.tile(tile_level, tile_index, width).await?;
    let Some(mut row) = hashes
        .get(offset..offset + count as usize)
        .map(<[Hash]>::to_vec)
    else {
        return Err(format!(
            "tile {tile_level}/{tile_index} has {} hashes, not {}",
            hashes.len(),
            offset + count as usize
        ));
    };
    while row.len() > 1 {
        row = row
            .chunks(2)
            .map(|pair| node_hash(&pair[0], &pair[1]))
            .collect();
    }
    Ok(row[0])
}

/// The largest power of two below `n`, which RFC 6962 splits a tree of `n` records at.
fn split(n: u64) -> u64 {
    1 << (63 - (n - 1).leading_zeros())
}

/// The hash of records `start` up to `end` in a tree of `size`, where `start` is a multiple
/// of the largest power of two that fits: every range RFC 6962 splits a tree into is.
fn range_hash(
    tiles: &dyn Tiles,
    start: u64,
    end: u64,
    size: u64,
) -> Pin<Box<dyn Future<Output = Result<Hash, String>> + Send + '_>> {
    Box::pin(async move {
        let n = end - start;
        if n.is_power_of_two() {
            let level = n.trailing_zeros();
            return subtree(tiles, level, start >> level, size).await;
        }
        let k = split(n);
        let left = range_hash(tiles, start, start + k, size).await?;
        let right = range_hash(tiles, start + k, end, size).await?;
        Ok(node_hash(&left, &right))
    })
}

/// The root of records `start` up to `end`, computed from record `leaf`'s hash `hash` and
/// the hashes of the subtrees beside its path.
fn root_through(
    tiles: &dyn Tiles,
    leaf: u64,
    hash: Hash,
    start: u64,
    end: u64,
    size: u64,
) -> Pin<Box<dyn Future<Output = Result<Hash, String>> + Send + '_>> {
    Box::pin(async move {
        let n = end - start;
        if n == 1 {
            return Ok(hash);
        }
        let k = split(n);
        if leaf < start + k {
            let left = root_through(tiles, leaf, hash, start, start + k, size).await?;
            let right = range_hash(tiles, start + k, end, size).await?;
            Ok(node_hash(&left, &right))
        } else {
            let left = range_hash(tiles, start, start + k, size).await?;
            let right = root_through(tiles, leaf, hash, start + k, end, size).await?;
            Ok(node_hash(&left, &right))
        }
    })
}

/// Whether record `index`, whose data is `data`, is in the tree of `size` records whose
/// root is `root`. Errors when a tile could not be read or is short.
pub async fn includes(
    tiles: &dyn Tiles,
    size: u64,
    root: &Hash,
    index: u64,
    data: &[u8],
) -> Result<bool, String> {
    if index >= size {
        return Ok(false);
    }
    let computed = root_through(tiles, index, record_hash(data), 0, size, size).await?;
    Ok(&computed == root)
}

/// RFC 6962's consistency proof that the first `old` records of records `start` up to
/// `end` are a tree of their own: the subtree hashes beside the path to its right edge.
/// `whole` says the old tree is the whole of the range, whose root the verifier holds.
fn consistency_proof(
    tiles: &dyn Tiles,
    old: u64,
    start: u64,
    end: u64,
    size: u64,
    whole: bool,
) -> Pin<Box<dyn Future<Output = Result<Vec<Hash>, String>> + Send + '_>> {
    Box::pin(async move {
        let n = end - start;
        if old == n {
            return Ok(match whole {
                true => Vec::new(),
                false => vec![range_hash(tiles, start, end, size).await?],
            });
        }
        let k = split(n);
        let (mut proof, beside) = if old <= k {
            let proof = consistency_proof(tiles, old, start, start + k, size, whole).await?;
            (proof, range_hash(tiles, start + k, end, size).await?)
        } else {
            let proof = consistency_proof(tiles, old - k, start + k, end, size, false).await?;
            (proof, range_hash(tiles, start, start + k, size).await?)
        };
        proof.push(beside);
        Ok(proof)
    })
}

/// RFC 9162's check of a consistency proof: both roots computed from `proof`, as 2.1.4.2
/// writes it.
fn proves(old: u64, old_root: &Hash, new: u64, new_root: &Hash, proof: &[Hash]) -> bool {
    let mut path = proof.to_vec();
    if old.is_power_of_two() {
        path.insert(0, *old_root);
    }
    let Some(&start) = path.first() else {
        return false;
    };
    let (mut first, mut second) = (old - 1, new - 1);
    while first & 1 == 1 {
        first >>= 1;
        second >>= 1;
    }
    let (mut old_hash, mut new_hash) = (start, start);
    for c in &path[1..] {
        if second == 0 {
            return false;
        }
        if first & 1 == 1 || first == second {
            old_hash = node_hash(c, &old_hash);
            new_hash = node_hash(c, &new_hash);
            while first & 1 == 0 && first != 0 {
                first >>= 1;
                second >>= 1;
            }
        } else {
            new_hash = node_hash(&new_hash, c);
        }
        first >>= 1;
        second >>= 1;
    }
    second == 0 && &old_hash == old_root && &new_hash == new_root
}

/// Whether the tree of `old` records whose root is `old_root` is the first `old` records of
/// the tree of `new` whose root is `new_root`, proved from the larger tree's tiles. Errors
/// as [`includes`] does.
pub async fn consistent(
    tiles: &dyn Tiles,
    (old, old_root): (u64, &Hash),
    (new, new_root): (u64, &Hash),
) -> Result<bool, String> {
    if old == 0 || old > new {
        return Ok(false);
    }
    if old == new {
        return Ok(old_root == new_root);
    }
    let proof = consistency_proof(tiles, old, 0, new, new, true).await?;
    Ok(proves(old, old_root, new, new_root, &proof))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A log held in memory, served as sum.golang.org serves tiles, and each tile asked for.
    pub(crate) struct Log {
        levels: Vec<Vec<Hash>>,
        pub(crate) asked: Mutex<Vec<(u32, u64, u64)>>,
    }

    pub(crate) fn data(i: u64) -> Vec<u8> {
        format!("record {i}\n").into_bytes()
    }

    impl Log {
        pub(crate) fn new(size: u64) -> Self {
            Self::from_data(size, data)
        }

        /// A log whose record `i` is `record(i)`.
        pub(crate) fn from_data(size: u64, record: impl Fn(u64) -> Vec<u8>) -> Self {
            let mut levels = vec![
                (0..size)
                    .map(|i| record_hash(&record(i)))
                    .collect::<Vec<_>>(),
            ];
            while levels.last().unwrap().len() > 1 {
                let next = levels
                    .last()
                    .unwrap()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|[left, right]| node_hash(left, right))
                    .collect();
                levels.push(next);
            }
            Self {
                levels,
                asked: Mutex::new(Vec::new()),
            }
        }

        /// RFC 6962's root of the first `n` records, computed directly.
        pub(crate) fn root(&self, n: u64) -> Hash {
            fn mth(leaves: &[Hash]) -> Hash {
                if leaves.len() == 1 {
                    return leaves[0];
                }
                let k = split(leaves.len() as u64) as usize;
                node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
            }
            mth(&self.levels[0][..n as usize])
        }
    }

    impl Tiles for Log {
        fn tile(&self, level: u32, index: u64, width: u64) -> Fetching<'_> {
            self.asked.lock().unwrap().push((level, index, width));
            let row = &self.levels[(level * HEIGHT) as usize];
            let start = (index << HEIGHT) as usize;
            let hashes = row
                .get(start..start + width as usize)
                .map(<[Hash]>::to_vec)
                .ok_or_else(|| format!("no tile {level}/{index}.p/{width}"));
            Box::pin(std::future::ready(hashes))
        }
    }

    /// Every record of trees across tile edges is proved in, and no other data is.
    #[tokio::test]
    async fn each_record_is_proved_in_its_tree_and_nothing_else_is() {
        let log = Log::new(70_000);
        for size in [1, 2, 3, 255, 256, 257, 65_536, 65_537, 70_000] {
            let root = log.root(size);
            for index in [0, size / 2, size - 1] {
                assert!(
                    includes(&log, size, &root, index, &data(index))
                        .await
                        .unwrap(),
                    "{index} of {size}"
                );
                assert!(
                    !includes(&log, size, &root, index, b"forged\n")
                        .await
                        .unwrap()
                );
            }
            assert!(
                !includes(&log, size, &root, size, &data(size))
                    .await
                    .unwrap()
            );
        }
    }

    /// A tree is a prefix of a larger one, proved from the larger one's tiles; another root
    /// for either tree, or a size past the larger, is not.
    #[tokio::test]
    async fn a_smaller_tree_is_proved_a_prefix_of_a_larger_one() {
        let log = Log::new(70_000);
        for new in [2, 257, 65_536, 70_000] {
            let new_root = log.root(new);
            for old in [1, 2, 3, 255, 256, 300, 65_535, 65_536, 69_999, 70_000] {
                if old > new {
                    continue;
                }
                let old_root = log.root(old);
                assert!(
                    consistent(&log, (old, &old_root), (new, &new_root))
                        .await
                        .unwrap(),
                    "{old} of {new}"
                );
                assert!(
                    !consistent(&log, (old, &[7; 32]), (new, &new_root))
                        .await
                        .unwrap()
                );
                if old < new {
                    assert!(
                        !consistent(&log, (old, &old_root), (new, &[7; 32]))
                            .await
                            .unwrap()
                    );
                }
            }
        }
        let root = log.root(300);
        assert!(!consistent(&log, (301, &root), (300, &root)).await.unwrap());
        assert!(!consistent(&log, (0, &root), (300, &root)).await.unwrap());
        assert!(
            !proves(3, &root, 4, &root, &[]),
            "a proof too short for its sizes"
        );
    }

    /// A proof reads few tiles: one per tile level the path crosses, and the edge's partial
    /// ones, each asked with the width the tree of that size has.
    #[tokio::test]
    async fn a_proof_reads_a_handful_of_tiles_at_their_widths() {
        let log = Log::new(70_000);
        includes(&log, 70_000, &log.root(70_000), 1234, &data(1234))
            .await
            .unwrap();
        let asked = log.asked.lock().unwrap();
        assert!(asked.len() <= 40, "{} tiles", asked.len());
        assert!(asked.contains(&(0, 4, 256)), "{asked:?}");
        assert!(
            asked.contains(&(0, 273, 112)),
            "the partial tile at the edge: {asked:?}"
        );
        assert!(asked.contains(&(1, 1, 17)), "{asked:?}");
    }

    struct Short;

    impl Tiles for Short {
        fn tile(&self, _: u32, _: u64, _: u64) -> Fetching<'_> {
            Box::pin(std::future::ready(Ok(vec![[0; 32]])))
        }
    }

    struct Down;

    impl Tiles for Down {
        fn tile(&self, _: u32, _: u64, _: u64) -> Fetching<'_> {
            Box::pin(std::future::ready(Err("down".to_owned())))
        }
    }

    /// A log whose tiles answer until the `n`th, which fails.
    struct FailAt<'a>(&'a Log, Mutex<u32>);

    impl Tiles for FailAt<'_> {
        fn tile(&self, level: u32, index: u64, width: u64) -> Fetching<'_> {
            let mut n = self.1.lock().unwrap();
            if *n == 0 {
                return Box::pin(std::future::ready(Err("failed".to_owned())));
            }
            *n -= 1;
            self.0.tile(level, index, width)
        }
    }

    /// Whichever tile fails, the proof is an error, not an answer.
    #[tokio::test]
    async fn any_tile_failing_fails_the_proof() {
        let log = Log::new(70_000);
        let (old, new) = (log.root(65_537), log.root(70_000));
        for n in 0..40 {
            let failing = FailAt(&log, Mutex::new(n));
            let included = includes(&failing, 70_000, &new, 66_000, &data(66_000)).await;
            assert!(included.is_err() || included == Ok(true), "{n}");
            let failing = FailAt(&log, Mutex::new(n));
            let proved = consistent(&failing, (65_537, &old), (70_000, &new)).await;
            assert!(proved.is_err() || proved == Ok(true), "{n}");
            let failing = FailAt(&log, Mutex::new(n));
            let ranged = range_hash(&failing, 0, 70_000, 70_000).await;
            assert!(ranged.is_err() || ranged == Ok(new), "{n}");
        }
    }

    /// A proof with a hash past what its sizes need is refused.
    #[tokio::test]
    async fn a_proof_with_a_hash_too_many_is_refused() {
        let log = Log::new(1000);
        let (old, new) = (log.root(300), log.root(1000));
        let mut proof = consistency_proof(&log, 300, 0, 1000, 1000, true)
            .await
            .unwrap();
        assert!(proves(300, &old, 1000, &new, &proof));
        proof.push([0; 32]);
        assert!(!proves(300, &old, 1000, &new, &proof));
    }

    #[tokio::test]
    async fn a_tile_short_or_not_read_is_an_error() {
        let error = includes(&Short, 1000, &[0; 32], 5, b"x").await.unwrap_err();
        assert!(error.contains("has 1 hashes"), "{error}");
        assert_eq!(
            includes(&Down, 1000, &[0; 32], 5, b"x").await,
            Err("down".to_owned())
        );
        assert_eq!(
            consistent(&Down, (600, &[0; 32]), (1000, &[0; 32])).await,
            Err("down".to_owned())
        );
    }
}
