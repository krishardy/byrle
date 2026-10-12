//! [`Analyses`] over Postgres, in the pool and database the intel store already uses.
//!
//! Tested by `tests/postgres.rs`. See docs/engineering_decisions/artifact-analysis-store.md.

use crate::analysis::InstallScripts;
use crate::analysis::attestation::{Attested, verifier_id};
use crate::analysis::detector::Detection;
use crate::analysis::source::{COMPARER, Sourced};
use crate::analysis::store::DetectionKey;
use crate::analysis::store::{Analyses, Analysis, AnalysisError, Scripts, Stored};
use crate::analysis::virustotal::{Counts, Scanned, Verdict};
use crate::integrity::Sri;
use sqlx::PgPool;

/// The stores a proxy decides with: the intel store, when one is configured, with the
/// analyses kept beside it in the same database; otherwise the analyses in memory, at most
/// `max_verified` of them.
pub fn stores(
    intel: Option<crate::intel::postgres::PgIntel>,
    max_verified: usize,
) -> (
    Option<std::sync::Arc<dyn crate::intel::store::Intel>>,
    std::sync::Arc<dyn Analyses>,
) {
    match intel {
        Some(store) => {
            let analyses = std::sync::Arc::new(PgAnalyses::new(store.pool().clone()));
            (Some(std::sync::Arc::new(store)), analyses)
        }
        None => (
            None,
            std::sync::Arc::new(crate::analysis::store::InProcess::new(max_verified)),
        ),
    }
}

/// What the detectors found, kept across restarts and shared between proxies.
#[derive(Debug, Clone)]
pub struct PgAnalyses {
    pool: PgPool,
}

impl PgAnalyses {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Write the analysis and its scripts in one transaction, so a reader never sees a
    /// row whose scripts are half written.
    async fn write(&self, digest: &Sri, analysis: &Analysis) -> Result<(), AnalysisError> {
        let (names, bodies) = columns(&analysis.scripts);
        let unreadable = match &analysis.scripts {
            Scripts::Unreadable(why) => Some(why.as_str()),
            Scripts::Declared(_) => None,
        };
        let mut tx = self.pool.begin().await.map_err(AnalysisError::Backend)?;

        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO artifact_analysis (digest, ecosystem, name, version, unreadable, reader)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (digest) DO UPDATE SET
                ecosystem   = EXCLUDED.ecosystem,
                name        = EXCLUDED.name,
                version     = EXCLUDED.version,
                unreadable  = EXCLUDED.unreadable,
                reader      = EXCLUDED.reader,
                analysed_at = now()
            RETURNING id
            "#,
            digest.to_string(),
            analysis.ecosystem,
            analysis.name,
            analysis.version,
            unreadable,
            crate::analysis::READER,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(AnalysisError::Backend)?;

        sqlx::query!(
            "DELETE FROM artifact_install_script WHERE analysis_id = $1",
            id
        )
        .execute(&mut *tx)
        .await
        .map_err(AnalysisError::Backend)?;

        sqlx::query!(
            r#"
            INSERT INTO artifact_install_script (analysis_id, ordinal, name, body)
            SELECT $1, (t.ordinal - 1)::SMALLINT, t.name, t.body
            FROM UNNEST($2::VARCHAR[], $3::TEXT[]) WITH ORDINALITY AS t(name, body, ordinal)
            "#,
            id,
            &names,
            &bodies as &[Option<String>],
        )
        .execute(&mut *tx)
        .await
        .map_err(AnalysisError::Backend)?;

        tx.commit().await.map_err(AnalysisError::Backend)
    }

    async fn read(&self, digest: &Sri) -> Result<Option<Analysis>, AnalysisError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                a.ecosystem AS "ecosystem!",
                a.name      AS "name!",
                a.version   AS "version!",
                a.unreadable,
                s.name      AS "script?",
                s.body      AS "body?"
            FROM artifact_analysis a
            LEFT JOIN artifact_install_script s ON s.analysis_id = a.id
            WHERE a.digest = $1 AND a.reader = $2
            ORDER BY s.ordinal
            "#,
            digest.to_string(),
            crate::analysis::READER,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AnalysisError::Backend)?;

        let Some(first) = rows.first() else {
            return Ok(None);
        };
        let scripts = match &first.unreadable {
            Some(why) => Scripts::Unreadable(why.clone()),
            None => {
                let mut found = InstallScripts::default();
                for row in &rows {
                    let Some(name) = row.script.clone() else {
                        continue;
                    };
                    if let Some(body) = row.body.clone() {
                        found.bodies.push((name.clone(), body));
                    }
                    found.names.push(name);
                }
                Scripts::Declared(found)
            }
        };
        Ok(Some(Analysis {
            ecosystem: first.ecosystem.clone(),
            name: first.name.clone(),
            version: first.version.clone(),
            scripts,
        }))
    }
}

/// The scripts as two arrays of the same length, which is what `UNNEST` takes. A name the
/// reader found no command for, which is a PyPI sdist's `setup.py`, is a `NULL` body.
fn columns(scripts: &Scripts) -> (Vec<String>, Vec<Option<String>>) {
    let Scripts::Declared(found) = scripts else {
        return (Vec::new(), Vec::new());
    };
    let bodies = found
        .names
        .iter()
        .map(|name| {
            found
                .bodies
                .iter()
                .find(|(of, _)| of == name)
                .map(|(_, body)| body.clone())
        })
        .collect();
    (found.names.clone(), bodies)
}

impl PgAnalyses {
    async fn write_attested(&self, digest: &Sri, attested: &Attested) -> Result<(), AnalysisError> {
        let (identity, failure) = match attested {
            Attested::Verified { identity } => (Some(identity.as_str()), None),
            Attested::Failed { why } => (None, Some(why.as_str())),
        };
        sqlx::query!(
            r#"
            INSERT INTO artifact_attestation (digest, identity, failure, verifier)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (digest) DO UPDATE SET
                identity    = EXCLUDED.identity,
                failure     = EXCLUDED.failure,
                verifier    = EXCLUDED.verifier,
                verified_at = now()
            "#,
            digest.to_string(),
            identity,
            failure,
            verifier_id(),
        )
        .execute(&self.pool)
        .await
        .map(drop)
        .map_err(AnalysisError::Backend)
    }

    async fn read_attested(&self, digest: &Sri) -> Result<Option<Attested>, AnalysisError> {
        let row = sqlx::query!(
            "SELECT identity, failure FROM artifact_attestation WHERE digest = $1 AND verifier = $2",
            digest.to_string(),
            verifier_id(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AnalysisError::Backend)?;
        Ok(row.map(|row| match (row.identity, row.failure) {
            (Some(identity), _) => Attested::Verified { identity },
            (None, why) => Attested::Failed {
                why: why.unwrap_or_default(),
            },
        }))
    }
}

impl PgAnalyses {
    async fn write_sourced(&self, digest: &Sri, sourced: &Sourced) -> Result<(), AnalysisError> {
        let result = serde_json::to_string(sourced).expect("a result serializes");
        sqlx::query!(
            r#"
            INSERT INTO artifact_source (digest, result, comparer)
            VALUES ($1, $2, $3)
            ON CONFLICT (digest) DO UPDATE SET
                result      = EXCLUDED.result,
                comparer    = EXCLUDED.comparer,
                compared_at = now()
            "#,
            digest.to_string(),
            result,
            COMPARER,
        )
        .execute(&self.pool)
        .await
        .map(drop)
        .map_err(AnalysisError::Backend)
    }

    /// A row this comparer wrote. One that no longer reads is not compared yet.
    async fn read_sourced(&self, digest: &Sri) -> Result<Option<Sourced>, AnalysisError> {
        let row = sqlx::query_scalar!(
            "SELECT result FROM artifact_source WHERE digest = $1 AND comparer = $2",
            digest.to_string(),
            COMPARER,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AnalysisError::Backend)?;
        Ok(row.and_then(|result| serde_json::from_str(&result).ok()))
    }
}

impl PgAnalyses {
    async fn write_detected(
        &self,
        key: &DetectionKey,
        detection: &Detection,
    ) -> Result<(), AnalysisError> {
        let result = serde_json::to_string(detection).expect("a detection serializes");
        sqlx::query!(
            r#"
            INSERT INTO version_detection (detector, detector_version, ecosystem, name, version, result)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (detector, ecosystem, name, version) DO UPDATE SET
                detector_version = EXCLUDED.detector_version,
                result           = EXCLUDED.result,
                detected_at      = now()
            "#,
            key.detector,
            key.detector_version,
            key.ecosystem,
            key.name,
            key.version,
            result,
        )
        .execute(&self.pool)
        .await
        .map(drop)
        .map_err(AnalysisError::Backend)
    }

    /// A row this detector version wrote. One that no longer reads is not run yet.
    async fn read_detected(&self, key: &DetectionKey) -> Result<Option<Detection>, AnalysisError> {
        let row = sqlx::query_scalar!(
            "SELECT result FROM version_detection \
             WHERE detector = $1 AND detector_version = $2 AND ecosystem = $3 AND name = $4 AND version = $5",
            key.detector,
            key.detector_version,
            key.ecosystem,
            key.name,
            key.version,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AnalysisError::Backend)?;
        Ok(row.and_then(|result| serde_json::from_str(&result).ok()))
    }
}

impl Analyses for PgAnalyses {
    fn get<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Analysis>> {
        Box::pin(self.read(digest))
    }

    fn put<'a>(&'a self, digest: &'a Sri, analysis: &'a Analysis) -> Stored<'a, ()> {
        Box::pin(self.write(digest, analysis))
    }

    fn attested<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Attested>> {
        Box::pin(self.read_attested(digest))
    }

    fn put_attested<'a>(&'a self, digest: &'a Sri, attested: &'a Attested) -> Stored<'a, ()> {
        Box::pin(self.write_attested(digest, attested))
    }

    fn sourced<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Sourced>> {
        Box::pin(self.read_sourced(digest))
    }

    fn put_sourced<'a>(&'a self, digest: &'a Sri, sourced: &'a Sourced) -> Stored<'a, ()> {
        Box::pin(self.write_sourced(digest, sourced))
    }

    fn detected<'a>(&'a self, key: &'a DetectionKey) -> Stored<'a, Option<Detection>> {
        Box::pin(self.read_detected(key))
    }

    fn put_detected<'a>(
        &'a self,
        key: &'a DetectionKey,
        detection: &'a Detection,
    ) -> Stored<'a, ()> {
        Box::pin(self.write_detected(key, detection))
    }

    fn scanned<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Scanned>> {
        Box::pin(self.read_scanned(digest))
    }

    fn put_scanned<'a>(&'a self, digest: &'a Sri, scanned: &'a Scanned) -> Stored<'a, ()> {
        Box::pin(self.write_scanned(digest, scanned))
    }

    fn virustotal_asked(&self, since: i64) -> Stored<'_, Vec<i64>> {
        Box::pin(self.read_virustotal_asked(since))
    }

    fn put_virustotal_asked(&self, at: i64) -> Stored<'_, ()> {
        Box::pin(self.write_virustotal_asked(at))
    }
}

impl PgAnalyses {
    async fn write_scanned(&self, digest: &Sri, scanned: &Scanned) -> Result<(), AnalysisError> {
        let (state, analysis, counts) = match &scanned.verdict {
            Verdict::Known(counts) => ("known", None, Some(counts)),
            Verdict::Unknown => ("unknown", None, None),
            Verdict::Queued(id) => ("queued", Some(id.as_str()), None),
        };
        let count =
            |of: fn(&Counts) -> u32| counts.map(|c| i32::try_from(of(c)).unwrap_or(i32::MAX));
        sqlx::query!(
            r#"
            INSERT INTO artifact_virustotal
                (digest, sha256, state, analysis, malicious, suspicious, engines, asked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8))
            ON CONFLICT (digest) DO UPDATE SET
                sha256     = EXCLUDED.sha256,
                state      = EXCLUDED.state,
                analysis   = EXCLUDED.analysis,
                malicious  = EXCLUDED.malicious,
                suspicious = EXCLUDED.suspicious,
                engines    = EXCLUDED.engines,
                asked_at   = EXCLUDED.asked_at
            "#,
            digest.to_string(),
            scanned.sha256,
            state,
            analysis,
            count(|c| c.malicious),
            count(|c| c.suspicious),
            count(|c| c.engines),
            scanned.asked as f64,
        )
        .execute(&self.pool)
        .await
        .map(drop)
        .map_err(AnalysisError::Backend)
    }

    /// The row for `digest`. One whose state does not read is not asked yet.
    async fn read_scanned(&self, digest: &Sri) -> Result<Option<Scanned>, AnalysisError> {
        let row = sqlx::query!(
            r#"
            SELECT sha256, state, analysis, malicious, suspicious, engines,
                   EXTRACT(EPOCH FROM asked_at)::bigint AS "asked!"
            FROM artifact_virustotal WHERE digest = $1
            "#,
            digest.to_string(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AnalysisError::Backend)?;
        Ok(row.and_then(|row| {
            let unsigned = |n: Option<i32>| n.and_then(|n| u32::try_from(n).ok());
            let verdict = match (row.state.as_str(), row.analysis) {
                ("known", _) => Verdict::Known(Counts {
                    malicious: unsigned(row.malicious)?,
                    suspicious: unsigned(row.suspicious)?,
                    engines: unsigned(row.engines)?,
                }),
                ("unknown", _) => Verdict::Unknown,
                ("queued", Some(id)) => Verdict::Queued(id),
                _ => return None,
            };
            Some(Scanned {
                sha256: row.sha256,
                verdict,
                asked: row.asked,
            })
        }))
    }

    async fn read_virustotal_asked(&self, since: i64) -> Result<Vec<i64>, AnalysisError> {
        sqlx::query_scalar!(
            r#"
            SELECT EXTRACT(EPOCH FROM asked_at)::bigint AS "asked!"
            FROM virustotal_request WHERE asked_at > to_timestamp($1) ORDER BY asked_at
            "#,
            since as f64,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AnalysisError::Backend)
    }

    /// Record a request, and delete those older than two days, which no limit counts.
    async fn write_virustotal_asked(&self, at: i64) -> Result<(), AnalysisError> {
        sqlx::query!(
            "INSERT INTO virustotal_request (asked_at) VALUES (to_timestamp($1))",
            at as f64,
        )
        .execute(&self.pool)
        .await
        .map_err(AnalysisError::Backend)?;
        sqlx::query!(
            "DELETE FROM virustotal_request WHERE asked_at < to_timestamp($1) - interval '2 days'",
            at as f64,
        )
        .execute(&self.pool)
        .await
        .map(drop)
        .map_err(AnalysisError::Backend)
    }
}
