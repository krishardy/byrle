//! [`Analyses`] over Postgres, in the database the intel store already uses.
//!
//! One pool, not two. The analyses are written on the request path and the advisories are
//! read on it, so a second pool would double the connections a proxy holds for one
//! database. [`crate::intel::postgres::PgIntel::pool`] hands this one over, and
//! `PgIntel::migrate` applies `migrations/0009_artifact_analysis.sql` and
//! `migrations/0010_artifact_attestation.sql` with the rest.
//!
//! Tested by `tests/postgres.rs`, which `make test-integration` runs against a container.

use crate::analysis::InstallScripts;
use crate::analysis::attestation::{Attested, verifier_id};
use crate::analysis::store::{Analyses, Analysis, AnalysisError, Scripts, Stored};
use crate::integrity::Sri;
use sqlx::PgPool;

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

        // Re-analysing the same bytes is not an error: two clients can ask for one
        // artifact at once. The later answer replaces the earlier one, which is the same
        // answer unless the reader itself changed.
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO artifact_analysis (digest, ecosystem, name, version, unreadable)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (digest) DO UPDATE SET
                ecosystem   = EXCLUDED.ecosystem,
                name        = EXCLUDED.name,
                version     = EXCLUDED.version,
                unreadable  = EXCLUDED.unreadable,
                analysed_at = now()
            RETURNING id
            "#,
            digest.to_string(),
            analysis.ecosystem,
            analysis.name,
            analysis.version,
            unreadable,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(AnalysisError::Backend)?;

        // The scripts are replaced rather than merged. A name the new answer does not
        // carry is a script the artifact no longer declares, and leaving it would report
        // a script no reader found.
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
        // One row per script, or one row with no script for an artifact that declares
        // none and for one that could not be read.
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
            WHERE a.digest = $1
            ORDER BY s.ordinal
            "#,
            digest.to_string(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(AnalysisError::Backend)?;

        let Some(first) = rows.first() else {
            return Ok(None);
        };
        // An unreadable archive was never asked, so any script row against it would be
        // one nothing wrote. The column decides, not the absence of rows.
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
        // The table's CHECK sets exactly one of the two.
        Ok(row.map(|row| match (row.identity, row.failure) {
            (Some(identity), _) => Attested::Verified { identity },
            (None, why) => Attested::Failed {
                why: why.unwrap_or_default(),
            },
        }))
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
}
