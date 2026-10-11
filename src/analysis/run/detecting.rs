//! Running each configured detector on a version, beside the analysis and never in front of
//! it: no request is deferred for it. See docs/engineering_decisions/detectors.md.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{Semaphore, watch};
use tracing::{info, warn};

use super::{Analyser, InFlight};
use crate::analysis::detector::{Detection, Detector, Target};
use crate::analysis::store::DetectionKey;

/// How many detector runs go at once, apart from the analyses a client waits on.
pub const DETECTOR_SLOTS: usize = 2;

/// The detectors, and their own slots, so none waits on a deferred client's analysis.
#[derive(Clone)]
pub(super) struct Detectors {
    detectors: Vec<Arc<dyn Detector>>,
    slots: Arc<Semaphore>,
    in_flight: Arc<Mutex<HashSet<DetectionKey>>>,
    /// How many runs have started.
    started: Arc<AtomicU64>,
    ended: Arc<watch::Sender<u64>>,
}

/// Which run of `detector` on `target` a result is kept under.
fn key(detector: &dyn Detector, target: &Target) -> DetectionKey {
    DetectionKey {
        detector: detector.name().to_owned(),
        detector_version: detector.version().to_owned(),
        ecosystem: target.ecosystem.as_str().to_owned(),
        name: target.name.clone(),
        version: target.version.clone(),
    }
}

impl Analyser {
    /// Run `detectors` on the versions it is asked to. None leaves detection off.
    pub fn with_detectors(mut self, detectors: Vec<Arc<dyn Detector>>) -> Self {
        self.detectors = (!detectors.is_empty()).then(|| Detectors {
            detectors,
            slots: Arc::new(Semaphore::new(DETECTOR_SLOTS)),
            in_flight: Arc::default(),
            started: Arc::default(),
            ended: Arc::new(watch::Sender::new(0)),
        });
        self
    }

    /// What each detector found about `target` when it ran before, by detector name. A store
    /// that cannot answer is no result, and the detector runs again.
    pub async fn detected(&self, target: &Target) -> Vec<(String, Detection)> {
        let Some(detectors) = &self.detectors else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for detector in &detectors.detectors {
            let key = key(detector.as_ref(), target);
            match self.store.detected(&key).await {
                Ok(Some(detection)) => found.push((key.detector, detection)),
                Ok(None) => {}
                Err(e) => {
                    warn!(error.message = %e, "analysis store cannot answer; the detector runs again");
                }
            }
        }
        found
    }

    /// Start each detector on `target` that is not in `done`, detectors whose result is
    /// stored, nor running on it now. A run finding a result stored since ends there.
    /// Returns the handles, for a test to wait on. The proxy drops them.
    pub fn start_detecting(
        &self,
        target: &Target,
        done: &[(String, Detection)],
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let Some(detectors) = &self.detectors else {
            return Vec::new();
        };
        let mut started = Vec::new();
        for detector in &detectors.detectors {
            if done.iter().any(|(name, _)| name == detector.name()) {
                continue;
            }
            let key = key(detector.as_ref(), target);
            if !detectors
                .in_flight
                .lock()
                .expect("detector in-flight lock")
                .insert(key.clone())
            {
                continue;
            }
            detectors.started.fetch_add(1, Ordering::Relaxed);
            let guard = InFlight {
                set: detectors.in_flight.clone(),
                key: key.clone(),
                ended: detectors.ended.clone(),
            };
            let (analyser, detector, slots, target) = (
                self.clone(),
                detector.clone(),
                detectors.slots.clone(),
                target.clone(),
            );
            started.push(tokio::spawn(async move {
                let _guard = guard;
                let _slot = slots
                    .acquire_owned()
                    .await
                    .expect("the semaphore is never closed");
                analyser.detect(detector.as_ref(), &target, &key).await;
            }));
        }
        started
    }

    /// Run `detector` on `target` within the deadline, unless its result for `key` is stored,
    /// and store what it found. A run that fails stores nothing.
    async fn detect(&self, detector: &dyn Detector, target: &Target, key: &DetectionKey) {
        if let Ok(Some(_)) = self.store.detected(key).await {
            return;
        }
        let Some(detection) = self.ran(detector, target, key).await else {
            return;
        };
        match self.store.put_detected(key, &detection).await {
            Ok(()) => log_ran(key, &detection),
            Err(e) => {
                warn!(byrle.detector = %key.detector, error.message = %e, "detector: not stored");
            }
        }
    }

    /// What `detector` found about `target`, `key`'s run, within the deadline.
    /// Returns `None`, logged, when it did not run or ran past the deadline.
    async fn ran(
        &self,
        detector: &dyn Detector,
        target: &Target,
        key: &DetectionKey,
    ) -> Option<Detection> {
        let why = match tokio::time::timeout(self.deadline, detector.detect(target)).await {
            Ok(Ok(detection)) => return Some(detection),
            Ok(Err(why)) => why,
            Err(_) => "past its deadline".to_owned(),
        };
        warn!(byrle.detector = %key.detector, byrle.package.name = %key.name, byrle.package.version = %key.version, error.message = %why, "detector did not run, nothing stored");
        None
    }

    /// How many detectors are set.
    pub fn detector_count(&self) -> usize {
        self.detectors
            .as_ref()
            .map_or(0, |detectors| detectors.detectors.len())
    }

    /// How many detector runs have started since this analyser was made. 0 when none is set.
    pub fn detections_started(&self) -> u64 {
        self.detectors
            .as_ref()
            .map_or(0, |detectors| detectors.started.load(Ordering::Relaxed))
    }

    /// Wait until `count` detector runs have ended since this analyser was made.
    pub async fn detections_ended(&self, count: u64) {
        if let Some(detectors) = &self.detectors {
            let _ = detectors
                .ended
                .subscribe()
                .wait_for(|ended| *ended >= count)
                .await;
        }
    }
}

/// Log what the run `key` found and could not do.
fn log_ran(key: &DetectionKey, detection: &Detection) {
    let rules: Vec<&str> = detection.findings.iter().map(|f| f.rule.as_str()).collect();
    let errors: Vec<&str> = detection.errors.iter().map(|f| f.rule.as_str()).collect();
    info!(byrle.detector = %key.detector, byrle.package.name = %key.name, byrle.package.version = %key.version, byrle.detector.findings = ?rules, byrle.detector.errors = ?errors, "detector ran");
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::analysis::detector::{Detecting, Finding};
    use crate::analysis::run::tests::analyser as made;
    use crate::analysis::store::InProcess;
    use crate::identity::Ecosystem;
    use std::time::Duration;

    /// A detector that answers each version with `answer`, after `delay`, counting its runs.
    pub(crate) struct Fake {
        pub(crate) answer: Result<Detection, String>,
        pub(crate) delay: Duration,
        pub(crate) runs: AtomicU64,
    }

    impl Fake {
        pub(crate) fn firing(rules: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                answer: Ok(Detection {
                    findings: rules
                        .iter()
                        .map(|rule| Finding {
                            rule: (*rule).to_owned(),
                            detail: "found".to_owned(),
                        })
                        .collect(),
                    errors: vec![Finding {
                        rule: "unclaimed_maintainer_email_domain".to_owned(),
                        detail: "Name or service not known".to_owned(),
                    }],
                }),
                delay: Duration::ZERO,
                runs: AtomicU64::new(0),
            })
        }
    }

    impl Detector for Fake {
        fn name(&self) -> &str {
            "guarddog"
        }
        fn version(&self) -> &str {
            "3.2.0"
        }
        fn detect<'a>(&'a self, _: &'a Target) -> Detecting<'a> {
            Box::pin(async move {
                self.runs.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(self.delay).await;
                self.answer.clone()
            })
        }
    }

    fn target() -> Target {
        Target {
            ecosystem: Ecosystem::Npm,
            name: "widget".to_owned(),
            version: "1.0.0".to_owned(),
        }
    }

    async fn run_all(analyser: &Analyser, done: &[(String, Detection)]) {
        for handle in analyser.start_detecting(&target(), done) {
            handle.await.expect("finishes");
        }
    }

    /// A run's findings are stored and read back, a second run finds them stored, a detector
    /// with a result in `done` is not started, and one in flight is not started twice.
    #[tokio::test]
    async fn a_detector_runs_once_and_its_result_is_read_back() {
        let fake = Fake::firing(&["threat-process-hooks"]);
        let analyser = made("detect-once", 1 << 20, Arc::new(InProcess::new(8)))
            .with_detectors(vec![fake.clone()]);
        assert_eq!(analyser.detector_count(), 1);
        assert_eq!(analyser.detected(&target()).await, []);
        run_all(&analyser, &[]).await;
        let detected = analyser.detected(&target()).await;
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].0, "guarddog");
        assert_eq!(detected[0].1.findings[0].rule, "threat-process-hooks");

        run_all(&analyser, &[]).await;
        assert_eq!(
            fake.runs.load(Ordering::Relaxed),
            1,
            "the second run found it stored"
        );
        assert!(analyser.start_detecting(&target(), &detected).is_empty());
        assert_eq!(analyser.detections_started(), 2);

        let slow = Arc::new(Fake {
            delay: Duration::from_millis(200),
            ..Arc::try_unwrap(Fake::firing(&[])).ok().expect("one owner")
        });
        let busy =
            made("detect-busy", 1 << 20, Arc::new(InProcess::new(8))).with_detectors(vec![slow]);
        let first = busy.start_detecting(&target(), &[]);
        assert!(busy.start_detecting(&target(), &[]).is_empty(), "in flight");
        for handle in first {
            handle.await.expect("finishes");
        }
        tokio::time::timeout(Duration::from_secs(10), busy.detections_ended(1))
            .await
            .expect("the run ends");
    }

    /// Off, nothing runs. A detector that fails, or outlasts the deadline, stores nothing, and
    /// a store that cannot answer is logged.
    #[tokio::test]
    async fn what_does_not_run_stores_nothing() {
        let off = made("detect-off", 1 << 20, Arc::new(InProcess::new(8)));
        let off = off.with_detectors(Vec::new());
        assert!(off.start_detecting(&target(), &[]).is_empty());
        assert_eq!((off.detector_count(), off.detections_started()), (0, 0));
        assert_eq!(off.detected(&target()).await, []);
        off.detections_ended(1).await;

        let failing = Arc::new(Fake {
            answer: Err("no".to_owned()),
            delay: Duration::ZERO,
            runs: AtomicU64::new(0),
        });
        let slow = Arc::new(Fake {
            delay: Duration::from_secs(30),
            ..Arc::try_unwrap(Fake::firing(&["x"]))
                .ok()
                .expect("one owner")
        });
        let (guard, buf) = crate::util::test_support::capture(tracing::Level::WARN);
        for (label, detector) in [("detect-fail", failing), ("detect-slow", slow)] {
            let analyser = made(label, 1 << 20, Arc::new(InProcess::new(8)))
                .with_deadline(Duration::from_millis(100))
                .with_detectors(vec![detector]);
            run_all(&analyser, &[]).await;
            assert_eq!(analyser.detected(&target()).await, [], "{label}");
        }
        let broken = made(
            "detect-broken",
            1 << 20,
            Arc::new(crate::analysis::store::tests::Broken),
        )
        .with_detectors(vec![Fake::firing(&["x"])]);
        run_all(&broken, &[]).await;
        assert_eq!(broken.detected(&target()).await, []);
        drop(guard);
        let log = crate::util::test_support::text(&buf);
        for said in [
            "detector did not run, nothing stored",
            "error.message=past its deadline",
            "detector: not stored",
            "analysis store cannot answer; the detector runs again",
        ] {
            assert!(log.contains(said), "{said}: {log}");
        }
    }
}
