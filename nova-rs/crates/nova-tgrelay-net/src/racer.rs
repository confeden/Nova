//! Layer 27: running the race plan.
//!
//! The executing half of `_connect_cf_ws_route` (`transparent_relay.py:3646`).
//! Layer 17 decided *what* races *what*; this dials it. Layer 26 is what each
//! candidate ends up calling.
//!
//! **First to answer wins, and the losers are the interesting part.** A race
//! that returns the winner and forgets the rest leaks a socket per candidate,
//! and on this path a socket is a Worker invocation that has to be closed with a
//! frame rather than dropped. So the losers are drained in the background: the
//! caller gets its tunnel immediately, and whatever the others eventually do is
//! dealt with afterwards — a late success is closed, a late failure benches its
//! domain, and a candidate that was abandoned mid-dial is charged nothing.
//!
//! **Being abandoned is not evidence.** The Python spells this
//! `except asyncio.CancelledError: continue` and it is the same rule as the
//! exclusion set in layer 17: "we stopped waiting for you" and "you are
//! unhealthy" are different claims, and conflating them would bench the whole
//! field every time the first candidate answered quickly.
//!
//! **One difference from the Python, and it is a defect there.** On the
//! out-of-budget path the Python hands its cleanup the *whole* task list rather
//! than the still-pending part, so a candidate that had already failed earlier in
//! the same batch is benched a second time — `_cf_note_bad_domain` extends the
//! TTL and halves the score again, so that domain ends up at a quarter of its
//! score for one failure. Here a [`JoinSet`] consumes each task exactly once, so
//! the double charge cannot happen; nothing had to be written to avoid it.
//!
//! **One guard here is deliberately redundant.** The budget is checked once
//! before each wait *and* by the wait itself, and a mutation removing the first
//! check survives: `timeout_at` polls the inner future before its timer, so the
//! only schedule the check catches on its own is a result landing in the same
//! instant the clock expires. It is kept because that schedule is real, because
//! the Python states the rule explicitly (`if wait_timeout <= 0.0`), and because
//! the alternative is a test that asserts a task-wake ordering. Labelled rather
//! than deleted, and rather than pretended to be covered.

use nova_tgrelay::race::RacePlan;
use std::future::Future;
use tokio::task::JoinSet;
use tokio::time::{timeout_at, Instant};

/// What the race needs from the world.
///
/// A trait rather than three closures because all three have to survive into a
/// detached task that outlives the call, and `Clone + Send + Sync + 'static` is
/// easier to state once than three times.
pub trait Candidates: Clone + Send + Sync + 'static {
    type Conn: Send + 'static;
    type Error: Send + 'static;

    /// Open one candidate. On success, the connection and the label of the
    /// egress that carried it — that label is what the `via` field of the log
    /// line says and what the health tables are keyed by.
    fn open(&self, domain: String) -> impl Future<Output = Result<(Self::Conn, String), Self::Error>> + Send;

    /// Close a connection that lost.
    ///
    /// A round trip, not a drop: a WebSocket wants a close frame, and a peer
    /// that only sees the TCP disappear keeps the Worker invocation alive on its
    /// side for as long as its own idle timer says.
    fn close(&self, conn: Self::Conn) -> impl Future<Output = ()> + Send;

    /// Send a domain to the bench. Called only for a candidate that genuinely
    /// failed.
    fn bench(&self, domain: &str);
}

/// The candidate that answered.
#[derive(Debug)]
pub struct Won<C> {
    pub domain: String,
    pub conn: C,
    /// The egress label, from [`Candidates::open`].
    pub label: String,
    /// How wide the batch it came out of was. The Python logs this as
    /// `source=race width=N`, and it is the only thing in the line that says
    /// whether the race did any work or the plan had already narrowed to one.
    pub width: usize,
}

/// How the race ended.
#[derive(Debug)]
pub enum RaceOutcome<C> {
    Won(Won<C>),
    /// Every candidate in every batch was tried and none answered.
    Exhausted,
    /// The whole-race ceiling ran out first. Only media has one.
    ///
    /// The Python cannot tell this from [`RaceOutcome::Exhausted`] — both are
    /// `return None, ""` — but they mean opposite things about the field: one
    /// says the candidates are bad, the other says they were never asked.
    OutOfBudget,
}

impl<C> RaceOutcome<C> {
    pub fn won(self) -> Option<Won<C>> {
        match self {
            Self::Won(w) => Some(w),
            _ => None,
        }
    }
}

/// The candidates of one batch, in flight.
///
/// Named because it appears in three signatures and clippy is right that the
/// bare form is unreadable: each task carries the domain it was dialling, so a
/// result can be attributed without a lookup table beside the set — which is
/// what the Python needs (`next((item for item_task, item in task_domains ...`)
/// and what makes its cleanup take the wrong list.
type Running<C> = JoinSet<(String, Result<(<C as Candidates>::Conn, String), <C as Candidates>::Error>)>;

/// Dial the plan, batch by batch, and return the first candidate that answers.
pub async fn race<C: Candidates>(plan: &RacePlan, candidates: &C) -> RaceOutcome<C::Conn> {
    // Computed once, before the first dial: the ceiling is on the whole race,
    // however many batches it takes, not on each batch in turn.
    let deadline = plan.total_budget.map(|budget| Instant::now() + budget);

    for batch in &plan.batches {
        let width = batch.len();
        let mut running: Running<C> = JoinSet::new();
        for domain in batch {
            let candidates = candidates.clone();
            let domain = domain.clone();
            running.spawn(async move {
                let outcome = candidates.open(domain.clone()).await;
                (domain, outcome)
            });
        }

        while !running.is_empty() {
            // Checked before waiting as well as by the wait itself: an expired
            // budget must not buy one more `join_next` that happens to be ready.
            if deadline.is_some_and(|dl| Instant::now() >= dl) {
                abandon(running, candidates);
                return RaceOutcome::OutOfBudget;
            }
            let joined = match deadline {
                Some(dl) => match timeout_at(dl, running.join_next()).await {
                    Ok(joined) => joined,
                    Err(_) => {
                        abandon(running, candidates);
                        return RaceOutcome::OutOfBudget;
                    }
                },
                None => running.join_next().await,
            };
            let Some(joined) = joined else { break };
            match joined {
                // Abandoned, or panicked. Neither says anything about the
                // domain: the first is our decision and the second is our bug.
                Err(_) => continue,
                Ok((domain, Err(_))) => candidates.bench(&domain),
                Ok((domain, Ok((conn, label)))) => {
                    if !running.is_empty() {
                        // The siblings keep running. They are not cancelled: one
                        // of them may be a handshake away from an open Worker
                        // socket, and dropping it there leaves the far side
                        // holding an invocation nobody closed.
                        drain(running, candidates.clone());
                    }
                    return RaceOutcome::Won(Won { domain, conn, label, width });
                }
            }
        }
    }
    RaceOutcome::Exhausted
}

/// Stop waiting for everything still in flight, then tidy up after it.
fn abandon<C: Candidates>(mut running: Running<C>, candidates: &C) {
    running.abort_all();
    drain(running, candidates.clone());
}

/// Deal with the candidates the race no longer needs, off the caller's path.
///
/// Detached on purpose: the winner is already open and the client is waiting on
/// it, so whatever a loser does next must not be in front of the first byte.
fn drain<C: Candidates>(mut running: Running<C>, candidates: C) {
    tokio::spawn(async move {
        while let Some(joined) = running.join_next().await {
            match joined {
                Err(_) => {}
                Ok((domain, Err(_))) => candidates.bench(&domain),
                Ok((_domain, Ok((conn, _label)))) => candidates.close(conn).await,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_tgrelay::race::{plan, DEFAULT_RACE_WIDTH};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::time::{sleep, Duration};

    /// What one candidate is scripted to do.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Act {
        Succeeds,
        Fails,
        /// Our own bug, not the domain's. Kept in the vocabulary because the
        /// race has to answer it, and the answer is "charge nobody".
        Panics,
    }

    #[derive(Debug, Clone)]
    struct Script {
        after: Duration,
        act: Act,
    }

    #[derive(Debug, Default)]
    struct Seen {
        opened: Vec<String>,
        benched: Vec<String>,
        closed: Vec<String>,
    }

    #[derive(Clone)]
    struct Fake {
        script: Arc<HashMap<String, Script>>,
        seen: Arc<Mutex<Seen>>,
    }

    impl Fake {
        fn new(script: &[(&str, u64, Act)]) -> Self {
            Self {
                script: Arc::new(
                    script
                        .iter()
                        .map(|(d, ms, act)| {
                            ((*d).to_string(), Script { after: Duration::from_millis(*ms), act: *act })
                        })
                        .collect(),
                ),
                seen: Arc::new(Mutex::new(Seen::default())),
            }
        }

        fn seen(&self) -> Seen {
            let s = self.seen.lock().expect("lock");
            Seen { opened: s.opened.clone(), benched: s.benched.clone(), closed: s.closed.clone() }
        }
    }

    impl Candidates for Fake {
        /// The "connection" is the domain that produced it, so a close can be
        /// attributed.
        type Conn = String;
        type Error = ();

        async fn open(&self, domain: String) -> Result<(String, String), ()> {
            self.seen.lock().expect("lock").opened.push(domain.clone());
            let script = self.script.get(&domain).cloned().expect("every candidate is scripted");
            sleep(script.after).await;
            match script.act {
                Act::Succeeds => Ok((domain, "warp-socks".to_string())),
                Act::Fails => Err(()),
                Act::Panics => panic!("the opener fell over"),
            }
        }

        async fn close(&self, conn: String) {
            self.seen.lock().expect("lock").closed.push(conn);
        }

        fn bench(&self, domain: &str) {
            self.seen.lock().expect("lock").benched.push(domain.to_string());
        }
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    const OWNED: &[&str] = &["nova-app.eu"];

    /// Let the detached drain finish before asserting on what it did.
    async fn settle() {
        for _ in 0..40 {
            tokio::task::yield_now().await;
            sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn the_first_candidate_to_answer_wins() {
        let fake = Fake::new(&[("a.pclead.co.uk", 80, Act::Succeeds), ("b.offshor.co.uk", 5, Act::Succeeds)]);
        let plan = plan(&names(&["a.pclead.co.uk", "b.offshor.co.uk"]), false, false, OWNED, DEFAULT_RACE_WIDTH);
        let won = race(&plan, &fake).await.won().expect("one of them answered");
        assert_eq!(won.domain, "b.offshor.co.uk", "not the one that was listed first");
        assert_eq!(won.label, "warp-socks");
        assert_eq!(won.width, 2);
    }

    #[tokio::test]
    async fn a_loser_that_answers_late_is_closed_rather_than_leaked() {
        // The whole reason the losers are drained instead of dropped: on this
        // path an open connection is a Worker invocation, and the far side keeps
        // it until something says otherwise.
        let fake = Fake::new(&[("a.pclead.co.uk", 60, Act::Succeeds), ("b.offshor.co.uk", 5, Act::Succeeds)]);
        let plan = plan(&names(&["a.pclead.co.uk", "b.offshor.co.uk"]), false, false, OWNED, DEFAULT_RACE_WIDTH);
        let won = race(&plan, &fake).await.won().expect("a winner");
        assert_eq!(won.domain, "b.offshor.co.uk");
        settle().await;
        assert_eq!(fake.seen().closed, ["a.pclead.co.uk"], "the slower success was closed");
        assert!(fake.seen().benched.is_empty(), "losing a race is not a health verdict");
    }

    #[tokio::test]
    async fn the_winner_is_returned_without_waiting_for_the_losers() {
        let fake = Fake::new(&[("a.pclead.co.uk", 400, Act::Succeeds), ("b.offshor.co.uk", 5, Act::Succeeds)]);
        let plan = plan(&names(&["a.pclead.co.uk", "b.offshor.co.uk"]), false, false, OWNED, DEFAULT_RACE_WIDTH);
        let started = Instant::now();
        let _won = race(&plan, &fake).await.won().expect("a winner");
        assert!(started.elapsed() < Duration::from_millis(200), "the slow sibling was not waited on");
    }

    #[tokio::test]
    async fn a_failed_candidate_is_benched_and_the_batch_carries_on() {
        let fake = Fake::new(&[("a.pclead.co.uk", 5, Act::Fails), ("b.offshor.co.uk", 40, Act::Succeeds)]);
        let plan = plan(&names(&["a.pclead.co.uk", "b.offshor.co.uk"]), false, false, OWNED, DEFAULT_RACE_WIDTH);
        let won = race(&plan, &fake).await.won().expect("the second one answered");
        assert_eq!(won.domain, "b.offshor.co.uk");
        assert_eq!(fake.seen().benched, ["a.pclead.co.uk"]);
    }

    #[tokio::test]
    async fn a_batch_where_everything_fails_moves_on_to_the_next_one() {
        let fake = Fake::new(&[("a.x", 5, Act::Fails), ("b.x", 5, Act::Fails), ("c.x", 5, Act::Fails), ("d.x", 5, Act::Succeeds)]);
        let plan = plan(&names(&["a.x", "b.x", "c.x", "d.x"]), false, false, OWNED, DEFAULT_RACE_WIDTH);
        assert_eq!(plan.batches.len(), 2, "three then one");
        let won = race(&plan, &fake).await.won().expect("the second batch answered");
        assert_eq!(won.domain, "d.x");
        assert_eq!(won.width, 1, "the width logged is the batch it came from, not the plan");
        let benched = fake.seen().benched;
        assert_eq!(benched.len(), 3);
        assert!(benched.contains(&"a.x".to_string()));
    }

    #[tokio::test]
    async fn every_candidate_failing_is_exhausted_and_not_out_of_budget() {
        let fake = Fake::new(&[("a.x", 5, Act::Fails), ("b.x", 5, Act::Fails)]);
        let plan = plan(&names(&["a.x", "b.x"]), false, false, OWNED, DEFAULT_RACE_WIDTH);
        assert!(matches!(race(&plan, &fake).await, RaceOutcome::Exhausted));
        assert_eq!(fake.seen().benched.len(), 2, "each failure is charged exactly once");
    }

    #[tokio::test]
    async fn the_media_ceiling_ends_the_whole_race_and_not_just_the_batch() {
        // Media is on a clock because it has a plain-TCP fallback: a slow race
        // costs more there than a missed candidate. Every candidate is slower
        // than the ceiling, so the second batch must never be dialled.
        let fake = Fake::new(&[
            ("kws2-1.nova-app.eu", 10_000, Act::Succeeds),
            ("kws5-1.nova-app.eu", 10_000, Act::Succeeds),
            ("a.pclead.co.uk", 10_000, Act::Succeeds),
        ]);
        let mut plan = plan(
            &names(&["kws2-1.nova-app.eu", "kws5-1.nova-app.eu", "a.pclead.co.uk"]),
            true,
            false,
            OWNED,
            DEFAULT_RACE_WIDTH,
        );
        assert_eq!(plan.batches.len(), 3, "media gives the owned siblings a batch each");
        plan.total_budget = Some(Duration::from_millis(120));

        let started = Instant::now();
        assert!(matches!(race(&plan, &fake).await, RaceOutcome::OutOfBudget));
        assert!(started.elapsed() < Duration::from_millis(600), "it stopped at the ceiling");
        assert_eq!(fake.seen().opened, ["kws2-1.nova-app.eu"], "the later batches were never dialled");
    }

    #[tokio::test]
    async fn a_budget_already_spent_dials_nothing_it_cannot_afford() {
        let fake = Fake::new(&[("a.x", 50, Act::Succeeds)]);
        let mut plan = plan(&names(&["a.x"]), true, false, OWNED, DEFAULT_RACE_WIDTH);
        plan.total_budget = Some(Duration::ZERO);
        assert!(matches!(race(&plan, &fake).await, RaceOutcome::OutOfBudget));
        settle().await;
        assert!(fake.seen().benched.is_empty(), "an abandoned candidate is charged nothing");
    }

    #[tokio::test]
    async fn a_candidate_abandoned_at_the_ceiling_is_not_charged_for_it() {
        // The rule stated on its own: `except asyncio.CancelledError: continue`.
        // Benching here would demote the whole field every time media ran out of
        // clock, which is exactly when the field is most needed.
        let fake = Fake::new(&[("a.x", 10_000, Act::Fails), ("b.x", 10_000, Act::Fails)]);
        let mut plan = plan(&names(&["a.x", "b.x"]), true, false, OWNED, DEFAULT_RACE_WIDTH);
        plan.total_budget = Some(Duration::from_millis(80));
        assert!(matches!(race(&plan, &fake).await, RaceOutcome::OutOfBudget));
        settle().await;
        assert!(fake.seen().benched.is_empty(), "{:?}", fake.seen().benched);
    }

    #[tokio::test]
    async fn media_dials_the_owned_siblings_one_at_a_time() {
        // Layer 17's rule, observed rather than asserted on the plan: racing
        // them doubles the Worker invocations, which are the metered resource.
        let fake = Fake::new(&[
            ("kws2-1.nova-app.eu", 5, Act::Fails),
            ("kws5-1.nova-app.eu", 5, Act::Succeeds),
            ("a.pclead.co.uk", 5, Act::Succeeds),
        ]);
        let plan = plan(
            &names(&["kws2-1.nova-app.eu", "kws5-1.nova-app.eu", "a.pclead.co.uk"]),
            true,
            false,
            OWNED,
            DEFAULT_RACE_WIDTH,
        );
        let won = race(&plan, &fake).await.won().expect("the sibling answered");
        assert_eq!(won.domain, "kws5-1.nova-app.eu");
        assert_eq!(won.width, 1, "a batch of one is not a race");
        assert_eq!(
            fake.seen().opened,
            ["kws2-1.nova-app.eu", "kws5-1.nova-app.eu"],
            "the third was never needed, so it was never invoked"
        );
    }

    #[tokio::test]
    async fn a_candidate_whose_opener_panics_is_charged_to_nobody() {
        // Written because a mutation proved nothing covered it: a panic is our
        // bug, and benching the domain for it would retire a working Worker
        // every time the port had a defect.
        let fake = Fake::new(&[("a.x", 5, Act::Panics), ("b.x", 40, Act::Succeeds)]);
        let plan = plan(&names(&["a.x", "b.x"]), false, false, OWNED, DEFAULT_RACE_WIDTH);
        let won = race(&plan, &fake).await.won().expect("the sibling still answered");
        assert_eq!(won.domain, "b.x");
        assert!(fake.seen().benched.is_empty(), "{:?}", fake.seen().benched);
    }

    #[tokio::test]
    async fn a_loser_that_fails_late_is_benched_by_the_drain() {
        // The other half of the drain, and the half a mutation showed untested:
        // a candidate that loses the race and *then* fails is still evidence
        // about that domain, so the verdict has to survive the handover to the
        // background task.
        let fake = Fake::new(&[("slow.x", 60, Act::Fails), ("fast.x", 5, Act::Succeeds)]);
        let plan = plan(&names(&["slow.x", "fast.x"]), false, false, OWNED, DEFAULT_RACE_WIDTH);
        let won = race(&plan, &fake).await.won().expect("a winner");
        assert_eq!(won.domain, "fast.x");
        assert!(fake.seen().benched.is_empty(), "not yet — the loser is still dialling");
        settle().await;
        assert_eq!(fake.seen().benched, ["slow.x"], "the late failure still counts");
    }

    #[tokio::test]
    async fn a_candidate_abandoned_at_the_ceiling_is_really_stopped() {
        // Not merely ignored. Left running it would finish, open a Worker
        // invocation nobody wants, and have to be closed again — which is what
        // the ceiling exists to avoid paying for. Waited on for far longer than
        // the candidate needed, so "it never completed" is a claim and not a
        // race.
        let fake = Fake::new(&[("slow.x", 150, Act::Succeeds)]);
        let mut plan = plan(&names(&["slow.x"]), true, false, OWNED, DEFAULT_RACE_WIDTH);
        plan.total_budget = Some(Duration::from_millis(60));
        assert!(matches!(race(&plan, &fake).await, RaceOutcome::OutOfBudget));
        sleep(Duration::from_millis(400)).await;
        settle().await;
        assert_eq!(fake.seen().opened, ["slow.x"], "it was dialled");
        assert!(fake.seen().closed.is_empty(), "and stopped before it could open anything");
    }

    #[tokio::test]
    async fn an_empty_plan_is_exhausted_without_dialling_anything() {
        let fake = Fake::new(&[]);
        let plan = plan(&[], false, false, OWNED, DEFAULT_RACE_WIDTH);
        assert!(matches!(race(&plan, &fake).await, RaceOutcome::Exhausted));
        assert!(fake.seen().opened.is_empty());
    }

    #[tokio::test]
    async fn the_ceiling_is_on_the_whole_race_and_not_refreshed_per_batch() {
        // Three batches of one, each taking 100 ms to fail, under a 250 ms
        // ceiling. Spent once, the third batch is cut off mid-dial; refreshed
        // per batch it would finish and the race would end `Exhausted` instead
        // — the same answer as "all candidates are bad", which is the one thing
        // an expired budget must not be confused with.
        let fake = Fake::new(&[("a.x", 100, Act::Fails), ("b.x", 100, Act::Fails), ("c.x", 100, Act::Fails)]);
        let mut plan = plan(&names(&["a.x", "b.x", "c.x"]), false, false, OWNED, 1);
        assert_eq!(plan.batches.len(), 3);
        plan.total_budget = Some(Duration::from_millis(250));
        assert!(matches!(race(&plan, &fake).await, RaceOutcome::OutOfBudget));
    }

    #[tokio::test]
    async fn a_failure_inside_a_timed_out_batch_is_charged_once_and_not_twice() {
        // The Python's out-of-budget cleanup is handed the whole task list, so a
        // candidate that had already failed is benched again — its score halved
        // twice for one failure. Stated here because the port not doing it is a
        // deliberate difference, not an accident of the runtime.
        let fake = Fake::new(&[("a.x", 10, Act::Fails), ("b.x", 10_000, Act::Succeeds)]);
        let mut plan = plan(&names(&["a.x", "b.x"]), true, false, OWNED, DEFAULT_RACE_WIDTH);
        plan.total_budget = Some(Duration::from_millis(120));
        assert!(matches!(race(&plan, &fake).await, RaceOutcome::OutOfBudget));
        settle().await;
        assert_eq!(fake.seen().benched, ["a.x"], "once");
    }
}
