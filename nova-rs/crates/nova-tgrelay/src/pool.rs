//! Pre-warmed tunnels, kept per `(dc, media)` pair.
//!
//! Layer 18, the policy half of `_TelegramWsPool`. Opening a WSS tunnel costs a
//! TLS handshake through the terminator plus a WebSocket upgrade, and a client
//! that has just started wants one immediately; the pool pays that cost ahead of
//! time. The connecting itself is I/O and stays out.
//!
//! Two rules that are easy to get wrong and are stated in the types:
//!
//! - **An entry that is too old or already closed is handed back to be closed,
//!   not dropped.** A WebSocket wants a close frame, and a pool that silently
//!   forgets its stale entries leaks a socket per eviction. [`Taken`] carries
//!   them out so the caller cannot fail to notice.
//! - **At most one refill per key is in flight.** Without the guard, every
//!   `take` on an empty bucket starts another one, and a cold start asking for
//!   four tunnels four times over opens sixteen.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// `WS_POOL_MAX_AGE`. Cloudflare and Telegram both drop idle upgrades well
/// before this; the number is a ceiling on how stale a "warm" tunnel may be, not
/// a promise about how long one lives.
pub const MAX_AGE: Duration = Duration::from_secs(120);
/// `proxy_config.pool_size`.
pub const DEFAULT_POOL_SIZE: usize = 4;

/// Which bucket an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub dc: u16,
    pub media: bool,
}

impl PoolKey {
    pub fn new(dc: u16, media: bool) -> Self {
        Self { dc, media }
    }
}

/// One pre-warmed tunnel and the route it was opened over.
#[derive(Debug)]
pub struct Warm<T> {
    pub value: T,
    /// `domain@ip via egress` — what the relay logs and keys health by.
    pub label: String,
    created: Instant,
}

impl<T> Warm<T> {
    pub fn new(value: T, label: impl Into<String>, created: Instant) -> Self {
        Self { value, label: label.into(), created }
    }

    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.created)
    }
}

/// The result of asking the pool for a tunnel.
///
/// `expired` is never empty by accident: whatever is in it has been taken out of
/// the pool and **must be closed by the caller**.
#[derive(Debug)]
pub struct Taken<T> {
    pub ready: Option<Warm<T>>,
    pub expired: Vec<Warm<T>>,
    /// True when the caller should start a refill. Already deduplicated against
    /// the ones in flight.
    pub refill: bool,
}

#[derive(Debug)]
pub struct WarmPool<T> {
    max_age: Duration,
    size: usize,
    idle: HashMap<PoolKey, VecDeque<Warm<T>>>,
    refilling: HashSet<PoolKey>,
}

impl<T> Default for WarmPool<T> {
    fn default() -> Self {
        Self::new(DEFAULT_POOL_SIZE, MAX_AGE)
    }
}

impl<T> WarmPool<T> {
    /// A `size` of zero disables the pool: nothing is kept and no refill is ever
    /// asked for.
    pub fn new(size: usize, max_age: Duration) -> Self {
        Self { max_age, size, idle: HashMap::new(), refilling: HashSet::new() }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn idle_count(&self, key: PoolKey) -> usize {
        self.idle.get(&key).map_or(0, VecDeque::len)
    }

    /// Take the oldest usable tunnel, evicting anything past its age.
    ///
    /// `is_dead` answers "has this one closed under us" — the pool cannot know,
    /// and a tunnel whose transport is already closing looks exactly like a fresh
    /// one from here.
    pub fn take(&mut self, key: PoolKey, now: Instant, is_dead: impl Fn(&T) -> bool) -> Taken<T> {
        let mut expired = Vec::new();
        let mut ready = None;
        if let Some(bucket) = self.idle.get_mut(&key) {
            while let Some(warm) = bucket.pop_front() {
                if warm.age(now) > self.max_age || is_dead(&warm.value) {
                    expired.push(warm);
                    continue;
                }
                ready = Some(warm);
                break;
            }
        }
        // Asked for either way: handing one out leaves a gap, and finding none
        // means the gap was already there.
        let refill = self.request_refill(key);
        Taken { ready, expired, refill }
    }

    /// Claim the right to refill `key`, or `false` if someone already has it.
    pub fn request_refill(&mut self, key: PoolKey) -> bool {
        if self.size == 0 || self.refilling.contains(&key) {
            return false;
        }
        self.refilling.insert(key);
        true
    }

    /// How many more this bucket wants. Call after claiming the refill.
    pub fn needed(&self, key: PoolKey) -> usize {
        self.size.saturating_sub(self.idle_count(key))
    }

    /// Put a freshly opened tunnel in.
    pub fn insert(&mut self, key: PoolKey, warm: Warm<T>) {
        self.idle.entry(key).or_default().push_back(warm);
    }

    /// Release the refill claim. **Must happen however the refill ended** — the
    /// Python does it in a `finally`, and a claim left behind stops that bucket
    /// ever being refilled again.
    pub fn finish_refill(&mut self, key: PoolKey) {
        self.refilling.remove(&key);
    }

    pub fn is_refilling(&self, key: PoolKey) -> bool {
        self.refilling.contains(&key)
    }

    /// Everything, for shutdown. The caller closes what comes back.
    pub fn drain(&mut self) -> Vec<Warm<T>> {
        self.refilling.clear();
        self.idle.drain().flat_map(|(_, bucket)| bucket).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: PoolKey = PoolKey { dc: 2, media: false };
    const MEDIA: PoolKey = PoolKey { dc: 2, media: true };

    fn alive(_: &u32) -> bool {
        false
    }

    fn dead(_: &u32) -> bool {
        true
    }

    fn warm(id: u32, now: Instant) -> Warm<u32> {
        Warm::new(id, format!("kws2.nova-app.eu@1.2.3.4 via warp-socks#{id}"), now)
    }

    #[test]
    fn a_fresh_tunnel_comes_straight_out() {
        let now = Instant::now();
        let mut pool = WarmPool::default();
        pool.insert(KEY, warm(1, now));
        let taken = pool.take(KEY, now, alive);
        assert_eq!(taken.ready.expect("ready").value, 1);
        assert!(taken.expired.is_empty());
        assert_eq!(pool.idle_count(KEY), 0);
    }

    #[test]
    fn the_oldest_is_used_first() {
        let now = Instant::now();
        let mut pool = WarmPool::default();
        pool.insert(KEY, warm(1, now));
        pool.insert(KEY, warm(2, now));
        assert_eq!(pool.take(KEY, now, alive).ready.expect("ready").value, 1);
        pool.finish_refill(KEY);
        assert_eq!(pool.take(KEY, now, alive).ready.expect("ready").value, 2);
    }

    #[test]
    fn an_entry_past_its_age_is_handed_back_to_be_closed_not_dropped() {
        // A pool that silently forgets stale entries leaks a socket per eviction,
        // and a WebSocket wants a close frame rather than a dropped handle.
        let now = Instant::now();
        let mut pool = WarmPool::default();
        pool.insert(KEY, warm(1, now));
        pool.insert(KEY, warm(2, now + MAX_AGE));
        let taken = pool.take(KEY, now + MAX_AGE + Duration::from_secs(1), alive);
        assert_eq!(taken.expired.iter().map(|w| w.value).collect::<Vec<_>>(), [1]);
        assert_eq!(taken.ready.expect("ready").value, 2, "the second is still inside its age");
    }

    #[test]
    fn one_that_closed_under_us_is_evicted_too() {
        let now = Instant::now();
        let mut pool = WarmPool::default();
        pool.insert(KEY, warm(1, now));
        let taken = pool.take(KEY, now, dead);
        assert!(taken.ready.is_none());
        assert_eq!(taken.expired.len(), 1, "closed, not stale, and still ours to close");
    }

    #[test]
    fn an_empty_bucket_still_asks_for_a_refill() {
        let now = Instant::now();
        let mut pool = WarmPool::<u32>::default();
        let taken = pool.take(KEY, now, alive);
        assert!(taken.ready.is_none());
        assert!(taken.refill, "finding none means the gap was already there");
    }

    #[test]
    fn only_one_refill_per_key_is_ever_in_flight() {
        // Without this, a cold start asking four times for four tunnels opens
        // sixteen.
        let now = Instant::now();
        let mut pool = WarmPool::<u32>::default();
        assert!(pool.take(KEY, now, alive).refill);
        assert!(!pool.take(KEY, now, alive).refill, "already claimed");
        assert!(pool.is_refilling(KEY));
        // A different bucket is unaffected.
        assert!(pool.take(MEDIA, now, alive).refill);

        pool.finish_refill(KEY);
        assert!(pool.take(KEY, now, alive).refill, "the claim was released");
    }

    #[test]
    fn a_pool_of_zero_never_asks_for_anything() {
        let now = Instant::now();
        let mut pool = WarmPool::<u32>::new(0, MAX_AGE);
        assert!(!pool.take(KEY, now, alive).refill);
        assert!(!pool.request_refill(KEY));
        assert_eq!(pool.needed(KEY), 0);
    }

    #[test]
    fn needed_counts_the_gap_and_never_goes_negative() {
        let now = Instant::now();
        let mut pool = WarmPool::new(4, MAX_AGE);
        assert_eq!(pool.needed(KEY), 4);
        for id in 0..6 {
            pool.insert(KEY, warm(id, now));
        }
        assert_eq!(pool.needed(KEY), 0, "already over the target, so nothing is wanted");
    }

    #[test]
    fn buckets_do_not_leak_into_each_other() {
        let now = Instant::now();
        let mut pool = WarmPool::default();
        pool.insert(KEY, warm(1, now));
        assert!(pool.take(MEDIA, now, alive).ready.is_none(), "media is its own bucket");
        assert_eq!(pool.idle_count(KEY), 1);
    }

    #[test]
    fn draining_hands_everything_back_and_forgets_the_claims() {
        let now = Instant::now();
        let mut pool = WarmPool::default();
        pool.insert(KEY, warm(1, now));
        pool.insert(MEDIA, warm(2, now));
        pool.request_refill(KEY);
        let mut ids: Vec<u32> = pool.drain().into_iter().map(|w| w.value).collect();
        ids.sort_unstable();
        assert_eq!(ids, [1, 2]);
        assert!(!pool.is_refilling(KEY));
        assert_eq!(pool.idle_count(KEY), 0);
    }

    #[test]
    fn a_label_travels_with_the_tunnel() {
        // It is what the relay logs and what the health tables are keyed by; a
        // pooled tunnel that lost its label would be credited to nothing.
        let now = Instant::now();
        let mut pool = WarmPool::default();
        pool.insert(KEY, Warm::new(7u32, "kws2.nova-app.eu@1.2.3.4 via opera-http", now));
        let ready = pool.take(KEY, now, alive).ready.expect("ready");
        assert_eq!(ready.label, "kws2.nova-app.eu@1.2.3.4 via opera-http");
    }
}
