//! Where "now" and "wait" come from.
//!
//! A run is a calendar: which slot a frame belongs to, when a ticket is due,
//! how long to watch. [`SystemClock`] grades a real node, whose slots really
//! do take six seconds. [`VirtualClock`] moves only when the runtime moves
//! it, so a run against a *simulated* node costs what the computation costs.
//!
//! **One clock per process.** [`install`] sets it before anything reads it;
//! [`current`] returns it. Global because what it replaces -- `trace::mono_ts`
//! and `trace::wall_ts` -- is read from a dozen places that have no business
//! taking a clock argument.
//!
//! Only the protocol's own waits moved onto it. Waiting for a node *process*
//! to start, or a port to answer, is about another program on this machine and
//! stays on the real clock.

use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;

/// Where "now" and "wait" come from.
#[async_trait]
pub trait Clock: Send + Sync + fmt::Debug {
    /// Milliseconds since the Unix epoch. Slots are defined against the
    /// common era, so the whole calendar follows from it.
    fn wall_ms(&self) -> u64;

    /// Milliseconds since this clock started: for ordering and durations
    /// within a run, not comparable across runs.
    fn mono_ms(&self) -> u64;

    /// Wait for `d` to pass on this clock.
    async fn sleep(&self, d: Duration);
}

/// The machine's clock: real seconds, as a real node experiences them.
#[derive(Debug, Default)]
pub struct SystemClock;

#[async_trait]
impl Clock for SystemClock {
    fn wall_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }

    fn mono_ms(&self) -> u64 {
        // Fixed at first use, so every reading shares one zero.
        static ORIGIN: OnceLock<std::time::Instant> = OnceLock::new();
        ORIGIN
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis() as u64
    }

    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

/// Time that moves only when the runtime moves it.
///
/// Built on tokio's timer rather than a wheel of our own: on a runtime started
/// with `start_paused`, time does not follow the machine's clock, and when
/// every task is waiting the runtime jumps to the earliest deadline. The
/// ordering and wake-ups stay the runtime's, which is the part worth not
/// reimplementing.
///
/// On an ordinary runtime it is a [`SystemClock`] with an anchored date --
/// correct, just not fast. The anchor is what makes a run reproducible: slot
/// numbers follow from the wall date.
#[derive(Debug)]
pub struct VirtualClock {
    anchor_wall_ms: u64,
    origin: tokio::time::Instant,
}

impl VirtualClock {
    /// Reads `wall_ms` now. Call it on the runtime that will use it: the
    /// origin is taken here.
    pub fn starting_at(wall_ms: u64) -> Self {
        Self {
            anchor_wall_ms: wall_ms,
            origin: tokio::time::Instant::now(),
        }
    }
}

#[async_trait]
impl Clock for VirtualClock {
    fn wall_ms(&self) -> u64 {
        self.anchor_wall_ms.saturating_add(self.mono_ms())
    }

    fn mono_ms(&self) -> u64 {
        tokio::time::Instant::now()
            .saturating_duration_since(self.origin)
            .as_millis() as u64
    }

    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

static INSTALLED: OnceLock<Arc<dyn Clock>> = OnceLock::new();

/// Install the clock for this process.
///
/// `Err` if one is already installed: a calendar that changed mid-run would
/// make the trace's own timestamps incomparable. Reading [`current`] installs
/// the default, so install before anything reads the time.
pub fn install(clock: Arc<dyn Clock>) -> Result<(), AlreadyInstalled> {
    INSTALLED.set(clock).map_err(|_| AlreadyInstalled)
}

/// The installed clock, or the machine's if none was installed.
pub fn current() -> Arc<dyn Clock> {
    Arc::clone(INSTALLED.get_or_init(|| Arc::new(SystemClock)))
}

/// A clock was already installed, or one had already been read.
#[derive(Debug, thiserror::Error)]
#[error("a clock is already installed for this process")]
pub struct AlreadyInstalled;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_system_clock_reports_a_real_date() {
        let clock = SystemClock;
        // Any date after this code was written; the point is that it is a
        // Unix millisecond and not an offset from something.
        assert!(clock.wall_ms() > 1_700_000_000_000);
    }

    #[tokio::test(start_paused = true)]
    async fn a_virtual_clock_reads_its_anchor_before_anything_waits() {
        let clock = VirtualClock::starting_at(1_000_000);
        assert_eq!(clock.wall_ms(), 1_000_000);
        assert_eq!(clock.mono_ms(), 0);
    }

    /// The property the whole seam is for: a wait that would cost a minute of
    /// real time costs none, and the clock still says a minute passed.
    #[tokio::test(start_paused = true)]
    async fn a_virtual_sleep_advances_the_clock_without_spending_the_time() {
        let clock = VirtualClock::starting_at(1_000_000);
        let before = std::time::Instant::now();
        clock.sleep(Duration::from_secs(60)).await;
        assert_eq!(clock.mono_ms(), 60_000);
        assert_eq!(clock.wall_ms(), 1_060_000);
        assert!(
            before.elapsed() < Duration::from_secs(1),
            "a virtual minute must not cost a real one"
        );
    }

    /// Sleeps compose: an epoch of tiny slots is 72 virtual seconds and no
    /// real ones, which is what a simulated run is made of.
    #[tokio::test(start_paused = true)]
    async fn virtual_sleeps_accumulate() {
        let clock = VirtualClock::starting_at(0);
        for _ in 0..12 {
            clock.sleep(Duration::from_secs(6)).await;
        }
        assert_eq!(clock.wall_ms(), 72_000);
    }

    #[tokio::test]
    async fn the_default_clock_is_the_machines() {
        // `current` installs the default on first read, so this also holds
        // the documented behaviour that reading settles the choice.
        assert!(current().wall_ms() > 1_700_000_000_000);
        assert!(install(Arc::new(SystemClock)).is_err());
    }
}
