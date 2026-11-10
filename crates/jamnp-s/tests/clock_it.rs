//! The clock is installed once per process, so the test that it reaches the
//! rest of the harness needs a process of its own.
//!
//! What it holds is the wiring, not the arithmetic (`clock`'s unit tests have
//! that): a clock installed at start-up is the one `trace`'s timestamps come
//! from, so a trace recorded on a virtual clock carries that clock's calendar
//! and the lanes' slot arithmetic stays coherent with the waits that produced
//! the frames.

use std::sync::Arc;
use std::time::Duration;

use jamnp_s::clock::{self, VirtualClock};
use jamnp_s::trace::{mono_ts, wall_ts};

/// A date well inside the JAM common era, so the slot it implies is a real
/// one rather than a negative number clamped to zero.
const ANCHOR_MS: u64 = 1_800_000_000_000;

#[tokio::test(start_paused = true)]
async fn the_trace_timestamps_follow_the_installed_clock() {
    let clock = Arc::new(VirtualClock::starting_at(ANCHOR_MS));
    clock::install(clock).expect("nothing has read the clock yet");

    assert_eq!(wall_ts(), ANCHOR_MS, "the trace reads the installed clock");
    assert_eq!(mono_ts(), 0);

    // One tiny epoch of waiting: 12 slots of 6 seconds.
    let before = std::time::Instant::now();
    for _ in 0..12 {
        clock::current().sleep(Duration::from_secs(6)).await;
    }

    assert_eq!(
        wall_ts(),
        ANCHOR_MS + 72_000,
        "an epoch of protocol time has passed on the trace's clock"
    );
    assert_eq!(mono_ts(), 72_000);
    assert!(
        before.elapsed() < Duration::from_secs(1),
        "and none of it cost real time"
    );
    assert!(
        clock::install(Arc::new(clock::SystemClock)).is_err(),
        "a run's calendar cannot be swapped once it has started"
    );
}
