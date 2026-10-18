//! Hybrid logical clock (P22): the wall-clock time in milliseconds in the
//! upper 48 bits and a counter in the lower 16. Values only ever increase,
//! even when the device's clock is set back, and stay close to real time.

use std::time::{SystemTime, UNIX_EPOCH};

/// Where the time comes from; tests drive it by hand.
#[derive(Clone, Debug)]
pub(crate) enum Clock {
    System,
    #[cfg(test)]
    Manual(std::sync::Arc<std::sync::atomic::AtomicU64>),
}

impl Clock {
    pub(crate) fn now_ms(&self) -> u64 {
        match self {
            Clock::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            #[cfg(test)]
            Clock::Manual(t) => t.load(std::sync::atomic::Ordering::SeqCst),
        }
    }
}

/// The next clock value after `last`.
pub(crate) fn next(last: u64, now_ms: u64) -> u64 {
    let physical = (now_ms & ((1 << 48) - 1)) << 16;
    if physical > last { physical } else { last + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn millis(hlc: u64) -> u64 {
        hlc >> 16
    }

    #[test]
    fn follows_the_clock_and_never_goes_back() {
        let a = next(0, 10_000_000);
        assert_eq!(millis(a), 10_000_000);
        // Same millisecond: the counter moves.
        let b = next(a, 10_000_000);
        assert_eq!(b, a + 1);
        // The clock is set back an hour: still increasing.
        let c = next(b, 10_000_000 - 3_600_000);
        assert!(c > b);
        assert_eq!(millis(c), 10_000_000);
        // Real time catches up again.
        let d = next(c, 10_005_000);
        assert_eq!(millis(d), 10_005_000);
        assert!(d > c);
    }

    #[test]
    fn many_values_in_one_millisecond_stay_ordered() {
        let mut last = 0;
        for _ in 0..100_000 {
            let n = next(last, 42);
            assert!(n > last);
            last = n;
        }
    }

    #[test]
    fn system_clock_is_after_2025() {
        assert!(Clock::System.now_ms() > 1_735_689_600_000);
    }
}
