//! Pause, resume, cancel and throttle for long-running jobs.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct JobControl {
    cancelled: AtomicBool,
    paused: AtomicBool,
    /// Bytes per second; 0 = unlimited. Adjustable while running.
    rate_limit: AtomicU64,
}

impl JobControl {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }
    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }
    pub fn set_rate_limit(&self, bytes_per_sec: u64) {
        self.rate_limit.store(bytes_per_sec, Ordering::SeqCst);
    }

    /// Block while paused. Returns false if cancelled.
    pub(crate) fn checkpoint(&self) -> bool {
        while self.is_paused() && !self.is_cancelled() {
            std::thread::sleep(Duration::from_millis(100));
        }
        !self.is_cancelled()
    }
}

/// Token-bucket style throttle used by a single reader thread.
pub(crate) struct Throttle {
    start: Instant,
    bytes: u64,
}

impl Throttle {
    pub fn new() -> Self {
        Throttle {
            start: Instant::now(),
            bytes: 0,
        }
    }

    pub fn account(&mut self, n: u64, ctl: &JobControl) {
        self.bytes += n;
        let rate = ctl.rate_limit.load(Ordering::Relaxed);
        if rate == 0 {
            return;
        }
        let due = Duration::from_secs_f64(self.bytes as f64 / rate as f64);
        let elapsed = self.start.elapsed();
        if due > elapsed {
            std::thread::sleep(due - elapsed);
        }
    }
}
