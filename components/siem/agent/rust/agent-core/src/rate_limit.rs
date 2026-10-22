use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct RateLimiter {
    max_per_minute: u32,
    tokens: u32,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            tokens: max_per_minute,
            last_refill: Instant::now(),
        }
    }

    pub fn allow(&mut self) -> bool {
        self.refill();
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed();
        if elapsed < Duration::from_secs(60) {
            return;
        }

        self.tokens = self.max_per_minute;
        self.last_refill = Instant::now();
    }
}
