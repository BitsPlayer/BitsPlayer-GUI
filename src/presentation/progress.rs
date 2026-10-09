use std::sync::{Arc, Mutex};

use iframe_extract::report::Reporter;

#[derive(Default)]
pub struct Progress {
    pub phase: String,
    pub done: u64,
    pub total: u64,
    pub detail: String,
}

impl Progress {
    pub fn percent(&self) -> u64 {
        if self.total > 0 {
            (self.done.saturating_mul(100) / self.total).min(100)
        } else {
            0
        }
    }

    pub fn reset(&mut self, phase: &str) {
        self.phase = phase.to_string();
        self.done = 0;
        self.total = 0;
        self.detail.clear();
    }
}

#[derive(Clone, Default)]
pub struct ChannelReporter {
    pub inner: Arc<Mutex<Progress>>,
}

impl Reporter for ChannelReporter {
    fn phase(&mut self, name: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.reset(name);
        }
    }

    fn progress(&mut self, done: u64, total: u64, detail: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.done = done;
            g.total = total;
            g.detail = detail.to_string();
        }
    }

    fn finish_phase(&mut self, detail: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.detail = detail.to_string();
            g.done = g.total.max(1);
        }
    }

    fn note(&mut self, msg: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.detail = msg.to_string();
        }
    }
}
