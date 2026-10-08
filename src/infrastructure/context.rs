use std::env;

pub use crate::domain::context::*;

impl HostContext {
    pub fn collect() -> Self {
        Self {
            examiner: env::var("BITSPLAYER_EXAMINER")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            host_name: env::var("HOSTNAME")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            operating_system: env::consts::OS.to_string(),
            architecture: env::consts::ARCH.to_string(),
        }
    }
}
