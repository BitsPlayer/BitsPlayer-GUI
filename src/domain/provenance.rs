use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
)]
#[serde(deny_unknown_fields)]
pub struct BuildProvenance {
    pub tool_version: String,

    pub git_commit: String,

    pub cargo_lock_sha256: String,

    pub binary_sha256: String,
}

