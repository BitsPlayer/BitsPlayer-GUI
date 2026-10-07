use serde::{
    Deserialize,
    Serialize,
};

use std::{
    io,
    path::PathBuf,
};

use crate::forensic::hashing::sha256_file;

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

impl BuildProvenance {
    pub fn collect(
    ) -> io::Result<Self> {
        let executable =
            std::env::current_exe()?;

        let binary_sha256 =
            sha256_file(
                &executable,
            )?;

        Ok(Self {
            tool_version:
                env!(
                    "CARGO_PKG_VERSION"
                )
                .to_string(),

            git_commit:
                env!(
                    "BITPLAYER_GIT_COMMIT"
                )
                .to_string(),

            cargo_lock_sha256:
                env!(
                    "BITPLAYER_CARGO_LOCK_SHA256"
                )
                .to_string(),

            binary_sha256,
        })
    }

    pub fn executable_path(
    ) -> io::Result<PathBuf> {
        std::env::current_exe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_build_provenance() {
        let provenance =
            BuildProvenance::collect()
                .unwrap();

        assert_eq!(
            provenance.tool_version,
            env!(
                "CARGO_PKG_VERSION"
            )
        );

        assert!(
            !provenance
                .git_commit
                .is_empty()
        );

        assert_eq!(
            provenance
                .cargo_lock_sha256
                .len(),
            64
        );

        assert_eq!(
            provenance
                .binary_sha256
                .len(),
            64
        );
    }
}