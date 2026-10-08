use std::io;

use crate::application::ports::AuditLog;
use crate::domain::case::Case;
use crate::infrastructure::signing::SigningIdentity;

pub use crate::application::seal::{seal_case_with_identity, SealReport};

pub fn seal_case(logger: &mut impl AuditLog, case: &Case) -> io::Result<SealReport> {
    let identity = SigningIdentity::load_or_create()?;
    seal_case_with_identity(logger, case, &identity)
}
