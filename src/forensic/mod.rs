//! Facade over the layered forensic API used by the GUI and the verify command.

pub mod seal;

pub use crate::application::{report, verify};
pub use crate::infrastructure::{
    artifact, audit, case, closure, context, evidence, evidence_copy, hashing, provenance, signing,
};
