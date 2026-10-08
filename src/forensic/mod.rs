//! Facade over the layered forensic API used by the GUI and the verify command.

pub mod seal;

pub use crate::application::verify;
pub use crate::infrastructure::{
    artifact, audit, case, closure, context, evidence, hashing, provenance, signing,
};
