//! Compatibility facade. Persistence lives in `infrastructure`; use cases move to `application`.

pub mod seal;
pub mod verify;

pub use crate::infrastructure::{
    artifact, audit, case, closure, context, evidence, hashing, provenance, signing,
};
