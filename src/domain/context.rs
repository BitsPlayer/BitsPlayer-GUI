use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostContext {
    pub examiner: Option<String>,
    pub host_name: Option<String>,
    pub operating_system: String,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtractionParameters {
    pub width: u32,
    pub height: u32,
    pub matrix: String,
    pub include_non_idr: bool,
    pub include_partial: bool,
    pub with_audio: bool,
    #[serde(default)]
    pub all_frames: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationContext {
    pub evidence_path: Option<String>,
    pub extraction_parameters: Option<ExtractionParameters>,
}

impl OperationContext {
    pub fn evidence(path: &Path) -> Self {
        Self {
            evidence_path: Some(path.to_string_lossy().to_string()),
            extraction_parameters: None,
        }
    }

    pub fn extraction(path: &Path, parameters: ExtractionParameters) -> Self {
        Self {
            evidence_path: Some(path.to_string_lossy().to_string()),
            extraction_parameters: Some(parameters),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_evidence_context() {
        let context = OperationContext::evidence(Path::new("/tmp/evidence.mp4"));
        assert_eq!(context.evidence_path.as_deref(), Some("/tmp/evidence.mp4"));
        assert!(context.extraction_parameters.is_none());
    }

    #[test]
    fn creates_extraction_context() {
        let context = OperationContext::extraction(
            Path::new("/tmp/evidence.mp4"),
            ExtractionParameters {
                width: 1920,
                height: 1080,
                matrix: String::from("BT.709"),
                include_non_idr: false,
                include_partial: true,
                with_audio: false,
                all_frames: true,
            },
        );

        let parameters = context.extraction_parameters.unwrap();
        assert_eq!(parameters.width, 1920);
        assert_eq!(parameters.height, 1080);
        assert!(parameters.include_partial);
        assert!(parameters.all_frames);
    }
}