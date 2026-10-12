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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CarveParameters {
    pub width: u32,
    pub height: u32,
    pub with_audio: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationContext {
    pub evidence_path: Option<String>,
    pub extraction_parameters: Option<ExtractionParameters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carve_parameters: Option<CarveParameters>,
}

impl OperationContext {
    pub fn evidence(path: &Path) -> Self {
        Self {
            evidence_path: Some(path.to_string_lossy().to_string()),
            extraction_parameters: None,
            carve_parameters: None,
        }
    }

    pub fn extraction(path: &Path, parameters: ExtractionParameters) -> Self {
        Self {
            evidence_path: Some(path.to_string_lossy().to_string()),
            extraction_parameters: Some(parameters),
            carve_parameters: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_style_contexts_reserialize_byte_identically() {
        let evidence = r#"{"evidence_path":"/tmp/e.mp4","extraction_parameters":null}"#;
        let parsed: OperationContext = serde_json::from_str(evidence).unwrap();
        assert!(parsed.carve_parameters.is_none());
        assert_eq!(serde_json::to_string(&parsed).unwrap(), evidence);

        let extraction = r#"{"evidence_path":"/tmp/e.mp4","extraction_parameters":{"width":64,"height":48,"matrix":"BT.709","include_non_idr":false,"include_partial":true,"with_audio":false,"all_frames":true}}"#;
        let parsed: OperationContext = serde_json::from_str(extraction).unwrap();
        assert!(
            parsed
                .extraction_parameters
                .as_ref()
                .unwrap()
                .frame_offset
                .is_none()
        );
        assert_eq!(serde_json::to_string(&parsed).unwrap(), extraction);
    }

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
                frame_offset: None,
            },
        );

        let parameters = context.extraction_parameters.unwrap();
        assert_eq!(parameters.width, 1920);
        assert_eq!(parameters.height, 1080);
        assert!(parameters.include_partial);
        assert!(parameters.all_frames);
    }
}
