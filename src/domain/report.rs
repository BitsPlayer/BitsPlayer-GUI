use serde::{Deserialize, Serialize};

pub const REPORT_TITLE: &str = "BitsPlayer Forensic Report";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForensicReport {
    pub case_json_sha256: Option<String>,
    pub audit_entries: usize,
    pub audit_actions: Vec<String>,
    pub evidence_files: Vec<ReportEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportEvidence {
    pub filename: String,
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportManifest {
    pub report_json_sha256: String,
    pub report_html_sha256: String,
}

impl ForensicReport {
    pub fn to_html(&self) -> String {
        let mut html = format!(
            "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>{REPORT_TITLE}</title></head>\n<body>\n<h1>{REPORT_TITLE}</h1>\n"
        );

        html.push_str("<h2>Case</h2>\n");
        html.push_str(&format!(
            "<p>case.json SHA-256: {}<br>\nAudit entries: {}</p>\n",
            escape_html(self.case_json_sha256.as_deref().unwrap_or("not present")),
            self.audit_entries
        ));

        html.push_str("<h2>Timeline</h2>\n<ol>\n");
        for action in &self.audit_actions {
            html.push_str(&format!("<li>{}</li>\n", escape_html(action)));
        }
        html.push_str("</ol>\n");

        html.push_str("<h2>Evidence</h2>\n");
        for evidence in &self.evidence_files {
            html.push_str(&format!(
                "<p><b>{}</b><br>\nPath: {}<br>\nSHA-256: {}<br>\nSize: {} bytes</p>\n",
                escape_html(&evidence.filename),
                escape_html(&evidence.path),
                escape_html(&evidence.sha256),
                evidence.size_bytes
            ));
        }

        html.push_str("</body></html>\n");
        html
    }
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escapes_interpolated_values() {
        let report = ForensicReport {
            case_json_sha256: None,
            audit_entries: 1,
            audit_actions: vec![String::from("<script>")],
            evidence_files: vec![ReportEvidence {
                filename: String::from("a&b\"c.bin"),
                path: String::from("evidence/a&b\"c.bin"),
                sha256: String::from("00"),
                size_bytes: 3,
            }],
        };

        let html = report.to_html();

        assert!(html.contains("<li>&lt;script&gt;</li>"));
        assert!(html.contains("<b>a&amp;b&quot;c.bin</b>"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("<title>BitsPlayer Forensic Report</title>"));
    }
}
