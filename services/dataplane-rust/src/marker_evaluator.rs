//! DGSSI Technical Marker Evaluator (Loi 05-20 Art. 31)
//! Loads markers from environment or embedded set.

use serde_json::Value;
use std::collections::HashSet;

pub struct DgssiMarkerEvaluator {
    markers: HashSet<String>,
}

impl DgssiMarkerEvaluator {
    pub fn new() -> Self {
        let mut markers = HashSet::new();

        if let Ok(env_markers) = std::env::var("DGSSI_MARKERS") {
            for m in env_markers.split(',') {
                let m = m.trim().to_lowercase();
                if !m.is_empty() {
                    markers.insert(m);
                }
            }
        }

        for m in [
            "sckit", "scscreenconnect", "rmm+", "labtech plus",
            "vssadmin delete shadows", "mimikatz", "procdump",
            "cmd.aspx", "shell.aspx",
        ] {
            markers.insert(m.to_string());
        }

        Self { markers }
    }

    pub fn evaluate(&self, event: &Value) -> bool {
        let fields = [
            event.get("payload"),
            event.get("cmdline"),
            event.get("process_name"),
            event.get("file_name"),
            event.get("dst_domain"),
            event.get("url"),
        ];

        for field in fields.into_iter().flatten() {
            if let Some(s) = field.as_str() {
                let lower = s.to_lowercase();
                for marker in &self.markers {
                    if lower.contains(marker) {
                        return true;
                    }
                }
            }
        }

        false
    }
}
