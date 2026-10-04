use serde::Serialize;

/// One normalized audit record.
///
/// Missing values are `None` so they serialize as JSON `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    pub timestamp: Option<String>,
    pub event_id: Option<String>,
    pub record_type: Option<String>,
    pub operation: Option<String>,
    pub user: Option<String>,
    pub success: Option<bool>,
    pub raw: String,
}

impl AuditEvent {
    pub fn empty(raw: String) -> Self {
        Self {
            timestamp: None,
            event_id: None,
            record_type: None,
            operation: None,
            user: None,
            success: None,
            raw,
        }
    }
}
