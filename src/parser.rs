use crate::event::AuditEvent;

/// A parsed input line. Malformed lines still produce an event so the
/// caller can emit JSON and keep reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLine {
    pub event: AuditEvent,
    /// True when the line has an audit type and a `msg=audit(time:id)` header.
    pub well_formed: bool,
}

/// Parse one auditd log line.
///
/// The original line, without a trailing newline, is always stored in `raw`.
/// Fields that cannot be extracted are left empty.
pub fn parse_line(line: &str) -> ParsedLine {
    let raw = line.trim_end_matches(['\n', '\r']).to_string();
    let mut event = AuditEvent::empty(raw);
    let text = event.raw.trim();

    event.record_type = find_field(text, "type").map(str::to_string);
    if let Some((seconds, fraction, id)) = parse_audit_stamp(text) {
        event.timestamp = format_timestamp(seconds, fraction);
        event.event_id = Some(id.to_string());
    }
    event.operation = extract_operation(text);
    event.user = extract_user(text);
    event.success = extract_success(text);

    let well_formed =
        event.record_type.is_some() && event.timestamp.is_some() && event.event_id.is_some();

    ParsedLine { event, well_formed }
}

fn parse_audit_stamp(line: &str) -> Option<(u64, &str, &str)> {
    let key = "msg=audit(";
    let start = line.find(key)?;
    if !is_field_boundary(line, start) {
        return None;
    }
    let rest = &line[start + key.len()..];
    let end = rest.find(')')?;
    let inside = &rest[..end];
    let (left, id) = inside.split_once(':')?;
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (seconds_text, fraction) = match left.split_once('.') {
        Some((seconds, fraction)) => (seconds, fraction),
        None => (left, ""),
    };
    if seconds_text.is_empty() || !seconds_text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !fraction.is_empty() && !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seconds: u64 = seconds_text.parse().ok()?;
    Some((seconds, fraction, id))
}

fn format_timestamp(seconds: u64, fraction: &str) -> Option<String> {
    let (year, month, day, hour, minute, second) = ymd_hms(seconds)?;
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        ))
    } else {
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{fraction}Z"
        ))
    }
}

/// Convert a Unix timestamp to UTC calendar fields.
///
/// Uses Howard Hinnant's `civil_from_days` algorithm. Returns `None` if the
/// year does not fit the four-digit form used in the JSON output.
fn ymd_hms(seconds: u64) -> Option<(i32, u32, u32, u32, u32, u32)> {
    let days = i64::try_from(seconds / 86_400).ok()?;
    let tod = u32::try_from(seconds % 86_400).ok()?;
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = u64::try_from(z - era * 146_097).ok()?;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = i64::try_from(yoe).ok()? + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    let year = i32::try_from(year).ok()?;
    if !(0..=9999).contains(&year) {
        return None;
    }
    Some((
        year,
        u32::try_from(month).ok()?,
        u32::try_from(day).ok()?,
        hour,
        minute,
        second,
    ))
}

fn extract_success(line: &str) -> Option<bool> {
    match find_field(line, "success")? {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

fn extract_user(line: &str) -> Option<String> {
    for key in ["UID", "AUID", "acct"] {
        if let Some(name) = find_field(line, key) {
            if is_usable_name(name) {
                return Some(name.to_string());
            }
        }
    }
    for key in ["uid", "auid"] {
        if let Some(raw) = find_field(line, key) {
            if let Some(user) = map_numeric_id(raw) {
                return Some(user);
            }
        }
    }
    None
}

fn is_usable_name(name: &str) -> bool {
    !name.is_empty() && name != "?" && name != "(null)" && name != "unset"
}

fn map_numeric_id(raw: &str) -> Option<String> {
    if raw == "-1" || raw == "4294967295" {
        return None;
    }
    let id: u64 = raw.parse().ok()?;
    if id == 4_294_967_295 {
        return None;
    }
    if id == 0 {
        Some("root".to_string())
    } else {
        Some(id.to_string())
    }
}

fn extract_operation(line: &str) -> Option<String> {
    if let Some(syscall) = find_field(line, "syscall") {
        if !syscall.is_empty() && syscall.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Some(syscall.to_string());
        }
        if let Some(name) = map_syscall(syscall) {
            return Some(name.to_string());
        }
    }
    match find_field(line, "key") {
        Some(key) if !key.is_empty() && key != "(null)" => Some(key.to_string()),
        _ => None,
    }
}

/// Small x86_64 syscall map for records that store a number.
/// `open` and `openat` both normalize to `open`.
fn map_syscall(number: &str) -> Option<&'static str> {
    Some(match number {
        "0" => "read",
        "1" => "write",
        "2" | "257" => "open",
        "3" => "close",
        "41" => "socket",
        "42" => "connect",
        "43" | "288" => "accept",
        "49" => "bind",
        "56" => "clone",
        "57" => "fork",
        "59" | "322" => "execve",
        "82" => "rename",
        "87" => "unlink",
        "90" => "chmod",
        "92" => "chown",
        "105" => "setuid",
        "231" => "exit_group",
        _ => return None,
    })
}

fn is_field_boundary(line: &str, index: usize) -> bool {
    index == 0 || line.as_bytes()[index - 1].is_ascii_whitespace()
}

/// Return the value of `key=...`, respecting double and single quotes.
///
/// The match must begin at the start of the line or after whitespace, so
/// `uid` does not match `euid`.
fn find_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let bytes = line.as_bytes();
    let needle = key.as_bytes();
    if needle.is_empty() {
        return None;
    }
    let mut index = 0;
    while index + needle.len() < bytes.len() {
        let at_key = is_field_boundary(line, index)
            && bytes[index..].starts_with(needle)
            && bytes[index + needle.len()] == b'=';
        if at_key {
            return Some(read_value(&line[index + needle.len() + 1..]));
        }
        index += 1;
    }
    None
}

fn read_value(input: &str) -> &str {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return "";
    }
    let quote = bytes[0];
    if quote == b'"' || quote == b'\'' {
        let rest = &input[1..];
        let end = rest.find(quote as char).unwrap_or(rest.len());
        return &rest[..end];
    }
    let end = input.find(char::is_whitespace).unwrap_or(input.len());
    &input[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSCALL_OPEN: &str = "type=SYSCALL msg=audit(1791115200.000:1234): arch=c000003e syscall=2 success=yes exit=3 a0=7ffc a1=0 items=1 ppid=100 pid=200 auid=0 uid=0 gid=0 euid=0 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"open_watch\"";

    #[test]
    fn parses_valid_syscall_record() {
        let parsed = parse_line(SYSCALL_OPEN);
        assert!(parsed.well_formed);
        let event = parsed.event;
        assert_eq!(event.timestamp.as_deref(), Some("2026-10-04T12:00:00Z"));
        assert_eq!(event.event_id.as_deref(), Some("1234"));
        assert_eq!(event.record_type.as_deref(), Some("SYSCALL"));
        assert_eq!(event.operation.as_deref(), Some("open"));
        assert_eq!(event.user.as_deref(), Some("root"));
        assert_eq!(event.success, Some(true));
        assert_eq!(event.raw, SYSCALL_OPEN);
    }

    #[test]
    fn parses_multiple_records_independently() {
        let second = "type=SYSCALL msg=audit(1791115201.500:1235): arch=c000003e syscall=59 success=no uid=1000 key=\"exec\"";
        let first = parse_line(SYSCALL_OPEN);
        let second = parse_line(second);
        assert_eq!(first.event.event_id.as_deref(), Some("1234"));
        assert_eq!(second.event.event_id.as_deref(), Some("1235"));
        assert_eq!(second.event.operation.as_deref(), Some("execve"));
        assert_eq!(second.event.user.as_deref(), Some("1000"));
        assert_eq!(second.event.success, Some(false));
        assert_eq!(
            second.event.timestamp.as_deref(),
            Some("2026-10-04T12:00:01.5Z")
        );
    }

    #[test]
    fn malformed_record_keeps_raw_and_null_fields() {
        let line = "this is not an audit record";
        let parsed = parse_line(line);
        assert!(!parsed.well_formed);
        assert_eq!(parsed.event.raw, line);
        assert!(parsed.event.timestamp.is_none());
        assert!(parsed.event.event_id.is_none());
        assert!(parsed.event.record_type.is_none());
        assert!(parsed.event.operation.is_none());
        assert!(parsed.event.user.is_none());
        assert!(parsed.event.success.is_none());
    }

    #[test]
    fn missing_fields_are_none() {
        let parsed = parse_line("type=CWD msg=audit(0.0:9): cwd=\"/tmp\"");
        assert!(parsed.well_formed);
        assert_eq!(parsed.event.record_type.as_deref(), Some("CWD"));
        assert_eq!(parsed.event.event_id.as_deref(), Some("9"));
        assert_eq!(
            parsed.event.timestamp.as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert!(parsed.event.operation.is_none());
        assert!(parsed.event.user.is_none());
        assert!(parsed.event.success.is_none());
    }

    #[test]
    fn empty_input_is_not_a_record() {
        let parsed = parse_line("");
        assert!(!parsed.well_formed);
        assert_eq!(parsed.event.raw, "");
    }

    #[test]
    fn prefers_quoted_account_name() {
        let line = "type=USER_AUTH msg=audit(1791115202.250:1236): pid=300 uid=0 auid=4294967295 msg='op=PAM:authentication acct=\"root\" exe=\"/usr/bin/sudo\" res=success'";
        let parsed = parse_line(line);
        assert!(parsed.well_formed);
        assert_eq!(parsed.event.user.as_deref(), Some("root"));
        assert_eq!(
            parsed.event.timestamp.as_deref(),
            Some("2026-10-04T12:00:02.25Z")
        );
        assert!(parsed.event.success.is_none());
        assert!(parsed.event.operation.is_none());
    }

    #[test]
    fn openat_maps_to_open_and_ignores_unset_auid() {
        let line =
            "type=SYSCALL msg=audit(1791115200:42): syscall=257 success=yes auid=4294967295 uid=0";
        let parsed = parse_line(line);
        assert_eq!(parsed.event.operation.as_deref(), Some("open"));
        assert_eq!(parsed.event.user.as_deref(), Some("root"));
        assert_eq!(parsed.event.event_id.as_deref(), Some("42"));
    }

    #[test]
    fn named_syscall_and_key_fallback() {
        let named = parse_line("type=SYSCALL msg=audit(1:1): syscall=openat uid=5");
        assert_eq!(named.event.operation.as_deref(), Some("openat"));
        let keyed = parse_line("type=PATH msg=audit(1:2): item=0 key=\"etc_passwd\"");
        assert_eq!(keyed.event.operation.as_deref(), Some("etc_passwd"));
    }

    #[test]
    fn does_not_confuse_uid_with_euid() {
        let parsed = parse_line("type=SYSCALL msg=audit(1:3): euid=0 uid=1000");
        assert_eq!(parsed.event.user.as_deref(), Some("1000"));
    }

    #[test]
    fn serializes_missing_fields_as_null() {
        let parsed = parse_line("not-audit");
        let value = serde_json::to_value(&parsed.event).expect("json");
        assert!(value["timestamp"].is_null());
        assert!(value["event_id"].is_null());
        assert!(value["record_type"].is_null());
        assert!(value["operation"].is_null());
        assert!(value["user"].is_null());
        assert!(value["success"].is_null());
        assert_eq!(value["raw"], "not-audit");
    }
}
