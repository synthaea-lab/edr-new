//! Parses raw auditd netlink messages into structured records.
//!
//! Format: type=EXECVE msg=audit(timestamp:seq): key=value ...

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub record_type: u32,  // AUDIT_EXECVE = 1309, AUDIT_SOCKADDR = 1306
    pub timestamp_sec: u64,
    pub timestamp_ms: u32,
    pub seq: u64,
    pub fields: HashMap<String, String>,
}

/// Parses one auditd message from the wire.
///
/// # Errors
///
/// Returns `Err` if the message format is invalid or missing required fields.
pub fn parse_audit_message(raw: &[u8]) -> Result<AuditRecord, String> {
    let msg = String::from_utf8_lossy(raw);

    // Parse "type=EXECVE"
    let record_type = parse_type(&msg)?;

    // Parse "msg=audit(1234567890.123:456):"
    let (timestamp_sec, timestamp_ms, seq) = parse_msg_header(&msg)?;

    // Parse remaining "key=value" pairs
    let fields = parse_fields(&msg)?;

    Ok(AuditRecord {
        record_type,
        timestamp_sec,
        timestamp_ms,
        seq,
        fields,
    })
}

fn parse_type(msg: &str) -> Result<u32, String> {
    let type_prefix = "type=";
    let type_start = msg.find(type_prefix)
        .ok_or_else(|| "missing 'type=' field".to_string())?;

    let type_value_start = type_start + type_prefix.len();
    let type_end = msg[type_value_start..]
        .find(' ')
        .map(|pos| type_value_start + pos)
        .unwrap_or(msg.len());

    let type_str = &msg[type_value_start..type_end];

    // Map type names to numeric values
    match type_str {
        "EXECVE" => Ok(1309),
        "SOCKADDR" => Ok(1306),
        _ => type_str.parse().map_err(|_| format!("unknown type: {type_str}")),
    }
}

fn parse_msg_header(msg: &str) -> Result<(u64, u32, u64), String> {
    let msg_prefix = "msg=audit(";
    let msg_start = msg.find(msg_prefix)
        .ok_or_else(|| "missing 'msg=audit(' header".to_string())?;

    let timestamp_start = msg_start + msg_prefix.len();
    let timestamp_end = msg[timestamp_start..]
        .find(':')
        .map(|pos| timestamp_start + pos)
        .ok_or_else(|| "missing ':' in msg header".to_string())?;

    let timestamp_str = &msg[timestamp_start..timestamp_end];

    // Parse timestamp (format: "1234567890.123")
    let parts: Vec<&str> = timestamp_str.split('.').collect();
    if parts.len() != 2 {
        return Err(format!("invalid timestamp format: {timestamp_str}"));
    }

    let timestamp_sec: u64 = parts[0].parse()
        .map_err(|_| format!("invalid timestamp seconds: {}", parts[0]))?;
    let timestamp_ms: u32 = parts[1].parse()
        .map_err(|_| format!("invalid timestamp milliseconds: {}", parts[1]))?;

    // Parse sequence number
    let seq_start = timestamp_end + 1;
    let seq_end = msg[seq_start..]
        .find(')')
        .map(|pos| seq_start + pos)
        .ok_or_else(|| "missing ')' in msg header".to_string())?;

    let seq_str = &msg[seq_start..seq_end];
    let seq: u64 = seq_str.parse()
        .map_err(|_| format!("invalid sequence number: {seq_str}"))?;

    Ok((timestamp_sec, timestamp_ms, seq))
}

fn parse_fields(msg: &str) -> Result<HashMap<String, String>, String> {
    let mut fields = HashMap::new();

    // Find the end of the msg=audit(...): header
    let fields_start = msg.find("): ")
        .map(|pos| pos + 3)
        .unwrap_or(0);

    if fields_start == 0 || fields_start >= msg.len() {
        return Ok(fields);
    }

    let fields_str = &msg[fields_start..];

    // Parse key=value pairs
    let mut current = 0;
    while current < fields_str.len() {
        // Skip whitespace
        while current < fields_str.len() && fields_str.chars().nth(current) == Some(' ') {
            current += 1;
        }

        if current >= fields_str.len() {
            break;
        }

        // Find '='
        let eq_pos = fields_str[current..]
            .find('=')
            .map(|pos| current + pos);

        let eq_pos = match eq_pos {
            Some(pos) => pos,
            None => break,
        };

        let key = fields_str[current..eq_pos].to_string();
        current = eq_pos + 1;

        // Parse value (may be quoted)
        let (value, next_pos) = if current < fields_str.len() && fields_str.chars().nth(current) == Some('"') {
            // Quoted value
            current += 1;
            let value_end = fields_str[current..]
                .find('"')
                .map(|pos| current + pos)
                .unwrap_or(fields_str.len());

            let value = fields_str[current..value_end].to_string();
            (value, value_end + 1)
        } else {
            // Unquoted value (until space or end)
            let value_end = fields_str[current..]
                .find(' ')
                .map(|pos| current + pos)
                .unwrap_or(fields_str.len());

            let value = fields_str[current..value_end].to_string();
            (value, value_end)
        };

        fields.insert(key, value);
        current = next_pos;
    }

    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_execve_message() {
        let raw = b"type=EXECVE msg=audit(1234567890.123:456): argc=2 a0=\"/bin/ls\" a1=\"-la\"";
        let record = parse_audit_message(raw).unwrap();
        assert_eq!(record.record_type, 1309);
        assert_eq!(record.timestamp_sec, 1234567890);
        assert_eq!(record.timestamp_ms, 123);
        assert_eq!(record.seq, 456);
        assert_eq!(record.fields.get("argc"), Some(&"2".to_string()));
        assert_eq!(record.fields.get("a0"), Some(&"/bin/ls".to_string()));
        assert_eq!(record.fields.get("a1"), Some(&"-la".to_string()));
    }

    #[test]
    fn parse_sockaddr_message() {
        let raw = b"type=SOCKADDR msg=audit(1234567890.500:789): saddr=02001F907F000001000000000000000000000000000000000000000000000000";
        let record = parse_audit_message(raw).unwrap();
        assert_eq!(record.record_type, 1306);
        assert_eq!(record.timestamp_sec, 1234567890);
        assert_eq!(record.timestamp_ms, 500);
        assert_eq!(record.seq, 789);
        assert!(record.fields.contains_key("saddr"));
    }

    #[test]
    fn parse_numeric_type() {
        let raw = b"type=1309 msg=audit(1000.0:1): argc=1 a0=\"test\"";
        let record = parse_audit_message(raw).unwrap();
        assert_eq!(record.record_type, 1309);
    }

    #[test]
    fn parse_unquoted_values() {
        let raw = b"type=EXECVE msg=audit(1000.0:1): pid=1234 uid=1000";
        let record = parse_audit_message(raw).unwrap();
        assert_eq!(record.fields.get("pid"), Some(&"1234".to_string()));
        assert_eq!(record.fields.get("uid"), Some(&"1000".to_string()));
    }
}
