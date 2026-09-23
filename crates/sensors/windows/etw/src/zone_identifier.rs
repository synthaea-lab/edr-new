//! Mark-of-the-web (#365): the `Zone.Identifier` alternate data stream a
//! browser, mail client or archiver writes next to a downloaded file — the
//! Windows counterpart of macOS's `com.apple.quarantine` xattr, surfaced as the
//! same `schema::FileQuarantineEvent`.
//!
//! Platform-independent on purpose: the stream content is attacker-controlled
//! (anything can write an ADS), so the parser is unit-tested on every CI leg
//! and has a never-panic suite in `tests/robustness.rs`. Only the ETW hook and
//! the read-back live in the Windows-gated `providers`.
//!
//! Lab-confirmed (2026-09-23, local Windows 11): Kernel-File reports a write to
//! the stream as a create/write on `C:\…\file.exe:Zone.Identifier`, for both a
//! `Set-Content -Stream` and a plain `CreateFileW` on `file:Zone.Identifier` —
//! two or three records per write, hence [`QuarantineDedup`].

use std::collections::HashMap;

/// Stream suffix on the path Kernel-File reports. Matched case-insensitively;
/// an explicit `:$DATA` stream type is accepted too.
const STREAM_SUFFIX: &str = ":Zone.Identifier";
const STREAM_TYPE_SUFFIX: &str = ":$DATA";

/// Read-back cap: real streams are a few hundred bytes (`ZoneId`, two URLs);
/// anything larger is truncated rather than read whole.
pub const MAX_STREAM_BYTES: u64 = 8 * 1024;

/// Per-value cap, in characters. URLs past this are cut, never dropped — the
/// prefix still names the host.
const MAX_VALUE_CHARS: usize = 2048;

/// The file the mark belongs to, when `path` names its `Zone.Identifier`
/// stream (`C:\d\a.exe:Zone.Identifier` → `C:\d\a.exe`). `None` for any other
/// path, including a bare `:Zone.Identifier` with no file in front.
#[must_use]
pub fn stream_host_path(path: &str) -> Option<&str> {
    let path = strip_suffix_ignore_ascii_case(path, STREAM_TYPE_SUFFIX).unwrap_or(path);
    let host = strip_suffix_ignore_ascii_case(path, STREAM_SUFFIX)?;
    (!host.is_empty() && !host.ends_with(['\\', '/', ':'])).then_some(host)
}

fn strip_suffix_ignore_ascii_case<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    let split = s.len().checked_sub(suffix.len())?;
    let tail = s.get(split..)?;
    tail.eq_ignore_ascii_case(suffix).then(|| &s[..split])
}

/// What a `Zone.Identifier` stream says. Every field is optional: writers
/// differ (some record no URL), and a read that races the writer sees an
/// empty stream — the mark alone is still the signal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneIdentifier {
    /// URL zone: 0 local machine, 1 intranet, 2 trusted, 3 internet,
    /// 4 restricted.
    pub zone_id: Option<u32>,
    /// `HostUrl` — where the file was downloaded from.
    pub host_url: Option<String>,
    /// `ReferrerUrl` — the page that linked to it.
    pub referrer_url: Option<String>,
}

impl ZoneIdentifier {
    /// True unless the stream positively places the file in a local, intranet
    /// or trusted zone (0–2). An unknown zone (empty or raced read, garbage
    /// value) counts as external: the stream exists, so something marked it.
    #[must_use]
    pub fn is_external(&self) -> bool {
        self.zone_id.is_none_or(|zone| zone >= 3)
    }
}

/// Parses stream content: an INI with a `[ZoneTransfer]` section. Decodes a
/// UTF-16LE or UTF-8 BOM, otherwise UTF-8 lossily; keys are
/// case-insensitive; keys under any other section are ignored, keys before
/// any section header are accepted. Never fails — unparseable input yields
/// empty fields.
#[must_use]
pub fn parse(bytes: &[u8]) -> ZoneIdentifier {
    let text = decode(bytes);
    let mut out = ZoneIdentifier::default();
    let mut in_zone_section = true;
    for line in text.lines() {
        let line = line.trim();
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_zone_section = section.trim().eq_ignore_ascii_case("ZoneTransfer");
            continue;
        }
        if !in_zone_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            k if k.eq_ignore_ascii_case("ZoneId") => out.zone_id = value.parse().ok(),
            k if k.eq_ignore_ascii_case("HostUrl") => out.host_url = bounded_value(value),
            k if k.eq_ignore_ascii_case("ReferrerUrl") => out.referrer_url = bounded_value(value),
            _ => {}
        }
    }
    out
}

fn decode(bytes: &[u8]) -> String {
    if let Some(utf16) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = utf16
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

fn bounded_value(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.chars().take(MAX_VALUE_CHARS).collect())
}

/// Collapses the two or three Kernel-File records one stream write produces
/// into one `FileQuarantine`. Keyed by the (case-folded) host path inside a
/// short window, pruned on every call, and hard-capped: past the cap a new
/// path is reported without being remembered — a possible duplicate event,
/// never a lost one — and the skip is counted.
#[cfg_attr(not(windows), allow(dead_code))] // driven by the Windows-only provider
pub(crate) struct QuarantineDedup {
    seen: HashMap<String, u64>,
    window_ns: u64,
    cap: usize,
    unremembered: u64,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl QuarantineDedup {
    pub(crate) fn new(window_ns: u64, cap: usize) -> Self {
        Self {
            seen: HashMap::new(),
            window_ns,
            cap,
            unremembered: 0,
        }
    }

    /// True if `host_path` was already reported within the window.
    pub(crate) fn is_duplicate(&mut self, host_path: &str, now_ns: u64) -> bool {
        let cutoff = now_ns.saturating_sub(self.window_ns);
        self.seen.retain(|_, &mut t| t >= cutoff);
        let key = host_path.to_lowercase();
        if self.seen.contains_key(&key) {
            return true;
        }
        if self.seen.len() >= self.cap {
            self.unremembered += 1;
            // Powers of two only: a burst must not flood the log.
            if self.unremembered.is_power_of_two() {
                tracing::warn!(
                    cap = self.cap,
                    unremembered_total = self.unremembered,
                    "quarantine dedup at its cap — marks reported without dedup"
                );
            }
            return false;
        }
        self.seen.insert(key, now_ns);
        false
    }

    /// New paths reported without being remembered because the cap was hit.
    #[cfg_attr(not(test), allow(dead_code))] // read by a future health surface
    pub(crate) fn unremembered(&self) -> u64 {
        self.unremembered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROWSER_STREAM: &str = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.test/page\r\nHostUrl=https://example.test/payload.exe\r\n";

    #[test]
    fn host_path_is_the_file_in_front_of_the_stream() {
        assert_eq!(
            stream_host_path(r"C:\Users\u\Downloads\a.exe:Zone.Identifier"),
            Some(r"C:\Users\u\Downloads\a.exe")
        );
    }

    #[test]
    fn host_path_matches_case_insensitively_and_with_stream_type() {
        assert_eq!(
            stream_host_path(r"C:\d\a.exe:zone.identifier:$DATA"),
            Some(r"C:\d\a.exe")
        );
    }

    #[test]
    fn other_paths_and_bare_streams_are_not_marks() {
        assert_eq!(stream_host_path(r"C:\d\a.exe"), None);
        assert_eq!(stream_host_path(r"C:\d\Zone.Identifier"), None);
        assert_eq!(stream_host_path(r"C:\d\a.exe:other"), None);
        assert_eq!(stream_host_path(":Zone.Identifier"), None);
        assert_eq!(stream_host_path(r"C:\d\:Zone.Identifier"), None);
        assert_eq!(stream_host_path(""), None);
    }

    #[test]
    fn parses_a_browser_stream() {
        let zone = parse(BROWSER_STREAM.as_bytes());
        assert_eq!(zone.zone_id, Some(3));
        assert_eq!(
            zone.host_url.as_deref(),
            Some("https://example.test/payload.exe")
        );
        assert_eq!(
            zone.referrer_url.as_deref(),
            Some("https://example.test/page")
        );
        assert!(zone.is_external());
    }

    #[test]
    fn parses_a_utf16le_stream_with_bom() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in BROWSER_STREAM.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(parse(&bytes), parse(BROWSER_STREAM.as_bytes()));
    }

    #[test]
    fn keys_in_other_sections_are_ignored() {
        let zone = parse(b"[Other]\nHostUrl=https://decoy.test/\n[ZoneTransfer]\nZoneId=3\n");
        assert_eq!(zone.host_url, None);
        assert_eq!(zone.zone_id, Some(3));
    }

    #[test]
    fn empty_or_raced_stream_still_counts_as_external() {
        let zone = parse(b"");
        assert_eq!(zone, ZoneIdentifier::default());
        assert!(zone.is_external());
    }

    #[test]
    fn local_intranet_and_trusted_zones_are_not_external() {
        for zone in 0..3 {
            let text = format!("[ZoneTransfer]\nZoneId={zone}\n");
            assert!(!parse(text.as_bytes()).is_external(), "zone {zone}");
        }
        assert!(parse(b"[ZoneTransfer]\nZoneId=4\n").is_external());
    }

    #[test]
    fn oversized_values_are_truncated_not_dropped() {
        let long = format!("[ZoneTransfer]\nHostUrl=https://{}\n", "a".repeat(10_000));
        let url = parse(long.as_bytes()).host_url.expect("kept");
        assert_eq!(url.chars().count(), MAX_VALUE_CHARS);
        assert!(url.starts_with("https://a"));
    }

    #[test]
    fn one_stream_write_reports_one_quarantine() {
        let mut dedup = QuarantineDedup::new(5_000_000_000, 16);
        assert!(!dedup.is_duplicate(r"C:\d\a.exe", 1_000));
        assert!(dedup.is_duplicate(r"C:\D\A.EXE", 2_000));
        assert!(!dedup.is_duplicate(r"C:\d\a.exe", 6_000_001_000));
    }

    #[test]
    fn dedup_past_its_cap_reports_and_counts_instead_of_growing() {
        let mut dedup = QuarantineDedup::new(u64::MAX, 2);
        assert!(!dedup.is_duplicate("a", 1));
        assert!(!dedup.is_duplicate("b", 1));
        assert!(!dedup.is_duplicate("c", 1));
        assert!(
            !dedup.is_duplicate("c", 1),
            "unremembered, so reported again"
        );
        assert_eq!(dedup.unremembered(), 2);
        assert_eq!(dedup.seen.len(), 2);
    }
}
