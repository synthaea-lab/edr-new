//! Lineage features for process parent-child relationship scoring — the Rust mirror of
//! `ml/synthaea_ml/features/lineage.py`.
//!
//! This is a parity seam: a model trained on the Python vectors only scores consistently
//! here if both sides produce the identical vector for the same ExecEvent (same parent_comm,
//! parent_image_path values). The pairing is locked by `ml/tests/fixtures/lineage_golden.jsonl`,
//! checked from Rust (this crate's golden test) and Python (`ml/tests/test_lineage_golden.py`).
//!
//! These features raise evasion cost: an attacker can rewrite any single command line cheaply,
//! but producing a normal-looking process lineage is drastically more expensive. Classic
//! attack patterns include: web server→shell (webshell), office app→interpreter (malicious
//! macro), shell→binary from suspicious paths (dropper).

use schema::ExecEvent;

/// See `lineage.py::SHELL_COMMS` — keep in sync.
const SHELL_COMMS: &[&str] = &[
    "bash",
    "sh",
    "zsh",
    "fish",
    "dash",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "pwsh",
];

/// See `lineage.py::WEBSERVER_COMMS` — keep in sync.
const WEBSERVER_COMMS: &[&str] = &[
    "httpd",
    "nginx",
    "apache2",
    "w3wp.exe",      // IIS worker process
    "w3wp",
    "node",          // Node.js web servers
    "java",          // Tomcat, Spring Boot, etc.
    "dotnet",        // .NET web apps
    "uwsgi",
    "gunicorn",
    "php-fpm",
];

/// See `lineage.py::OFFICE_COMMS` — keep in sync.
const OFFICE_COMMS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "mspub.exe",
    "winword",
    "excel",
    "powerpnt",
    "outlook",
];

/// See `lineage.py::SYSTEM_PATHS` — keep in sync.
/// Unix and Windows system directories where legitimate parent processes reside.
const SYSTEM_PATHS: &[&str] = &[
    "/usr/bin/",
    "/bin/",
    "/sbin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/System/Library/",           // macOS system binaries
    "/Library/Apple/",            // macOS Apple-signed binaries
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\SystemApps\\",
    "\\Windows\\UUS\\",
    "\\Program Files\\",
    "\\Program Files (x86)\\",
];

/// See `lineage.py::SUSPICIOUS_PATHS` — keep in sync.
/// Directories where malware droppers commonly execute from.
const SUSPICIOUS_PATHS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "\\AppData\\",
    "\\Temp\\",
    "\\tmp\\",
    "\\Public\\",
    "\\Downloads\\",
    "\\Desktop\\",
    "%temp%",
    "%appdata%",
];

/// Feature names in output order — must match `lineage.py::FEATURE_NAMES` and the ONNX
/// model's input column order. Public so a detection can name the attributed features.
pub const FEATURE_NAMES: [&str; 6] = [
    "has_parent_lineage",
    "parent_comm_is_shell",
    "parent_comm_is_webserver",
    "parent_comm_is_office",
    "parent_path_is_system",
    "parent_path_is_suspicious",
];

/// Check if a string (case-insensitive) matches any item in a list.
fn matches_any_ci(value: &str, needles: &[&str]) -> bool {
    let lower = value.to_lowercase();
    needles.iter().any(|&n| {
        let needle_lower = n.to_lowercase();
        // Match exact basename for comm, substring for paths
        lower == needle_lower || lower.contains(&needle_lower)
    })
}

/// The 6-feature lineage vector, in [`FEATURE_NAMES`] order.
///
/// Input is an `ExecEvent` with optional `parent_comm` and `parent_image_path` fields.
/// All features are binary (0.0 or 1.0) for this first phase; fleet-informed rarity
/// scoring is deferred to a future issue (#44 + #49 dependencies).
#[must_use]
pub fn extract_features(event: &ExecEvent) -> [f32; 6] {
    let has_parent = event.parent_comm.is_some() || event.parent_image_path.is_some();

    let parent_comm_is_shell = event
        .parent_comm
        .as_ref()
        .map_or(false, |comm| matches_any_ci(comm, SHELL_COMMS));

    let parent_comm_is_webserver = event
        .parent_comm
        .as_ref()
        .map_or(false, |comm| matches_any_ci(comm, WEBSERVER_COMMS));

    let parent_comm_is_office = event
        .parent_comm
        .as_ref()
        .map_or(false, |comm| matches_any_ci(comm, OFFICE_COMMS));

    let parent_path_is_system = event
        .parent_image_path
        .as_ref()
        .map_or(false, |path| matches_any_ci(path, SYSTEM_PATHS));

    let parent_path_is_suspicious = event
        .parent_image_path
        .as_ref()
        .map_or(false, |path| matches_any_ci(path, SUSPICIOUS_PATHS));

    [
        if has_parent { 1.0 } else { 0.0 },
        if parent_comm_is_shell { 1.0 } else { 0.0 },
        if parent_comm_is_webserver { 1.0 } else { 0.0 },
        if parent_comm_is_office { 1.0 } else { 0.0 },
        if parent_path_is_system { 1.0 } else { 0.0 },
        if parent_path_is_suspicious { 1.0 } else { 0.0 },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use schema::fixtures::exec;

    #[test]
    fn no_parent_lineage_has_all_zeros() {
        let event = exec();
        let feats = extract_features(&event);
        assert_eq!(feats, [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn shell_parent_detected() {
        let event = ExecEvent {
            parent_comm: Some("bash".to_string()),
            ..exec()
        };
        let feats = extract_features(&event);
        assert_eq!(feats[0], 1.0); // has_parent_lineage
        assert_eq!(feats[1], 1.0); // parent_comm_is_shell
        assert_eq!(feats[2], 0.0); // parent_comm_is_webserver
    }

    #[test]
    fn webserver_parent_detected() {
        let event = ExecEvent {
            parent_comm: Some("nginx".to_string()),
            ..exec()
        };
        let feats = extract_features(&event);
        assert_eq!(feats[0], 1.0); // has_parent_lineage
        assert_eq!(feats[1], 0.0); // parent_comm_is_shell
        assert_eq!(feats[2], 1.0); // parent_comm_is_webserver
    }

    #[test]
    fn office_parent_detected() {
        let event = ExecEvent {
            parent_comm: Some("winword.exe".to_string()),
            ..exec()
        };
        let feats = extract_features(&event);
        assert_eq!(feats[0], 1.0); // has_parent_lineage
        assert_eq!(feats[3], 1.0); // parent_comm_is_office
    }

    #[test]
    fn system_path_detected() {
        let event = ExecEvent {
            parent_image_path: Some("/usr/bin/systemd".to_string()),
            ..exec()
        };
        let feats = extract_features(&event);
        assert_eq!(feats[0], 1.0); // has_parent_lineage
        assert_eq!(feats[4], 1.0); // parent_path_is_system
    }

    #[test]
    fn suspicious_path_detected() {
        let event = ExecEvent {
            parent_image_path: Some("C:\\Users\\Bob\\AppData\\Local\\Temp\\dropper.exe".to_string()),
            ..exec()
        };
        let feats = extract_features(&event);
        assert_eq!(feats[0], 1.0); // has_parent_lineage
        assert_eq!(feats[5], 1.0); // parent_path_is_suspicious
    }

    #[test]
    fn case_insensitive_matching() {
        let event = ExecEvent {
            parent_comm: Some("BASH".to_string()),
            ..exec()
        };
        let feats = extract_features(&event);
        assert_eq!(feats[1], 1.0); // parent_comm_is_shell (case-insensitive)
    }

    #[test]
    fn windows_system32_is_system_path() {
        let event = ExecEvent {
            parent_image_path: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
            ..exec()
        };
        let feats = extract_features(&event);
        assert_eq!(feats[4], 1.0); // parent_path_is_system
    }
}
