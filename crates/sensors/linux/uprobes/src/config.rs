//! Configuration for uprobe sensor: allowlists and budgets.
//!
//! This module defines the configuration structure for controlling which processes
//! and libraries are allowed to be monitored, and what rate limits apply.

use std::collections::HashSet;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid budget value: {0}")]
    InvalidBudget(String),
}

/// Configuration for TLS capture uprobes.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Enable TLS capture (default: false for security).
    pub enabled: bool,
    /// Maximum bytes captured per process per second (budget enforcement).
    /// Default: 4096 bytes/sec (enough for ~16 HTTP requests with headers).
    pub bytes_per_process_per_sec: u32,
    /// Process names allowed for TLS capture (allowlist). Empty = all processes.
    /// Example: ["curl", "wget", "python3"].
    pub process_allowlist: HashSet<String>,
    /// Library paths to exclude from capture. Example: ["/lib/libcurl.so.4"].
    pub library_denylist: HashSet<PathBuf>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default (sensitive data)
            bytes_per_process_per_sec: 4096,
            process_allowlist: HashSet::new(), // Empty = all processes allowed
            library_denylist: HashSet::new(),
        }
    }
}

/// Configuration for readline capture uprobes.
#[derive(Debug, Clone)]
pub struct ReadlineConfig {
    /// Enable readline capture (default: false).
    pub enabled: bool,
    /// Maximum commands captured per process per second.
    /// Default: 10 commands/sec (interactive shells rarely exceed this).
    pub commands_per_process_per_sec: u32,
    /// Process names allowed for readline capture (allowlist). Empty = all shells.
    /// Example: ["bash", "zsh"].
    pub process_allowlist: HashSet<String>,
}

impl Default for ReadlineConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default
            commands_per_process_per_sec: 10,
            process_allowlist: HashSet::new(), // Empty = all shells allowed
        }
    }
}

/// Complete uprobe sensor configuration.
#[derive(Debug, Clone, Default)]
pub struct UprobesConfig {
    /// TLS capture configuration.
    pub tls: TlsConfig,
    /// Readline capture configuration.
    pub readline: ReadlineConfig,
}

impl UprobesConfig {
    /// Create a new configuration with default values (all captures disabled).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable TLS capture with default budget and no allowlist.
    #[must_use]
    pub fn with_tls_enabled(mut self) -> Self {
        self.tls.enabled = true;
        self
    }

    /// Enable readline capture with default budget and no allowlist.
    #[must_use]
    pub fn with_readline_enabled(mut self) -> Self {
        self.readline.enabled = true;
        self
    }

    /// Set TLS bytes budget per process per second.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidBudget`] if the budget is 0.
    pub fn tls_budget(mut self, bytes_per_sec: u32) -> Result<Self, ConfigError> {
        if bytes_per_sec == 0 {
            return Err(ConfigError::InvalidBudget(
                "bytes_per_process_per_sec must be > 0".to_string(),
            ));
        }
        self.tls.bytes_per_process_per_sec = bytes_per_sec;
        Ok(self)
    }

    /// Set readline commands budget per process per second.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidBudget`] if the budget is 0.
    pub fn readline_budget(mut self, commands_per_sec: u32) -> Result<Self, ConfigError> {
        if commands_per_sec == 0 {
            return Err(ConfigError::InvalidBudget(
                "commands_per_process_per_sec must be > 0".to_string(),
            ));
        }
        self.readline.commands_per_process_per_sec = commands_per_sec;
        Ok(self)
    }

    /// Add processes to TLS capture allowlist.
    #[must_use]
    pub fn tls_allow_processes(mut self, processes: &[&str]) -> Self {
        self.tls.process_allowlist = processes.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// Add processes to readline capture allowlist.
    #[must_use]
    pub fn readline_allow_processes(mut self, processes: &[&str]) -> Self {
        self.readline.process_allowlist = processes.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// Add libraries to TLS capture denylist.
    #[must_use]
    pub fn tls_deny_libraries(mut self, libraries: &[PathBuf]) -> Self {
        self.tls.library_denylist = libraries.iter().cloned().collect();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_captures_disabled() {
        let config = UprobesConfig::new();
        assert!(!config.tls.enabled);
        assert!(!config.readline.enabled);
    }

    #[test]
    fn can_enable_tls() {
        let config = UprobesConfig::new().with_tls_enabled();
        assert!(config.tls.enabled);
        assert_eq!(config.tls.bytes_per_process_per_sec, 4096);
    }

    #[test]
    fn can_enable_readline() {
        let config = UprobesConfig::new().with_readline_enabled();
        assert!(config.readline.enabled);
        assert_eq!(config.readline.commands_per_process_per_sec, 10);
    }

    #[test]
    fn can_set_tls_budget() {
        let config = UprobesConfig::new().tls_budget(8192).unwrap();
        assert_eq!(config.tls.bytes_per_process_per_sec, 8192);
    }

    #[test]
    fn rejects_zero_tls_budget() {
        let result = UprobesConfig::new().tls_budget(0);
        assert!(result.is_err());
    }

    #[test]
    fn can_set_readline_budget() {
        let config = UprobesConfig::new().readline_budget(20).unwrap();
        assert_eq!(config.readline.commands_per_process_per_sec, 20);
    }

    #[test]
    fn rejects_zero_readline_budget() {
        let result = UprobesConfig::new().readline_budget(0);
        assert!(result.is_err());
    }

    #[test]
    fn can_set_tls_allowlist() {
        let config = UprobesConfig::new().tls_allow_processes(&["curl", "wget"]);
        assert_eq!(config.tls.process_allowlist.len(), 2);
        assert!(config.tls.process_allowlist.contains("curl"));
        assert!(config.tls.process_allowlist.contains("wget"));
    }

    #[test]
    fn can_set_readline_allowlist() {
        let config = UprobesConfig::new().readline_allow_processes(&["bash", "zsh"]);
        assert_eq!(config.readline.process_allowlist.len(), 2);
        assert!(config.readline.process_allowlist.contains("bash"));
    }

    #[test]
    fn can_set_library_denylist() {
        let libs = vec![PathBuf::from("/lib/libcurl.so.4")];
        let config = UprobesConfig::new().tls_deny_libraries(&libs);
        assert_eq!(config.tls.library_denylist.len(), 1);
    }

    #[test]
    fn empty_allowlist_means_all_allowed() {
        let config = UprobesConfig::new();
        assert!(config.tls.process_allowlist.is_empty());
        assert!(config.readline.process_allowlist.is_empty());
    }

    #[test]
    fn builder_pattern_works() {
        let config = UprobesConfig::new()
            .with_tls_enabled()
            .with_readline_enabled()
            .tls_budget(8192)
            .unwrap()
            .readline_budget(20)
            .unwrap()
            .tls_allow_processes(&["curl"])
            .readline_allow_processes(&["bash"]);

        assert!(config.tls.enabled);
        assert!(config.readline.enabled);
        assert_eq!(config.tls.bytes_per_process_per_sec, 8192);
        assert_eq!(config.readline.commands_per_process_per_sec, 20);
    }
}
