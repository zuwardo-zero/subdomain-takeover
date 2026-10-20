//! BBOT integration for subdomain enumeration

use crate::Config;
use anyhow::Result;
use std::collections::HashSet;
use std::process::Command as StdCommand;
use std::time::Duration;
use tracing::{info, warn};

/// Enumerate subdomains using BBOT
pub async fn enumerate(config: &Config) -> Result<Vec<String>> {
    info!("Starting BBOT enumeration for {} (mode: {})", config.domain, config.bbot_mode);

    let mut subdomains = HashSet::new();

    // Set timeout based on mode
    let timeout = match config.bbot_mode.as_str() {
        "fast" => Duration::from_secs(config.timeout.max(30) * 5),
        "passive" => Duration::from_secs(config.timeout.max(60) * 10),
        "active" => Duration::from_secs(config.timeout.max(60) * 15),
        "baddns" => Duration::from_secs(config.timeout.max(60) * 10),
        _ => Duration::from_secs(config.timeout.max(60) * 10), // subdomain-enum default
    };

    // Build BBOT command based on mode
    let mut cmd = StdCommand::new("bbot");
    cmd.arg("-t").arg(&config.domain)
        .arg("--json")                    // JSON output for parsing
        .arg("--no-color");

    // Select preset based on mode
    match config.bbot_mode.as_str() {
        "fast" => {
            cmd.arg("-p").arg("fast"); // Fast scan - no extra discovery
        }
        "passive" => {
            cmd.arg("-f").arg("passive"); // Passive modules only
        }
        "active" => {
            cmd.arg("-f").arg("active"); // Active modules
        }
        "baddns" => {
            cmd.arg("-p").arg("baddns"); // Subdomain takeover detection
        }
        "subdomain-enum" => {
            cmd.arg("-p").arg("subdomain-enum"); // Comprehensive subdomain enum
        }
        _ => {
            cmd.arg("-p").arg("fast"); // Default to fast
        }
    }

    // Run with timeout
    let mut child = match cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to spawn BBOT: {}. Is BBOT installed?", e);
            return Ok(Vec::new());
        }
    };

    // Wait with timeout
    let start = std::time::Instant::now();
    let output = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = std::io::read_to_string(child.stdout.take().unwrap()).unwrap_or_default();
                let stderr = std::io::read_to_string(child.stderr.take().unwrap()).unwrap_or_default();
                break std::process::Output {
                    status,
                    stdout: stdout.into_bytes(),
                    stderr: stderr.into_bytes(),
                };
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let stdout = std::io::read_to_string(child.stdout.take().unwrap()).unwrap_or_default();
                    let stderr = std::io::read_to_string(child.stderr.take().unwrap()).unwrap_or_default();
                    // Create a timeout exit status (124 is standard timeout exit code)
                    break std::process::Output {
                        status: std::process::Command::new("sh").arg("-c").arg("exit 124").status().unwrap(),
                        stdout: stdout.into_bytes(),
                        stderr: stderr.into_bytes(),
                    };
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                warn!("BBOT process error: {}", e);
                break std::process::Output {
                    status: std::process::Command::new("sh").arg("-c").arg("exit 1").status().unwrap(),
                    stdout: Vec::new(),
                    stderr: e.to_string().into_bytes(),
                };
            }
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("BBOT exited with status {:?}: {}", output.status, stderr);
    }

    // Parse JSON output
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(event_type) = json.get("type").and_then(|v| v.as_str()) {
                if event_type == "subdomain" || event_type == "dns" || event_type == "baddns" {
                    if let Some(subdomain) = json.get("subdomain").and_then(|v| v.as_str()) {
                        let clean = subdomain.strip_prefix("*.").unwrap_or(subdomain);
                        if is_subdomain_of(clean, &config.domain) {
                            subdomains.insert(clean.to_string());
                        }
                    }
                }
            }
        }
    }

    let result: Vec<String> = subdomains.into_iter().collect();
    info!("BBOT found {} subdomains", result.len());
    Ok(result)
}

/// Check if a domain is a subdomain of the target domain
fn is_subdomain_of(subdomain: &str, target_domain: &str) -> bool {
    let subdomain = subdomain.to_lowercase();
    let target_domain = target_domain.to_lowercase();

    if subdomain == target_domain {
        return true;
    }

    subdomain.ends_with(&format!(".{}", target_domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_subdomain_of() {
        assert!(is_subdomain_of("example.com", "example.com"));
        assert!(is_subdomain_of("www.example.com", "example.com"));
        assert!(is_subdomain_of("api.v2.example.com", "example.com"));
        assert!(!is_subdomain_of("example.com.evil.com", "example.com"));
        assert!(!is_subdomain_of("evil.com", "example.com"));
    }
}