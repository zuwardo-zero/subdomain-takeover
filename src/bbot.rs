//! BBOT integration for subdomain enumeration

use crate::Config;
use anyhow::Result;
use std::collections::HashSet;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command as TokioCommand;
use tracing::{info, warn};

/// Enumerate subdomains using BBOT
pub async fn enumerate(config: &Config) -> Result<Vec<String>> {
    info!(
        "Starting BBOT enumeration for {} (mode: {})",
        config.domain, config.bbot_mode
    );

    let mut subdomains = HashSet::new();

    // Set timeout based on mode
    let timeout = match config.bbot_mode.as_str() {
        "fast" => Duration::from_secs(config.timeout.max(30) * 5),
        "passive" => Duration::from_secs(config.timeout.max(60) * 10),
        "active" => Duration::from_secs(config.timeout.max(60) * 15),
        "baddns" => Duration::from_secs(config.timeout.max(60) * 10),
        _ => Duration::from_secs(config.timeout.max(60) * 10), // subdomain-enum default
    };

    // Build BBOT command based on mode.
    // `-y` is required: without it BBOT blocks at the interactive
    // "Press enter to execute" prompt and is killed on timeout.
    let mut cmd = TokioCommand::new("bbot");
    cmd.arg("-t")
        .arg(&config.domain)
        .arg("-y")
        .arg("--json") // JSON events on stdout for parsing
        .arg("--no-color")
        .kill_on_drop(true);

    // Select preset/flags based on mode
    match config.bbot_mode.as_str() {
        // Quick passive subdomain enumeration (the "fast" preset has 0 modules)
        "fast" => {
            cmd.arg("-f").arg("subdomain-enum").arg("-rf").arg("passive");
        }
        "passive" => {
            cmd.arg("-f").arg("passive"); // Passive modules only
        }
        "active" => {
            cmd.arg("-f").arg("subdomain-enum"); // Active + passive modules
        }
        "baddns" => {
            cmd.arg("-p").arg("baddns-heavy"); // Subdomain takeover detection modules
        }
        "subdomain-enum" => {
            cmd.arg("-p").arg("subdomain-enum"); // Comprehensive subdomain enum
        }
        _ => {
            cmd.arg("-f").arg("subdomain-enum").arg("-rf").arg("passive");
        }
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to spawn BBOT: {}. Is BBOT installed?", e);
            return Ok(Vec::new());
        }
    };

    // Wait with timeout; wait_with_output drains stdout/stderr concurrently,
    // avoiding pipe-buffer deadlocks on verbose scans.
    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            warn!("BBOT process error: {}", e);
            return Ok(Vec::new());
        }
        Err(_) => {
            warn!("BBOT timed out after {:?} (partial results discarded)", timeout);
            return Ok(Vec::new());
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            "BBOT exited with status {:?}: {}",
            output.status,
            stderr.chars().take(500).collect::<String>()
        );
    }

    // Parse JSON event lines. BBOT emits {"type": "DNS_NAME", "host": "..."} etc.
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(event_type) = json.get("type").and_then(|v| v.as_str()) {
                let is_dns_event = matches!(
                    event_type,
                    "DNS_NAME" | "DNS_NAME_UNRESOLVED" | "SUBDOMAIN" | "dns" | "subdomain"
                );
                if is_dns_event {
                    // Prefer `host`, fall back to `data` (BBOT 3.x event schema)
                    let host = json
                        .get("host")
                        .and_then(|v| v.as_str())
                        .or_else(|| json.get("data").and_then(|v| v.as_str()))
                        .or_else(|| json.get("subdomain").and_then(|v| v.as_str()));

                    if let Some(host) = host {
                        if let Some(clean) = sanitize_host(host) {
                            if is_subdomain_of(&clean, &config.domain) {
                                subdomains.insert(clean);
                            }
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

/// Extract a bare hostname from a BBOT event value, rejecting non-host strings
fn sanitize_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.contains(' ') || value.contains('/') || value.contains('@') {
        return None;
    }
    // Strip port if present (e.g. "www.example.com:443")
    let host = value.split(':').next().unwrap_or(value);
    if host.is_empty() {
        return None;
    }
    let clean = host.strip_prefix("*.").unwrap_or(host);
    Some(clean.trim_end_matches('.').to_lowercase())
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

    #[test]
    fn test_sanitize_host() {
        assert_eq!(sanitize_host("WWW.Example.com."), Some("www.example.com".to_string()));
        assert_eq!(sanitize_host("*.example.com"), Some("example.com".to_string()));
        assert_eq!(sanitize_host("example.com:443"), Some("example.com".to_string()));
        assert_eq!(sanitize_host("https://example.com"), None);
        assert_eq!(sanitize_host("not a host"), None);
    }
}
