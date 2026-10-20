//! Certificate Transparency log enumeration

use crate::Config;
use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct CrtShEntry {
    #[serde(rename = "name_value")]
    name_value: String,
    #[serde(rename = "issuer_ca_id")]
    issuer_ca_id: Option<i64>,
    #[serde(rename = "issuer_name")]
    issuer_name: Option<String>,
    #[serde(rename = "min_cert_id")]
    min_cert_id: Option<i64>,
    #[serde(rename = "min_entry_timestamp")]
    min_entry_timestamp: Option<String>,
    #[serde(rename = "not_after")]
    not_after: Option<String>,
    #[serde(rename = "not_before")]
    not_before: Option<String>,
}

/// Enumerate subdomains from Certificate Transparency logs via crt.sh
pub async fn enumerate(config: &Config) -> Result<Vec<String>> {
    let client = build_client(config)?;
    let mut subdomains = HashSet::new();

    // Primary source: crt.sh
    let crt_subdomains = query_crt_sh(&client, &config.domain).await?;
    subdomains.extend(crt_subdomains);

    // Secondary source: CertSpotter
    let certspotter_subdomains = query_certspotter(&client, &config.domain).await?;
    subdomains.extend(certspotter_subdomains);

    // Tertiary source: URLScan.io
    let urlscan_subdomains = query_urlscan(&client, &config.domain).await?;
    subdomains.extend(urlscan_subdomains);

    // Rate limiting between requests
    if config.ct_rate_limit > 0 {
        let delay = Duration::from_millis(1000 / config.ct_rate_limit as u64);
        sleep(delay).await;
    }

    Ok(subdomains.into_iter().collect())
}

fn build_client(config: &Config) -> Result<Client> {
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout))
        .user_agent("subdomain-takeover/0.1.0 (Security Research)")
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .build()?;
    Ok(client)
}

async fn query_crt_sh(client: &Client, domain: &str) -> Result<Vec<String>> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    debug!("Querying crt.sh: {}", url);

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        warn!("crt.sh returned status: {}", response.status());
        return Ok(Vec::new());
    }

    let text = response.text().await?;
    if text.trim().is_empty() || text.trim() == "[]" {
        return Ok(Vec::new());
    }

    let entries: Vec<CrtShEntry> = match serde_json::from_str(&text) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to parse crt.sh response: {}", e);
            return Ok(Vec::new());
        }
    };

    let mut subdomains = Vec::new();
    for entry in entries {
        // name_value can contain multiple subdomains separated by newlines
        for name in entry.name_value.split('\n') {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }

            // Remove wildcard prefix
            let name = name.strip_prefix("*.").unwrap_or(name);

            // Validate it's a subdomain of our target
            if is_subdomain_of(name, domain) {
                subdomains.push(name.to_string());
            }
        }
    }

    debug!("crt.sh returned {} subdomains for {}", subdomains.len(), domain);
    Ok(subdomains)
}

/// Check if a domain is a subdomain of the target domain
fn is_subdomain_of(subdomain: &str, target_domain: &str) -> bool {
    let subdomain = subdomain.to_lowercase();
    let target_domain = target_domain.to_lowercase();

    // Exact match
    if subdomain == target_domain {
        return true;
    }

    // Subdomain match (must end with .target_domain)
    subdomain.ends_with(&format!(".{}", target_domain))
}

/// Query CertSpotter API (alternative CT log source)
async fn query_certspotter(client: &Client, domain: &str) -> Result<Vec<String>> {
    // Optional API key from environment
    let api_key = std::env::var("CERTSPOTTER_API_KEY").ok();
    
    let mut url = format!("https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names", domain);
    if let Some(ref key) = api_key {
        url.push_str("&api_key=");
        url.push_str(key);
    }
    
    debug!("Querying CertSpotter: {}", url);

    let mut request = client.get(&url);
    if let Some(key) = api_key {
        request = request.header("Authorization", format!("Bearer {}", key));
    }
    
    let response = request.send().await?;

    if !response.status().is_success() {
        warn!("CertSpotter returned status: {}", response.status());
        return Ok(Vec::new());
    }

    let text = response.text().await?;
    #[derive(Deserialize)]
    struct CertSpotterEntry {
        dns_names: Vec<String>,
    }

    let entries: Vec<CertSpotterEntry> = match serde_json::from_str(&text) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to parse CertSpotter response: {}", e);
            return Ok(Vec::new());
        }
    };

    let mut subdomains = Vec::new();
    for entry in entries {
        for name in entry.dns_names {
            let name = name.strip_prefix("*.").unwrap_or(&name);
            if is_subdomain_of(name, domain) {
                subdomains.push(name.to_string());
            }
        }
    }

    debug!("CertSpotter returned {} subdomains for {}", subdomains.len(), domain);
    Ok(subdomains)
}

/// Query URLScan.io for subdomains (passive DNS)
async fn query_urlscan(client: &Client, domain: &str) -> Result<Vec<String>> {
    // Optional API key from environment
    let api_key = std::env::var("URLSCAN_API_KEY").ok();
    
    let url = format!("https://urlscan.io/api/v1/search/?q=domain:{}", domain);
    
    debug!("Querying URLScan: {}", url);

    let mut request = client.get(&url);
    if let Some(key) = api_key {
        request = request.header("API-Key", key);
    }
    
    let response = request.send().await?;

    if !response.status().is_success() {
        warn!("URLScan returned status: {}", response.status());
        return Ok(Vec::new());
    }

    #[derive(Deserialize)]
    struct UrlScanResponse {
        results: Vec<UrlScanResult>,
    }

    #[derive(Deserialize)]
    struct UrlScanResult {
        page: UrlScanPage,
    }

    #[derive(Deserialize)]
    struct UrlScanPage {
        domain: String,
    }

    let data: UrlScanResponse = match response.json().await {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to parse URLScan response: {}", e);
            return Ok(Vec::new());
        }
    };

    let mut subdomains = Vec::new();
    for result in data.results {
        if is_subdomain_of(&result.page.domain, domain) {
            subdomains.push(result.page.domain);
        }
    }

    debug!("URLScan returned {} subdomains for {}", subdomains.len(), domain);
    Ok(subdomains)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_subdomain_of() {
        assert!(is_subdomain_of("example.com", "example.com"));
        assert!(is_subdomain_of("www.example.com", "example.com"));
        assert!(is_subdomain_of("api.v2.example.com", "example.com"));
        assert!(is_subdomain_of("sub.example.com", "example.com"));
        assert!(!is_subdomain_of("example.com.evil.com", "example.com"));
        assert!(!is_subdomain_of("evil.com", "example.com"));
        assert!(!is_subdomain_of("example.org", "example.com"));
    }
}