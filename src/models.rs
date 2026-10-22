//! Data models for the subdomain takeover tool

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Represents a subdomain with its DNS records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subdomain {
    pub name: String,
    pub a_records: Vec<IpAddr>,
    pub aaaa_records: Vec<IpAddr>,
    pub cname_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub mx_records: Vec<String>,
    /// CNAME targets that do not resolve (NXDOMAIN) - potential dangling records
    #[serde(default)]
    pub dangling_cnames: Vec<String>,
}

/// Cloud service provider - loaded dynamically from providers.json
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CloudProvider {
    pub id: String,
    pub name: String,
}

impl CloudProvider {
    pub fn new(id: String, name: String) -> Self {
        Self { id, name }
    }

    pub fn as_str(&self) -> &str {
        &self.id
    }
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Fingerprint match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintMatch {
    pub provider: CloudProvider,
    pub service_name: String,
    pub cname: String,
    pub evidence: Vec<String>,
    pub confidence: ConfidenceLevel,
}

/// Confidence level for fingerprint matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

/// Takeover check result for a single subdomain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverResult {
    pub subdomain: String,
    pub vulnerable: bool,
    pub provider: Option<CloudProvider>,
    pub service_name: Option<String>,
    pub cname: Option<String>,
    pub fingerprints: Vec<FingerprintMatch>,
    pub http_status: Option<u16>,
    pub http_body_snippet: Option<String>,
    pub error: Option<String>,
    pub timestamp: String,
    pub validation: Option<ValidationResult>,
}

/// Deeper validation result for high-confidence findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub claimable: Option<bool>,
    pub details: String,
    pub checked_at: String,
}

/// Complete scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub target_domain: String,
    pub scan_timestamp: String,
    pub total_subdomains_checked: usize,
    pub vulnerable_count: usize,
    pub results: Vec<TakeoverResult>,
    pub metadata: ScanMetadata,
}

/// Scan metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub ct_logs_enabled: bool,
    pub brute_force_enabled: bool,
    pub bbot_enabled: bool,
    pub bbot_mode: String,
    pub permute_enabled: bool,
    pub recursive_enabled: bool,
    pub wordlist_used: Option<String>,
    pub concurrency: usize,
    pub http_concurrency: usize,
    pub timeout_seconds: u64,
    pub duration_seconds: f64,
    pub subdomains_per_second: Option<f64>,
}

/// Provider fingerprint definition (loaded from JSON)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderFingerprint {
    pub name: String,
    pub id: String,
    pub cname_patterns: Vec<String>,
    pub a_record_patterns: Vec<String>,
    /// NS record patterns (for NS-based takeover checks, e.g. DigitalOcean)
    #[serde(default)]
    pub ns_patterns: Vec<String>,
    pub takeover_signatures: Vec<TakeoverSignature>,
    pub nxdomain: bool,
    pub confidence: String,
}

/// Takeover vulnerability signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverSignature {
    pub status_codes: Vec<u16>,
    pub body_patterns: Vec<String>,
    pub description: String,
    #[serde(default)]
    pub nxdomain: bool,
}

/// IP range for provider matching (CIDR notation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRange {
    pub cidr: String,
    pub provider_id: String,
    pub provider_name: String,
}

/// Benchmark results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResults {
    pub total_subdomains: usize,
    pub total_time_seconds: f64,
    pub subdomains_per_second: f64,
    pub vulnerable_found: usize,
    pub providers_checked: usize,
    pub dns_queries: usize,
    pub http_requests: usize,
    pub memory_peak_mb: f64,
}