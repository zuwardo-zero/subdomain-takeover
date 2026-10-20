//! Cloud service fingerprint definitions for subdomain takeover detection
//!
//! Providers are loaded dynamically from providers.json (sourced from can-i-take-over-xyz
//! and other public lists). Supports CNAME patterns, A/AAAA record IP ranges,
//! NXDOMAIN checks, and confidence levels.

use crate::models::{CloudProvider, ConfidenceLevel, ProviderFingerprint, Subdomain};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;

static PROVIDERS: OnceLock<Vec<ProviderFingerprint>> = OnceLock::new();
static PROVIDER_MAP: OnceLock<HashMap<String, ProviderFingerprint>> = OnceLock::new();
static IP_RANGES: OnceLock<Vec<crate::models::IpRange>> = OnceLock::new();

/// Initialize providers from embedded JSON file
pub fn init_providers() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let data = include_str!("../data/providers.json");
    let providers: serde_json::Value = serde_json::from_str(data)?;
    
    let providers_vec = providers["providers"].as_array()
        .ok_or("Invalid providers format")?
        .iter()
        .map(|v| serde_json::from_value::<crate::models::ProviderFingerprint>(v.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    
    // Build IP ranges for A/AAAA record matching
    let mut ip_ranges = Vec::new();
    for provider in &providers_vec {
        for pattern in &provider.a_record_patterns {
            if pattern.contains('/') {
                // CIDR notation
                ip_ranges.push(crate::models::IpRange {
                    cidr: pattern.clone(),
                    provider_id: provider.id.clone(),
                    provider_name: provider.name.clone(),
                });
            } else if pattern.parse::<std::net::IpAddr>().is_ok() {
                // Single IP - add as /32 or /128
                let cidr = if pattern.contains(':') {
                    format!("{}/128", pattern)
                } else {
                    format!("{}/32", pattern)
                };
                ip_ranges.push(crate::models::IpRange {
                    cidr,
                    provider_id: provider.id.clone(),
                    provider_name: provider.name.clone(),
                });
            }
        }
    }
    
    // Build provider map for quick lookup
    let mut provider_map = HashMap::new();
    for provider in &providers_vec {
        provider_map.insert(provider.id.clone(), provider.clone());
    }
    
    let _ = PROVIDERS.set(providers_vec);
    let _ = PROVIDER_MAP.set(provider_map);
    let _ = IP_RANGES.set(ip_ranges);
    
    Ok(())
}

/// Get all provider fingerprints
pub fn get_all_fingerprints() -> &'static Vec<ProviderFingerprint> {
    PROVIDERS.get_or_init(|| {
        // Fallback: try to load from file
        init_providers().ok();
        PROVIDERS.get().cloned().unwrap_or_default()
    })
}

/// Get provider by ID
pub fn get_provider(id: &str) -> Option<&'static ProviderFingerprint> {
    PROVIDER_MAP.get_or_init(|| {
        let _ = init_providers();
        let mut map = HashMap::new();
        if let Some(providers) = PROVIDERS.get() {
            for p in providers {
                map.insert(p.id.clone(), p.clone());
            }
        }
        map
    }).get(id)
}

/// Match a CNAME against known cloud provider patterns
pub fn match_cname(cname: &str) -> Vec<(CloudProvider, String)> {
    let fingerprints = get_all_fingerprints();
    let mut matches = Vec::new();

    let cname_lower = cname.to_lowercase();

    for fp in fingerprints {
        for pattern in &fp.cname_patterns {
            if cname_lower.contains(&pattern.to_lowercase()) {
                matches.push((
                    CloudProvider::new(fp.id.clone(), fp.name.clone()),
                    fp.name.clone()
                ));
                break; // One match per provider is enough
            }
        }
    }

    matches
}

/// Match A/AAAA records against known provider IP ranges
pub fn match_a_records(ips: &[IpAddr]) -> Vec<(CloudProvider, String, String)> {
    let ip_ranges = IP_RANGES.get_or_init(|| {
        let _ = init_providers();
        IP_RANGES.get().cloned().unwrap_or_default()
    });
    
    let mut matches = Vec::new();
    
    for ip in ips {
        let ip_str = ip.to_string();
        for range in ip_ranges {
            if ip_in_cidr(&ip_str, &range.cidr) {
                matches.push((
                    CloudProvider::new(range.provider_id.clone(), range.provider_name.clone()),
                    range.provider_name.clone(),
                    format!("A/AAAA record matches {} ({})", range.provider_name, range.cidr)
                ));
            }
        }
    }
    
    matches
}

/// Check if an IP is in a CIDR range
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    use std::net::IpAddr;
    use std::str::FromStr;
    
    let ip = match IpAddr::from_str(ip) {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    
    let network_ip = match IpAddr::from_str(parts[0]) {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    
    let prefix_len = match parts[1].parse::<u8>() {
        Ok(len) => len,
        Err(_) => return false,
    };
    
    match (ip, network_ip) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            let mask = if prefix_len >= 32 { u32::MAX } else { !0u32 << (32 - prefix_len) };
            let ip_u32 = u32::from(ip);
            let network_u32 = u32::from(network);
            (ip_u32 & mask) == (network_u32 & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            let ip_segments = ip.segments();
            let network_segments = network.segments();
            let full_bits = prefix_len as usize;
            let full_segments = full_bits / 16;
            let remaining_bits = full_bits % 16;
            
            for i in 0..full_segments.min(8) {
                if ip_segments[i] != network_segments[i] {
                    return false;
                }
            }
            
            if remaining_bits > 0 && full_segments < 8 {
                let mask = !0u16 << (16 - remaining_bits);
                if (ip_segments[full_segments] & mask) != (network_segments[full_segments] & mask) {
                    return false;
                }
            }
            
            true
        }
        _ => false,
    }
}

/// Check for NXDOMAIN (non-existent domain)
pub fn check_nxdomain(record: &Subdomain) -> Vec<(CloudProvider, String)> {
    let mut matches = Vec::new();
    
    // If no DNS records at all, check for NXDOMAIN-based providers
    if record.a_records.is_empty() 
        && record.aaaa_records.is_empty() 
        && record.cname_records.is_empty()
        && record.ns_records.is_empty()
        && record.mx_records.is_empty() {
        
        for fp in get_all_fingerprints() {
            if fp.nxdomain {
                matches.push((
                    CloudProvider::new(fp.id.clone(), fp.name.clone()),
                    fp.name.clone()
                ));
            }
        }
    }
    
    matches
}

/// Check HTTP response for takeover signatures
pub fn check_takeover_signatures(
    provider: &CloudProvider,
    status_code: u16,
    body: &str,
    _headers: &HashMap<String, String>,
) -> Vec<(CloudProvider, ConfidenceLevel, String)> {
    let provider_id = provider.as_str();
    let provider_fp = get_provider(provider_id);
    
    let mut results = Vec::new();
    
    if let Some(fp) = provider_fp {
        for sig in &fp.takeover_signatures {
            if sig.status_codes.contains(&status_code) || sig.status_codes.is_empty() {
                for pattern in &sig.body_patterns {
                    if body.to_lowercase().contains(&pattern.to_lowercase()) {
                        let confidence = match fp.confidence.as_str() {
                            "High" => ConfidenceLevel::High,
                            "Medium" => ConfidenceLevel::Medium,
                            _ => ConfidenceLevel::Low,
                        };
                        results.push((
                            CloudProvider::new(fp.id.clone(), fp.name.clone()),
                            confidence,
                            sig.description.clone()
                        ));
                        break;
                    }
                }
                
                // Also check for NXDOMAIN signature
                if sig.nxdomain && sig.body_patterns.is_empty() {
                    let confidence = match fp.confidence.as_str() {
                        "High" => ConfidenceLevel::High,
                        "Medium" => ConfidenceLevel::Medium,
                        _ => ConfidenceLevel::Low,
                    };
                    results.push((
                        CloudProvider::new(fp.id.clone(), fp.name.clone()),
                        confidence,
                        sig.description.clone()
                    ));
                }
            }
        }
    }
    
    results
}

/// Quick check for common takeover patterns without full HTTP request
pub fn quick_cname_check(record: &Subdomain) -> Vec<(CloudProvider, ConfidenceLevel, String)> {
    let mut results = Vec::new();

    for cname in &record.cname_records {
        let matches = match_cname(cname);
        for (provider, service_name) in matches {
            let fp = get_provider(provider.as_str());
            let confidence = fp.map(|fp| match fp.confidence.as_str() {
                "High" => ConfidenceLevel::High,
                "Medium" => ConfidenceLevel::Medium,
                _ => ConfidenceLevel::Low,
            }).unwrap_or(ConfidenceLevel::Low);
            
            results.push((
                provider,
                confidence,
                format!("CNAME points to {}", service_name)
            ));
        }
    }
    
    // Also check A/AAAA records
    let all_ips: Vec<IpAddr> = record.a_records.iter()
        .chain(record.aaaa_records.iter())
        .cloned()
        .collect();
    
    if !all_ips.is_empty() {
        let a_matches = match_a_records(&all_ips);
        for (provider, _service_name, evidence) in a_matches {
            let fp = get_provider(provider.as_str());
            let confidence = fp.map(|fp| match fp.confidence.as_str() {
                "High" => ConfidenceLevel::High,
                "Medium" => ConfidenceLevel::Medium,
                _ => ConfidenceLevel::Low,
            }).unwrap_or(ConfidenceLevel::Low);
            
            results.push((
                provider,
                confidence,
                evidence
            ));
        }
    }
    
    // Check NXDOMAIN
    let nxdomain_matches = check_nxdomain(record);
    for (provider, service_name) in nxdomain_matches {
        let fp = get_provider(provider.as_str());
        let confidence = fp.map(|fp| match fp.confidence.as_str() {
            "High" => ConfidenceLevel::High,
            "Medium" => ConfidenceLevel::Medium,
            _ => ConfidenceLevel::Low,
        }).unwrap_or(ConfidenceLevel::Low);
        
        results.push((
            provider,
            confidence,
            format!("NXDOMAIN - {} claims vulnerable", service_name)
        ));
    }
    
    results
}

/// Deeper validation for high-confidence findings
/// Attempts to verify if the resource is actually claimable
pub async fn validate_claimability(
    provider: &CloudProvider,
    _subdomain: &str,
    record: &Subdomain,
) -> crate::models::ValidationResult {
    let provider_id = provider.as_str();
    let fp = get_provider(provider_id);
    
    let mut details = String::new();
    let mut claimable = None;
    
    if let Some(fp) = fp {
        // For NXDOMAIN providers, the domain doesn't exist - highly claimable
        if fp.nxdomain && record.a_records.is_empty() && record.cname_records.is_empty() {
            claimable = Some(true);
            details = format!("{} reports NXDOMAIN for this service - highly claimable", fp.name);
        } else {
            // Check if we have a CNAME pointing to a known vulnerable pattern
            for cname in &record.cname_records {
                for pattern in &fp.cname_patterns {
                    if cname.to_lowercase().contains(&pattern.to_lowercase()) {
                        details = format!("CNAME {} matches {} pattern: {}", cname, fp.name, pattern);
                        // Can't definitively prove claimability without auth, but high confidence
                        claimable = Some(true);
                        break;
                    }
                }
            }
            
            // Check A records against IP ranges
            if claimable.is_none() {
                let all_ips: Vec<IpAddr> = record.a_records.iter()
                    .chain(record.aaaa_records.iter())
                    .cloned()
                    .collect();
                
                let a_matches = match_a_records(&all_ips);
                if !a_matches.is_empty() {
                    claimable = Some(true);
                    details = format!("A/AAAA records match {} IP ranges", fp.name);
                }
            }
        }
    }
    
    if details.is_empty() {
        details = "No definitive claimability determination possible without authentication".to_string();
    }
    
    crate::models::ValidationResult {
        claimable,
        details,
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}