//! Subdomain takeover vulnerability detection

use crate::{Config, models::{ConfidenceLevel, FingerprintMatch, Subdomain, TakeoverResult}};
use crate::fingerprints::{check_takeover_signatures, get_all_fingerprints, match_cname, check_nxdomain, validate_claimability};
use anyhow::Result;
use dashmap::DashMap;
use indicatif::ProgressBar;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::debug;

/// Check all resolved subdomains for takeover vulnerabilities
pub async fn check_all(config: &Config, resolved: &[Subdomain]) -> Result<Vec<TakeoverResult>> {
    check_all_with_progress(config, resolved, None).await
}

/// Check all resolved subdomains for takeover vulnerabilities with optional progress bar
pub async fn check_all_with_progress(
    config: &Config,
    resolved: &[Subdomain],
    progress: Option<ProgressBar>,
) -> Result<Vec<TakeoverResult>> {
    let client = build_http_client(config)?;
    let results = Arc::new(DashMap::new());
    let semaphore = Arc::new(Semaphore::new(config.http_concurrency));

    let mut tasks = Vec::new();

    for record in resolved {
        // Check all subdomains that have interesting DNS records
        if !has_interesting_dns(record) {
            continue;
        }

        let record = record.clone();
        let client = client.clone();
        let config = config.clone();
        let results = results.clone();
        let semaphore = semaphore.clone();
        let progress = progress.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let result = check_subdomain(&client, &config, &record).await;
            results.insert(record.name.clone(), result);
            if let Some(pb) = progress {
                pb.inc(1);
            }
        });

        tasks.push(task);
    }

    // Wait for all tasks
    for task in tasks {
        task.await?;
    }

    // Convert to sorted vector
    let mut result: Vec<TakeoverResult> = results.iter().map(|r| r.value().clone()).collect();
    result.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));

    Ok(result)
}

fn has_interesting_dns(record: &Subdomain) -> bool {
    // Check CNAME records
    for cname in &record.cname_records {
        let matches = match_cname(cname);
        if !matches.is_empty() {
            return true;
        }
    }
    
    // Check A/AAAA records
    let all_ips: Vec<std::net::IpAddr> = record.a_records.iter()
        .chain(record.aaaa_records.iter())
        .cloned()
        .collect();
    if !all_ips.is_empty() {
        let a_matches = crate::fingerprints::match_a_records(&all_ips);
        if !a_matches.is_empty() {
            return true;
        }
    }
    
    // Check NXDOMAIN
    let nxdomain_matches = check_nxdomain(record);
    if !nxdomain_matches.is_empty() {
        return true;
    }
    
    false
}

fn build_http_client(config: &Config) -> Result<Client> {
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout))
        .user_agent("subdomain-takeover/0.1.0 (Security Research)")
        .redirect(if config.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .build()?;
    Ok(client)
}

async fn check_subdomain(
    client: &Client,
    config: &Config,
    record: &Subdomain,
) -> TakeoverResult {
    let start = Instant::now();
    let mut fingerprints = Vec::new();
    let mut vulnerable = false;
    let mut provider: Option<crate::models::CloudProvider> = None;
    let mut service_name: Option<String> = None;
    let mut matched_cname: Option<String> = None;
    let mut http_status: Option<u16> = None;
    let mut http_body_snippet: Option<String> = None;

    // Check CNAME records
    for cname in &record.cname_records {
        let matches = match_cname(cname);
        for (prov, svc_name) in matches {
            let prov = prov.clone();
            provider = Some(prov.clone());
            service_name = Some(svc_name.to_string());
            matched_cname = Some(cname.clone());

            // Try HTTP check for this CNAME target
            let (status, body, headers) = fetch_http(client, config, &record.name).await;
            http_status = status;
            http_body_snippet = body.clone();

            // Check for takeover signatures
            let sig_results = check_takeover_signatures(
                &prov,
                status.unwrap_or(0),
                &body.unwrap_or_default(),
                &headers,
            );

            for (p, confidence, desc) in sig_results {
                fingerprints.push(FingerprintMatch {
                    provider: p,
                    service_name: svc_name.to_string(),
                    cname: cname.clone(),
                    evidence: vec![desc],
                    confidence,
                });

                if confidence == ConfidenceLevel::High {
                    vulnerable = true;
                }
            }
        }
    }

    // Check A/AAAA records
    let all_ips: Vec<std::net::IpAddr> = record.a_records.iter()
        .chain(record.aaaa_records.iter())
        .cloned()
        .collect();
    if !all_ips.is_empty() {
        let a_matches = crate::fingerprints::match_a_records(&all_ips);
        for (prov, svc_name, evidence) in a_matches {
                    let prov = prov.clone();
                    if provider.is_none() {
                        provider = Some(prov.clone());
                        service_name = Some(svc_name.to_string());
                    }
            
                    let (status, body, headers) = fetch_http(client, config, &record.name).await;
                    http_status = status;
                    http_body_snippet = body.clone();

                    let sig_results = check_takeover_signatures(
                        &prov,
                        status.unwrap_or(0),
                        &body.unwrap_or_default(),
                        &headers,
                    );

                    for (p, confidence, _desc) in sig_results {
                        fingerprints.push(FingerprintMatch {
                            provider: p,
                            service_name: svc_name.to_string(),
                            cname: "A/AAAA record".to_string(),
                            evidence: vec![evidence.clone()],
                            confidence,
                        });

                        if confidence == ConfidenceLevel::High {
                            vulnerable = true;
                        }
                    }
                }
    }

    // Check dangling CNAMEs / NS-based takeover
    let nxdomain_matches = check_nxdomain(record);
    for (prov, svc_name) in nxdomain_matches {
        let prov = prov.clone();
        if provider.is_none() {
            provider = Some(prov.clone());
            service_name = Some(svc_name.to_string());
        }

        let fp = crate::fingerprints::get_provider(prov.as_str());
        let confidence = fp.map(|fp| match fp.confidence.as_str() {
            "High" => ConfidenceLevel::High,
            "Medium" => ConfidenceLevel::Medium,
            _ => ConfidenceLevel::Low,
        }).unwrap_or(ConfidenceLevel::Medium);

        // Identify which dangling CNAME (if any) triggered the match
        let dangling_cname = fp.and_then(|fp| {
            record.dangling_cnames.iter().find(|cname| {
                let cname_lower = cname.to_lowercase();
                fp.cname_patterns
                    .iter()
                    .any(|p| cname_lower.contains(&p.to_lowercase()))
            })
        }).cloned();

        let (cname_value, evidence, confidence) = match dangling_cname {
            Some(cname) => (
                cname.clone(),
                format!("Dangling CNAME {} - target no longer resolves", cname),
                confidence,
            ),
            None => (
                "NS record".to_string(),
                format!("NS records point to {} but no records exist", svc_name),
                ConfidenceLevel::Medium,
            ),
        };

        fingerprints.push(FingerprintMatch {
            provider: prov.clone(),
            service_name: svc_name.to_string(),
            cname: cname_value,
            evidence: vec![evidence],
            confidence,
        });

        if confidence == ConfidenceLevel::High {
            vulnerable = true;
        }
    }

    // If no specific provider matched but we have DNS records, do generic check
    if !vulnerable && provider.is_none() && (!record.cname_records.is_empty() || !record.a_records.is_empty() || !record.aaaa_records.is_empty()) {
        let (status, body, _headers) = fetch_http(client, config, &record.name).await;
        http_status = status;
        http_body_snippet = body.clone();

        // Check against all fingerprints generically
        for fp in get_all_fingerprints() {
            for sig in &fp.takeover_signatures {
                if sig.status_codes.contains(&status.unwrap_or(0)) || sig.status_codes.is_empty() {
                    for pattern in &sig.body_patterns {
                        if body.as_ref().is_some_and(|b| b.to_lowercase().contains(&pattern.to_lowercase())) {
                            vulnerable = true;
                            provider = Some(crate::models::CloudProvider::new(fp.id.clone(), fp.name.clone()));
                            service_name = Some(fp.name.to_string());
                            matched_cname = record.cname_records.first().cloned();
                            fingerprints.push(FingerprintMatch {
                                provider: crate::models::CloudProvider::new(fp.id.clone(), fp.name.clone()),
                                service_name: fp.name.to_string(),
                                cname: matched_cname.clone().unwrap_or_default(),
                                evidence: vec![sig.description.to_string()],
                                confidence: ConfidenceLevel::Medium,
                            });
                        }
                    }
                }
            }
        }
    }

    let elapsed = start.elapsed();
    debug!(
        "Checked {} in {:.2}s: vulnerable={}, provider={:?}",
        record.name,
        elapsed.as_secs_f64(),
        vulnerable,
        provider
    );

    // Run deeper validation only when explicitly requested (--validate)
    let validation = if config.validate
        && vulnerable
        && matches!(fingerprints.iter().map(|f| f.confidence).max(), Some(ConfidenceLevel::High))
    {
        Some(validate_claimability(provider.as_ref().unwrap(), &record.name, record).await)
    } else {
        None
    };

    TakeoverResult {
        subdomain: record.name.clone(),
        vulnerable,
        provider,
        service_name,
        cname: matched_cname,
        fingerprints,
        http_status,
        http_body_snippet,
        error: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
        validation,
    }
}

async fn fetch_http(
    client: &Client,
    _config: &Config,
    subdomain: &str,
) -> (Option<u16>, Option<String>, HashMap<String, String>) {
    // Try HTTPS first
    let urls = vec![
        format!("https://{}", subdomain),
        format!("http://{}", subdomain),
    ];

    for url in urls {
        match client.get(&url).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let headers: HashMap<String, String> = response
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();

                // Read body with size limit
                let body = match response.text().await {
                    Ok(text) => {
                        let snippet = if text.len() > 5000 {
                            text[..5000].to_string()
                        } else {
                            text
                        };
                        Some(snippet)
                    }
                    Err(_) => None,
                };

                return (Some(status), body, headers);
            }
            Err(e) => {
                debug!("HTTP request failed for {}: {}", url, e);
            }
        }
    }

    (None, None, HashMap::new())
}