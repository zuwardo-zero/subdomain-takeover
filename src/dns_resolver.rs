//! DNS resolution with CNAME tracking

use crate::{Config, models::Subdomain};
use anyhow::Result;
use dashmap::DashMap;
use indicatif::ProgressBar;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::debug;
use trust_dns_proto::rr::{RecordType, RData};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

/// Resolve all subdomains and extract DNS records including CNAMEs
pub async fn resolve_all(config: &Config, subdomains: &[String]) -> Result<Vec<Subdomain>> {
    resolve_all_with_progress(config, subdomains, None).await
}

/// Resolve all subdomains with optional progress bar
pub async fn resolve_all_with_progress(
    config: &Config,
    subdomains: &[String],
    progress: Option<ProgressBar>,
) -> Result<Vec<Subdomain>> {
    let resolver = build_resolver(config)?;

    // Detect wildcard DNS
    let wildcard_ips = detect_wildcard(&resolver, &config.domain).await;
    if !wildcard_ips.is_empty() && !config.silent {
        eprintln!("[!] Wildcard DNS detected for {}: {} IP(s)", config.domain, wildcard_ips.len());
    }

    let results = Arc::new(DashMap::new());
    let semaphore = Arc::new(Semaphore::new(config.concurrency));

    let mut tasks = Vec::new();

    for subdomain in subdomains {
        let subdomain = subdomain.clone();
        let resolver = resolver.clone();
        let results = results.clone();
        let semaphore = semaphore.clone();
        let wildcard_ips = wildcard_ips.clone();
        let progress = progress.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            match resolve_subdomain(&resolver, &subdomain, &wildcard_ips).await {
                Ok(record) => {
                    results.insert(subdomain, record);
                }
                Err(e) => {
                    debug!("Failed to resolve {}: {}", subdomain, e);
                }
            }
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
    let mut result: Vec<Subdomain> = results.iter().map(|r| r.value().clone()).collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(result)
}

/// Detect wildcard DNS by querying random non-existent subdomains.
/// Probes run concurrently so detection adds minimal latency.
pub async fn detect_wildcard(resolver: &Arc<TokioAsyncResolver>, domain: &str) -> Vec<std::net::IpAddr> {
    use std::collections::HashSet;

    let mut probes = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let resolver = resolver.clone();
        let random_sub = format!("{}.{}", rand::random::<u64>(), domain);
        probes.spawn(async move {
            resolver
                .lookup_ip(&random_sub)
                .await
                .map(|lookup| lookup.iter().collect::<Vec<std::net::IpAddr>>())
                .unwrap_or_default()
        });
    }

    let mut wildcard_ips = HashSet::new();
    while let Some(result) = probes.join_next().await {
        if let Ok(ips) = result {
            wildcard_ips.extend(ips);
        }
    }

    wildcard_ips.into_iter().collect()
}

fn build_resolver(config: &Config) -> Result<Arc<TokioAsyncResolver>> {
    // Parse custom resolver if provided
    let resolver_config = if config.resolver != "default" {
        use trust_dns_resolver::config::NameServerConfig;
        use trust_dns_resolver::config::Protocol;
        use std::net::SocketAddr;
        use std::str::FromStr;

        let addr = SocketAddr::from_str(&format!("{}:53", config.resolver))?;
        let ns_config = NameServerConfig {
            socket_addr: addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        };
        ResolverConfig::from_parts(None, vec![], vec![ns_config])
    } else {
        ResolverConfig::default()
    };

    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.attempts = 2;
    resolver_opts.timeout = std::time::Duration::from_secs(5);

    let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);
    Ok(Arc::new(resolver))
}

async fn resolve_subdomain(
    resolver: &Arc<TokioAsyncResolver>,
    subdomain: &str,
    wildcard_ips: &[std::net::IpAddr],
) -> Result<Subdomain> {
    let mut record = Subdomain {
        name: subdomain.to_string(),
        a_records: Vec::new(),
        aaaa_records: Vec::new(),
        cname_records: Vec::new(),
        txt_records: Vec::new(),
        ns_records: Vec::new(),
        mx_records: Vec::new(),
        dangling_cnames: Vec::new(),
    };

    // Run the independent record lookups concurrently - cuts per-subdomain
    // latency from the sum of all queries to the slowest single query
    let (ip_result, cname_result, txt_result, ns_result, mx_result) = tokio::join!(
        resolver.lookup_ip(subdomain),
        resolver.lookup(subdomain, RecordType::CNAME),
        resolver.lookup(subdomain, RecordType::TXT),
        resolver.lookup(subdomain, RecordType::NS),
        resolver.lookup(subdomain, RecordType::MX),
    );

    // A / AAAA records
    if let Ok(lookup) = ip_result {
        for ip in lookup.iter() {
            // Skip wildcard responses
            if wildcard_ips.contains(&ip) {
                continue;
            }
            if ip.is_ipv4() {
                record.a_records.push(ip);
            } else {
                record.aaaa_records.push(ip);
            }
        }
    }

    // CNAME records
    if let Ok(response) = cname_result {
        for record_data in response.records() {
            if let Some(RData::CNAME(cname)) = record_data.data() {
                record.cname_records.push(cname.to_string());
            }
        }
    }

    // TXT records
    if let Ok(response) = txt_result {
        for record_data in response.records() {
            if let Some(RData::TXT(txt)) = record_data.data() {
                for txt_data in txt.iter() {
                    record.txt_records.push(String::from_utf8_lossy(txt_data).to_string());
                }
            }
        }
    }

    // NS records
    if let Ok(response) = ns_result {
        for record_data in response.records() {
            if let Some(RData::NS(ns)) = record_data.data() {
                record.ns_records.push(ns.to_string());
            }
        }
    }

    // MX records
    if let Ok(response) = mx_result {
        for record_data in response.records() {
            if let Some(RData::MX(mx)) = record_data.data() {
                record.mx_records.push(format!("{} {}", mx.preference(), mx.exchange()));
            }
        }
    }

    // Follow CNAME chain if present
    for initial_cname in record.cname_records.clone() {
        let mut current_cname = initial_cname;
        let mut visited = std::collections::HashSet::new();
        visited.insert(current_cname.clone());

        // Limit CNAME chain following to prevent loops
        for _ in 0..10 {
            if let Ok(response) = resolver.lookup(&current_cname, RecordType::CNAME).await {
                let mut found_next = false;
                for record_data in response.records() {
                    if let Some(RData::CNAME(cname)) = record_data.data() {
                        let next = cname.to_string();
                        if visited.insert(next.clone()) {
                            record.cname_records.push(next.clone());
                            current_cname = next;
                            found_next = true;
                        }
                        break;
                    }
                }
                if !found_next {
                    break;
                }
            } else {
                break;
            }
        }
    }

    // Detect dangling CNAME: final target no longer resolves (NXDOMAIN).
    // This is the actual subdomain takeover scenario - the CNAME still points
    // at a provider hostname whose resource was deleted.
    if let Some(last_target) = record.cname_records.last().cloned()
        && !last_target.is_empty()
    {
        match resolver.lookup_ip(&last_target).await {
            Ok(_) => {}
            Err(e) => {
                use trust_dns_resolver::error::ResolveErrorKind;
                let is_nxdomain = matches!(
                    e.kind(),
                    ResolveErrorKind::NoRecordsFound { response_code, .. }
                        if *response_code == trust_dns_proto::op::ResponseCode::NXDomain
                );
                if is_nxdomain {
                    record.dangling_cnames.push(last_target);
                }
            }
        }
    }

    debug!("Resolved {}: A={}, AAAA={}, CNAME={}, dangling={}", subdomain, record.a_records.len(), record.aaaa_records.len(), record.cname_records.len(), record.dangling_cnames.len());
    Ok(record)
}

/// Check if a subdomain has a CNAME pointing to a known cloud provider,
/// A/AAAA records inside a provider's IP ranges, or a dangling/NS-based match
pub fn has_cloud_cname(record: &Subdomain) -> bool {
    use crate::fingerprints::{match_cname, match_a_records, check_nxdomain};
    
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
        let a_matches = match_a_records(&all_ips);
        if !a_matches.is_empty() {
            return true;
        }
    }
    
    // Check dangling CNAMEs / NS-based takeover
    let nxdomain_matches = check_nxdomain(record);
    if !nxdomain_matches.is_empty() {
        return true;
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_resolver() {
        let config = Config {
            domain: "example.com".to_string(),
            output: "test.json".into(),
            ct_logs: true,
            brute_force: true,
            wordlist: None,
            concurrency: 100,
            http_concurrency: 50,
            timeout: 10,
            follow_redirects: true,
            only_vulnerable: false,
            verbose: false,
            silent: true,
            resolver: "1.1.1.1".to_string(),
            max_subdomains: 0,
            permute: false,
            recursive: false,
            bbot: false,
            bbot_mode: "fast".to_string(),
            validate: false,
            ct_rate_limit: 10,
        };

        let resolver = build_resolver(&config);
        assert!(resolver.is_ok());
    }
}