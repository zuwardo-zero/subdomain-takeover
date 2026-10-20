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

/// Detect wildcard DNS by querying random non-existent subdomains
async fn detect_wildcard(resolver: &Arc<TokioAsyncResolver>, domain: &str) -> Vec<std::net::IpAddr> {
    use rand::Rng;
    use std::collections::HashSet;

    let mut wildcard_ips = HashSet::new();
    let mut rng = rand::thread_rng();

    // Query 5 random subdomains that are unlikely to exist
    for _ in 0..5 {
        let random_sub = format!("{}.{}", rng.gen::<u64>(), domain);
        if let Ok(lookup) = resolver.lookup_ip(&random_sub).await {
            for ip in lookup.iter() {
                wildcard_ips.insert(ip);
            }
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
            tls_config: None,
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
    };

    // Resolve A records
    if let Ok(lookup) = resolver.lookup_ip(subdomain).await {
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

    // Resolve CNAME records
    if let Ok(response) = resolver.lookup(subdomain, RecordType::CNAME).await {
        for record_data in response.records() {
            if let Some(RData::CNAME(cname)) = record_data.data() {
                record.cname_records.push(cname.to_string());
            }
        }
    }

    // Resolve TXT records
    if let Ok(response) = resolver.lookup(subdomain, RecordType::TXT).await {
        for record_data in response.records() {
            if let Some(RData::TXT(txt)) = record_data.data() {
                for txt_data in txt.iter() {
                    record.txt_records.push(String::from_utf8_lossy(txt_data).to_string());
                }
            }
        }
    }

    // Resolve NS records
    if let Ok(response) = resolver.lookup(subdomain, RecordType::NS).await {
        for record_data in response.records() {
            if let Some(RData::NS(ns)) = record_data.data() {
                record.ns_records.push(ns.to_string());
            }
        }
    }

    // Resolve MX records
    if let Ok(response) = resolver.lookup(subdomain, RecordType::MX).await {
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

    debug!("Resolved {}: A={}, AAAA={}, CNAME={}", subdomain, record.a_records.len(), record.aaaa_records.len(), record.cname_records.len());
    Ok(record)
}

/// Check if a subdomain has a CNAME pointing to a known cloud provider
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
    
    // Check NXDOMAIN
    let nxdomain_matches = check_nxdomain(record);
    if !nxdomain_matches.is_empty() {
        return true;
    }
    
    false
}

/// Get all CNAME targets for a subdomain
pub fn get_cname_chain(record: &Subdomain) -> Vec<String> {
    record.cname_records.clone()
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
            dns_semaphore: Arc::new(Semaphore::new(100)),
            http_semaphore: Arc::new(Semaphore::new(50)),
        };

        let resolver = build_resolver(&config);
        assert!(resolver.is_ok());
    }
}