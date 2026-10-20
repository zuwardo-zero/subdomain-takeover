//! DNS brute force enumeration

use crate::{Config, wordlists};
use anyhow::Result;
use dashmap::DashSet;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, info};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

/// Enumerate subdomains via DNS brute force
pub async fn enumerate(config: &Config) -> Result<Vec<String>> {
    let wordlist = load_wordlist(config)?;
    info!("Loaded {} words for brute force", wordlist.len());

    // Build resolver once (respects custom resolver config)
    let resolver = Arc::new(build_brute_resolver(config)?);

    let subdomains = Arc::new(DashSet::new());
    let semaphore = Arc::new(Semaphore::new(config.concurrency));

    let mut tasks = Vec::new();

    for word in wordlist {
        // Check max_subdomains limit early
        if config.max_subdomains > 0 && subdomains.len() >= config.max_subdomains {
            break;
        }

        let domain = config.domain.clone();
        let subdomains = subdomains.clone();
        let semaphore = semaphore.clone();
        let resolver = resolver.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let subdomain = format!("{}.{}", word, domain);

            // Quick DNS check - if it resolves, it exists
            if check_dns_exists(&resolver, &subdomain).await {
                subdomains.insert(subdomain);
            }
        });

        tasks.push(task);
    }

    // Wait for all tasks
    for task in tasks {
        task.await?;
    }

    let mut result: Vec<String> = subdomains.iter().map(|s| s.clone()).collect();
    result.sort();
    result.dedup();

    // Apply max_subdomains limit
    if config.max_subdomains > 0 && result.len() > config.max_subdomains {
        result.truncate(config.max_subdomains);
    }

    // Recursive brute force: if enabled, try sub-subdomains for each found subdomain
    if config.recursive && !result.is_empty() {
        info!("Recursive brute force enabled, enumerating sub-subdomains...");
        let recursive_subdomains = enumerate_recursive(config, &result, &resolver).await?;
        result.extend(recursive_subdomains);
        result.sort();
        result.dedup();
        
        // Apply max_subdomains limit again after recursive
        if config.max_subdomains > 0 && result.len() > config.max_subdomains {
            result.truncate(config.max_subdomains);
        }
    }

    debug!("DNS brute force found {} subdomains", result.len());
    Ok(result)
}

fn build_brute_resolver(config: &Config) -> Result<TokioAsyncResolver> {
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

    Ok(TokioAsyncResolver::tokio(resolver_config, resolver_opts))
}

fn load_wordlist(config: &Config) -> Result<Vec<String>> {
    if let Some(path) = &config.wordlist {
        // Load custom wordlist
        let content = std::fs::read_to_string(path)?;
        Ok(content
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect())
    } else {
        // Use built-in wordlist
        Ok(wordlists::get_builtin_wordlist())
    }
}

/// Quick DNS existence check using provided resolver
async fn check_dns_exists(resolver: &Arc<TokioAsyncResolver>, subdomain: &str) -> bool {
    // Try A record lookup
    match resolver.lookup_ip(subdomain).await {
        Ok(lookup) => lookup.iter().next().is_some(),
        Err(_) => false,
    }
}

/// Generate permutations of subdomains (alterations)
pub fn generate_permutations(base_subdomains: &[String]) -> Vec<String> {
    let mut permutations = Vec::new();
    let prefixes = [
        "dev", "staging", "test", "prod", "production", "api", "app", "admin",
        "internal", "private", "internal-api", "internal-app", "v1", "v2", "v3",
        "beta", "alpha", "demo", "sandbox", "preview", "canary", "release",
        "www", "web", "mail", "email", "smtp", "imap", "pop", "ftp", "ssh",
        "vpn", "remote", "desktop", "mobile", "m", "wap", "portal", "dashboard",
        "panel", "console", "manage", "control", "config", "settings", "setup",
        "install", "update", "upgrade", "backup", "restore", "db", "database",
        "sql", "mysql", "postgres", "redis", "cache", "queue", "worker", "job",
        "cron", "scheduler", "task", "monitor", "metrics", "logs", "logging",
        "analytics", "stats", "statistics", "report", "reports", "export", "import",
    ];

    let suffixes = [
        "dev", "staging", "test", "prod", "production", "api", "app", "admin",
        "internal", "private", "beta", "alpha", "demo", "sandbox", "preview",
        "canary", "release", "v1", "v2", "v3", "old", "new", "legacy", "backup",
        "bak", "tmp", "temp", "staging2", "stage", "uat", "qa", "dev2", "dev3",
    ];

    let separators = ["-", ".", "_", ""];

    for base in base_subdomains {
        // Extract the subdomain part (before the main domain)
        let parts: Vec<&str> = base.split('.').collect();
        if parts.len() < 2 {
            continue;
        }
        let subdomain_part = parts[0];
        let domain = parts[1..].join(".");

        // Prefix permutations
        for prefix in &prefixes {
            for sep in &separators {
                permutations.push(format!("{}{}{}.{}", prefix, sep, subdomain_part, domain));
            }
        }

        // Suffix permutations
        for suffix in &suffixes {
            for sep in &separators {
                permutations.push(format!("{}{}{}.{}", subdomain_part, sep, suffix, domain));
            }
        }

        // Numeric suffixes
        for i in 1..=10 {
            permutations.push(format!("{}{}.{}", subdomain_part, i, domain));
        }
    }

    permutations.sort();
    permutations.dedup();
    permutations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_permutations() {
        let base = vec!["api.example.com".to_string()];
        let perms = generate_permutations(&base);

        assert!(perms.contains(&"dev-api.example.com".to_string()));
        assert!(perms.contains(&"api-dev.example.com".to_string()));
        assert!(perms.contains(&"api1.example.com".to_string()));
        assert!(perms.len() > 100);
    }
}

/// Recursive brute force: enumerate sub-subdomains for each found subdomain
#[allow(clippy::unnecessary_to_owned)]
async fn enumerate_recursive(config: &Config, base_subdomains: &[String], resolver: &Arc<TokioAsyncResolver>) -> Result<Vec<String>> {
    let wordlist = load_wordlist(config)?;
    let wordlist = Arc::new(wordlist); // Share wordlist across tasks
    let subdomains = Arc::new(DashSet::new());
    let semaphore = Arc::new(Semaphore::new(config.concurrency));

    let mut tasks = Vec::new();

    for base in base_subdomains {
        // Extract the subdomain part and domain
        let parts: Vec<&str> = base.split('.').collect();
        if parts.len() < 2 {
            continue;
        }
        let subdomain_part = parts[0];
        let domain = parts[1..].join(".");

        for word in wordlist.iter().cloned() {
            #[allow(clippy::unnecessary_to_owned)]
            // cloned() is required here because the async tasks need owned values that live for 'static
            let domain = domain.clone();
            let subdomain_part = subdomain_part.to_string();
            let subdomains = subdomains.clone();
            let semaphore = semaphore.clone();
            let resolver = resolver.clone();

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let subdomain = format!("{}.{}.{}", word, subdomain_part, domain);

                // Quick DNS check - if it resolves, it exists
                if check_dns_exists(&resolver, &subdomain).await {
                    subdomains.insert(subdomain);
                }
            });

            tasks.push(task);
        }
    }

    // Wait for all tasks
    for task in tasks {
        task.await?;
    }

    let result: Vec<String> = subdomains.iter().map(|s| s.clone()).collect();
    debug!("Recursive brute force found {} subdomains", result.len());
    Ok(result)
}