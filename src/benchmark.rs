//! Benchmark module for performance testing

use crate::{Config, BenchmarkCommand};
use crate::{ct_logs, dns_brute, dns_resolver, takeover_check};
use anyhow::Result;
use std::fs;
use std::sync::Arc;
use std::time::{Instant};
use tokio::sync::Semaphore;
use tracing::{info};

/// Run benchmark against a list of subdomains
pub async fn run_benchmark(cmd: BenchmarkCommand) -> Result<()> {
    let BenchmarkCommand::Run {
        input,
        output,
        concurrency,
        http_concurrency,
        timeout,
        ct_logs,
        brute_force,
        max_subdomains,
    } = cmd;
    
    let _start_time = Instant::now();
    let content = fs::read_to_string(&input)?;
    let subdomains: Vec<String> = content
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    
    let total_subdomains = subdomains.len();
    info!("Loaded {} subdomains for benchmark", total_subdomains);
    
    // Create config from benchmark command
    // Extract base domain from first subdomain for wildcard detection
    let base_domain = subdomains.first()
        .and_then(|s| s.split('.').skip(1).collect::<Vec<_>>().join(".").into())
        .unwrap_or_else(|| "example.com".to_string());
    
    let config = Config {
        domain: base_domain,
        output: output.clone().into(),
        ct_logs,
        brute_force,
        wordlist: None,
        concurrency,
        http_concurrency,
        timeout,
        follow_redirects: true,
        only_vulnerable: false,
        verbose: false,
        silent: true,
        resolver: "1.1.1.1".to_string(),
        max_subdomains,
        permute: false,
        recursive: false,
        bbot: false,
        bbot_mode: "fast".to_string(),
        validate: false,
        ct_rate_limit: 10,
        dns_semaphore: Arc::new(Semaphore::new(concurrency)),
        http_semaphore: Arc::new(Semaphore::new(http_concurrency)),
    };

    let start_time = Instant::now();
    let mut all_subdomains = Vec::new();
    
    // Use provided subdomains as the base
    all_subdomains.extend(subdomains);
    
    // Phase 1: Certificate Transparency Logs (if enabled)
    if ct_logs {
        let ct_subdomains = ct_logs::enumerate(&config).await?;
        all_subdomains.extend(ct_subdomains);
    }

    // Phase 2: DNS Brute Force (if enabled)
    if brute_force {
        let brute_subdomains = dns_brute::enumerate(&config).await?;
        all_subdomains.extend(brute_subdomains);
    }

    // Deduplicate
    all_subdomains.sort();
    all_subdomains.dedup();
    
    // Apply max_subdomains limit if set
    if config.max_subdomains > 0 && all_subdomains.len() > config.max_subdomains {
        all_subdomains.truncate(config.max_subdomains);
    }

    // Phase 3: DNS Resolution + CNAME extraction
    let resolved = dns_resolver::resolve_all(&config, &all_subdomains).await?;

    // Phase 4: Takeover Detection
    let results = takeover_check::check_all(&config, &resolved).await?;

    let duration = start_time.elapsed().as_secs_f64();
    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();

    // Calculate metrics
    let subdomains_per_second = total_subdomains as f64 / duration;
    
    let benchmark_results = crate::models::BenchmarkResults {
        total_subdomains: all_subdomains.len(),
        total_time_seconds: duration,
        subdomains_per_second,
        vulnerable_found: vulnerable_count,
        providers_checked: 80,
        dns_queries: all_subdomains.len() * 6,
        http_requests: results.iter().filter(|r| r.http_status.is_some()).count(),
        memory_peak_mb: get_memory_usage_mb(),
    };

    // Write benchmark results
    let json = serde_json::to_string_pretty(&benchmark_results)?;
    fs::write(&output, json)?;

    println!("\n=== Benchmark Results ===");
    println!("Total subdomains processed: {}", all_subdomains.len());
    println!("Total time: {:.2}s", duration);
    println!("Subdomains/second: {:.2}", subdomains_per_second);
    println!("Vulnerable found: {}", vulnerable_count);
    println!("DNS queries: ~{}", all_subdomains.len() * 6);
    println!("HTTP requests: {}", results.iter().filter(|r| r.http_status.is_some()).count());
    println!("Memory peak: {:.1} MB", benchmark_results.memory_peak_mb);
    println!("Results written to: {}", output);

    Ok(())
}

fn get_memory_usage_mb() -> f64 {
    // Get memory usage from /proc/self/status on Linux
    if let Ok(content) = fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<f64>() {
                        return kb / 1024.0;
                    }
                }
            }
        }
    }
    0.0
}