//! Subdomain takeover detection tool
//!
//! Enumerates subdomains via Certificate Transparency logs and DNS brute force,
//! then checks each for dangling DNS records pointing to unclaimed cloud resources.

pub mod ct_logs;
pub mod dns_brute;
pub mod dns_resolver;
pub mod fingerprints;
pub mod models;
pub mod output;
pub mod takeover_check;
pub mod wordlists;
pub mod bbot;
pub mod benchmark;

use anyhow::Result;
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;

/// Truncate a string to at most `max_bytes` bytes without splitting a UTF-8
/// character (plain slicing can panic on multi-byte boundaries).
pub fn safe_truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Build a progress bar with the standard style
fn make_progress_bar(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("##-"),
    );
    pb.set_message(message.to_string());
    pb
}

#[derive(Subcommand, Debug, Clone)]
pub enum BenchmarkCommand {
    /// Run benchmark against a list of subdomains
    Run {
        /// Input file with subdomains (one per line)
        #[arg(short, long)]
        input: String,
        
        /// Output file for benchmark results
        #[arg(short, long, default_value = "benchmark.json")]
        output: String,
        
        /// Number of concurrent DNS resolutions
        #[arg(short, long, default_value = "100")]
        concurrency: usize,
        
        /// Number of concurrent HTTP checks
        #[arg(long, default_value = "50")]
        http_concurrency: usize,
        
        /// Timeout for HTTP requests (seconds)
        #[arg(long, default_value = "10")]
        timeout: u64,
        
        /// Enable CT log enumeration
        #[arg(long, default_value = "false")]
        ct_logs: bool,
        
        /// Enable DNS brute force
        #[arg(long, default_value = "false")]
        brute_force: bool,
        
        /// Maximum subdomains to check (0 = unlimited)
        #[arg(long, default_value = "0")]
        max_subdomains: usize,
    },
}

#[derive(Parser, Debug, Clone)]
#[command(name = "subtake", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<BenchmarkCommand>,
    
    /// Target domain (e.g., example.com)
    #[arg(short, long)]
    pub domain: Option<String>,

    /// Output file for results (JSON)
    #[arg(short, long, default_value = "results.json")]
    pub output: PathBuf,

    /// Disable CT log enumeration
    #[arg(long)]
    pub no_ct_logs: bool,

    /// Disable DNS brute force
    #[arg(long)]
    pub no_brute_force: bool,

    /// Custom wordlist file for DNS brute force
    #[arg(short, long)]
    pub wordlist: Option<PathBuf>,

    /// Number of concurrent DNS resolutions
    #[arg(short, long, default_value = "100")]
    pub concurrency: usize,

    /// Number of concurrent HTTP checks
    #[arg(long, default_value = "50")]
    pub http_concurrency: usize,

    /// Timeout for HTTP requests (seconds)
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Disable following HTTP redirects
    #[arg(long)]
    pub no_follow_redirects: bool,

    /// Only show vulnerable subdomains
    #[arg(long)]
    pub only_vulnerable: bool,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Silent mode (only output JSON)
    #[arg(short, long)]
    pub silent: bool,

    /// DNS resolver to use (e.g., 8.8.8.8, 1.1.1.1)
    #[arg(long, default_value = "1.1.1.1")]
    pub resolver: String,

    /// Maximum subdomains to check (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub max_subdomains: usize,

    /// Enable subdomain permutation/alteration
    #[arg(long, default_value = "false")]
    pub permute: bool,

    /// Enable recursive brute force (sub-subdomain enumeration)
    #[arg(long, default_value = "false")]
    pub recursive: bool,

    /// Rate limit for CT log requests (requests per second)
    #[arg(long, default_value = "10")]
    pub ct_rate_limit: u32,

    /// Enable BBOT enumeration (comprehensive subdomain discovery)
    #[arg(long, default_value = "false")]
    pub bbot: bool,

    /// BBOT mode: fast, passive, active, baddns, subdomain-enum
    #[arg(long, default_value = "fast")]
    pub bbot_mode: String,

    /// Enable deeper validation for high-confidence findings
    #[arg(long, default_value = "false")]
    pub validate: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub domain: String,
    pub output: PathBuf,
    pub ct_logs: bool,
    pub brute_force: bool,
    pub wordlist: Option<PathBuf>,
    pub concurrency: usize,
    pub http_concurrency: usize,
    pub timeout: u64,
    pub follow_redirects: bool,
    pub only_vulnerable: bool,
    pub verbose: bool,
    pub silent: bool,
    pub resolver: String,
    pub max_subdomains: usize,
    pub permute: bool,
    pub recursive: bool,
    pub bbot: bool,
    pub bbot_mode: String,
    pub validate: bool,
    pub ct_rate_limit: u32,
}

impl From<Cli> for Config {
    fn from(args: Cli) -> Self {
        Self {
            domain: args.domain.unwrap_or_default(),
            output: args.output,
            ct_logs: !args.no_ct_logs,
            brute_force: !args.no_brute_force,
            wordlist: args.wordlist,
            concurrency: args.concurrency,
            http_concurrency: args.http_concurrency,
            timeout: args.timeout,
            follow_redirects: !args.no_follow_redirects,
            only_vulnerable: args.only_vulnerable,
            verbose: args.verbose,
            silent: args.silent,
            resolver: args.resolver,
            max_subdomains: args.max_subdomains,
            permute: args.permute,
            recursive: args.recursive,
            bbot: args.bbot,
            bbot_mode: args.bbot_mode,
            validate: args.validate,
            ct_rate_limit: args.ct_rate_limit,
        }
    }
}

pub async fn run(config: Config) -> Result<()> {
    // Initialize fingerprints - fail loudly if the embedded provider DB is broken
    crate::fingerprints::init_providers()
        .map_err(|e| anyhow::anyhow!("failed to load provider fingerprints: {}", e))?;
    
    use crate::{ct_logs, dns_brute, dns_resolver, output, takeover_check, bbot};
    use std::time::Instant;

    let start_time = Instant::now();
    let mut all_subdomains = Vec::new();

    // Phase 1: Certificate Transparency Logs
    if config.ct_logs {
        if !config.silent {
            eprintln!("[+] Enumerating subdomains from Certificate Transparency logs...");
        }
        let ct_subdomains = ct_logs::enumerate(&config).await?;
        if !config.silent {
            eprintln!("[+] CT logs found {} subdomains", ct_subdomains.len());
        }
        all_subdomains.extend(ct_subdomains);
    }

    // Phase 1b: BBOT Enumeration (comprehensive OSINT)
    if config.bbot {
        if !config.silent {
            eprintln!("[+] Enumerating subdomains with BBOT...");
        }
        let bbot_subdomains = bbot::enumerate(&config).await?;
        if !config.silent {
            eprintln!("[+] BBOT found {} subdomains", bbot_subdomains.len());
        }
        all_subdomains.extend(bbot_subdomains);
    }

    // Phase 2: DNS Brute Force
    if config.brute_force {
        if !config.silent {
            eprintln!("[+] Starting DNS brute force...");
        }
        let brute_subdomains = dns_brute::enumerate(&config).await?;
        if !config.silent {
            eprintln!("[+] DNS brute force found {} subdomains", brute_subdomains.len());
        }
        all_subdomains.extend(brute_subdomains);
    }

    // Phase 2b: Subdomain Permutation/Alteration
    if config.permute && !all_subdomains.is_empty() {
        if !config.silent {
            eprintln!("[+] Generating subdomain permutations...");
        }
        let permuted = dns_brute::generate_permutations(&all_subdomains);
        // Permutations are mostly dead names - filter them down to the ones
        // that actually resolve before feeding them into the full resolve phase
        let permuted = dns_brute::filter_existing(&config, permuted).await?;
        if !config.silent {
            eprintln!("[+] {} permuted subdomains exist", permuted.len());
        }
        all_subdomains.extend(permuted);
    }

    // Deduplicate
    all_subdomains.sort();
    all_subdomains.dedup();

    // Apply max_subdomains limit
    if config.max_subdomains > 0 && all_subdomains.len() > config.max_subdomains {
        all_subdomains.truncate(config.max_subdomains);
    }

    if !config.silent {
        eprintln!("[+] Total unique subdomains to check: {}", all_subdomains.len());
    }

    // Phase 3: DNS Resolution + CNAME extraction
    if !config.silent {
        eprintln!("[+] Resolving DNS records and extracting CNAMEs...");
    }

    let dns_pb = if !config.silent {
        Some(make_progress_bar(all_subdomains.len() as u64, "Resolving DNS"))
    } else {
        None
    };

    let resolved = dns_resolver::resolve_all_with_progress(&config, &all_subdomains, dns_pb.clone()).await?;

    if let Some(pb) = dns_pb {
        pb.finish_with_message("DNS resolution complete");
    }

    if !config.silent {
        eprintln!("[+] Resolved {} subdomains with DNS records", resolved.len());
    }

    // Phase 4: Takeover Detection
    if !config.silent {
        eprintln!("[+] Checking for subdomain takeover vulnerabilities...");
    }

    // Filter subdomains with interesting DNS for progress bar
    let interesting_count = resolved.iter().filter(|r| dns_resolver::has_cloud_cname(r)).count() as u64;

    let http_pb = if !config.silent && interesting_count > 0 {
        Some(make_progress_bar(interesting_count, "Checking takeovers"))
    } else {
        None
    };

    let results = takeover_check::check_all_with_progress(&config, &resolved, http_pb.clone()).await?;

    if let Some(pb) = http_pb {
        pb.finish_with_message("Takeover check complete");
    }

    // Phase 5: Output
    let duration = start_time.elapsed().as_secs_f64();
    output::write_results(&config, &results, duration, resolved.len()).await?;

    if !config.silent {
        // Console listing of findings (respects --only-vulnerable)
        output::print_results(&results, config.only_vulnerable);
        let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();
        eprintln!("\n[+] Scan complete. {} vulnerable subdomains found.", vulnerable_count);
        eprintln!("[+] Results written to {}", config.output.display());
    }

    Ok(())
}