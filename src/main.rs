//! Subdomain Takeover Detection Tool
//!
//! Enumerates subdomains via Certificate Transparency logs and DNS brute force,
//! then checks each for dangling DNS records pointing to unclaimed cloud resources.

use subdomain_takeover::{run, benchmark::run_benchmark, Cli, Config};
use anyhow::Result;
use clap::Parser;
use std::time::Instant;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else if cli.silent { "error" } else { "info" };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();

    // Handle benchmark subcommand
    if let Some(bench_cmd) = cli.command {
        return run_benchmark(bench_cmd).await;
    }

    // Normal scan mode - require domain
    let domain = cli.domain.clone().ok_or_else(|| anyhow::anyhow!("Domain is required (use -d or --domain)"))?;
    let mut config = Config::from(cli);
    config.domain = domain;

    if !config.silent {
        // ASCII art "subtake" banner
        eprintln!(r#"
             _     _        _
  ___ _   _| |__ | |_ __ _| | _____
 / __| | | | '_ \| __/ _` | |/ / _ \
 \__ \ |_| | |_) | || (_| |   <  __/
 |___/\__,_|_.__/ \__\__,_|_|\_\___|
                                    
        Subdomain Takeover Detection Tool

"#);
        eprintln!();
        eprintln!("Target: {}", config.domain);
        eprintln!("CT Logs: {}", if config.ct_logs { "enabled" } else { "disabled" });
        eprintln!("DNS Brute Force: {}", if config.brute_force { "enabled" } else { "disabled" });
        eprintln!("BBOT: {} ({})", if config.bbot { "enabled" } else { "disabled" }, config.bbot_mode);
        eprintln!("Permutations: {}", if config.permute { "enabled" } else { "disabled" });
        eprintln!("Recursive: {}", if config.recursive { "enabled" } else { "disabled" });
        eprintln!("Validation: {}", if config.validate { "enabled" } else { "disabled" });
        eprintln!("Concurrency: {} (DNS) / {} (HTTP)", config.concurrency, config.http_concurrency);
        eprintln!();
    }

    let start = Instant::now();

    match run(config.clone()).await {
        Ok(_) => {
            let elapsed = start.elapsed();
            if !config.silent {
                eprintln!("\n[+] Scan completed in {:.2}s", elapsed.as_secs_f64());
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("\n[-] Error: {}", e);
            std::process::exit(1);
        }
    }
}
