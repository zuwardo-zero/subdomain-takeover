//! Output formatting and writing

use crate::models::{ScanMetadata, ScanResults, TakeoverResult};
use crate::Config;
use anyhow::Result;
use std::fs;
use tracing::info;

/// Write scan results to JSON file
pub async fn write_results(
    config: &Config,
    results: &[TakeoverResult],
    duration: f64,
    total_resolved: usize,
) -> Result<()> {
    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();

    let scan_results = ScanResults {
        target_domain: config.domain.clone(),
        scan_timestamp: chrono::Utc::now().to_rfc3339(),
        total_subdomains_checked: total_resolved,
        vulnerable_count,
        results: results.to_vec(),
        metadata: ScanMetadata {
            ct_logs_enabled: config.ct_logs,
            brute_force_enabled: config.brute_force,
            bbot_enabled: config.bbot,
            bbot_mode: config.bbot_mode.clone(),
            permute_enabled: config.permute,
            recursive_enabled: config.recursive,
            wordlist_used: config.wordlist.as_ref().map(|p| p.display().to_string()),
            concurrency: config.concurrency,
            http_concurrency: config.http_concurrency,
            timeout_seconds: config.timeout,
            duration_seconds: duration,
            subdomains_per_second: None,
        },
    };

    let json = serde_json::to_string_pretty(&scan_results)?;
    fs::write(&config.output, json)?;

    // Also write a human-readable summary and CSV
    write_summary(config, &scan_results).await?;
    write_csv(config, results).await?;

    Ok(())
}

async fn write_summary(config: &Config, results: &ScanResults) -> Result<()> {
    let summary_path = config.output.with_extension("txt");
    let mut summary = String::new();

    summary.push_str("Subdomain Takeover Scan Results\n");
    summary.push_str("================================\n\n");
    summary.push_str(&format!("Target Domain: {}\n", results.target_domain));
    summary.push_str(&format!("Scan Time: {}\n", results.scan_timestamp));
    summary.push_str(&format!("Total Subdomains Checked: {}\n", results.total_subdomains_checked));
    summary.push_str(&format!("Vulnerable Subdomains: {}\n\n", results.vulnerable_count));

    if results.vulnerable_count > 0 {
        summary.push_str("VULNERABLE SUBDOMAINS:\n");
        summary.push_str("----------------------\n\n");

        for result in &results.results {
            if result.vulnerable {
                summary.push_str(&format!("Subdomain: {}\n", result.subdomain));
                summary.push_str(&format!(
                    "  Provider: {}\n",
                    result.service_name.as_deref().unwrap_or("Unknown")
                ));
                summary.push_str(&format!("  CNAME: {}\n", result.cname.as_deref().unwrap_or("N/A")));

                if let Some(status) = result.http_status {
                    summary.push_str(&format!("  HTTP Status: {}\n", status));
                }

                for fp in &result.fingerprints {
                    summary.push_str(&format!("  Evidence: {} (Confidence: {:?})\n", fp.evidence.join(", "), fp.confidence));
                }

                if let Some(body) = &result.http_body_snippet {
                    let snippet = if body.len() > 200 {
                        format!("{}...", crate::safe_truncate(body, 200))
                    } else {
                        body.clone()
                    };
                    summary.push_str(&format!("  Response Snippet: {}\n", snippet));
                }

                if let Some(validation) = &result.validation {
                    summary.push_str(&format!("  Validation: {} - {}\n", 
                        validation.claimable.map(|c| if c { "CLAIMABLE" } else { "NOT CLAIMABLE" }).unwrap_or("UNKNOWN"),
                        validation.details
                    ));
                }

                summary.push('\n');
            }
        }
    } else {
        summary.push_str("No vulnerable subdomains found.\n");
    }

    summary.push_str("\nALL CHECKED SUBDOMAINS:\n");
    summary.push_str("-----------------------\n\n");

    for result in &results.results {
        let status = if result.vulnerable { "VULNERABLE" } else { "OK" };
        summary.push_str(&format!("{} - {}\n", result.subdomain, status));

        if let Some(cname) = &result.cname {
            if !cname.is_empty() {
                summary.push_str(&format!("  CNAME: {}\n", cname));
            }
        }

        if !result.fingerprints.is_empty() {
            for fp in &result.fingerprints {
                summary.push_str(&format!(
                    "  Fingerprint: {} - {}\n",
                    fp.service_name,
                    fp.evidence.join(", ")
                ));
            }
        }
    }

    fs::write(&summary_path, summary)?;
    info!("Summary written to {}", summary_path.display());

    Ok(())
}

/// Write results in CSV format
pub async fn write_csv(config: &Config, results: &[TakeoverResult]) -> Result<()> {
    let csv_path = config.output.with_extension("csv");
    let mut csv = String::new();

    // Header
    csv.push_str("subdomain,vulnerable,provider,service_name,cname,http_status,confidence,evidence,timestamp,validation_claimable,validation_details\n");

    for result in results {
        for fp in &result.fingerprints {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{:?},{},{},{},{}\n",
                result.subdomain,
                result.vulnerable,
                result.provider.as_ref().map(|p| p.as_str()).unwrap_or(""),
                result.service_name.as_deref().unwrap_or(""),
                result.cname.as_deref().unwrap_or(""),
                result.http_status.map(|s| s.to_string()).unwrap_or_default(),
                fp.confidence,
                fp.evidence.join("; "),
                result.timestamp,
                result.validation.as_ref().map(|v| v.claimable.map(|c| if c { "YES" } else { "NO" }).unwrap_or("UNKNOWN")).unwrap_or(""),
                result.validation.as_ref().map(|v| v.details.replace(',', ";")).unwrap_or_default(),
            ));
        }

        // If no fingerprints, still output a row
        if result.fingerprints.is_empty() {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{}\n",
                result.subdomain,
                result.vulnerable,
                result.provider.as_ref().map(|p| p.as_str()).unwrap_or(""),
                result.service_name.as_deref().unwrap_or(""),
                result.cname.as_deref().unwrap_or(""),
                result.http_status.map(|s| s.to_string()).unwrap_or_default(),
                "", // confidence
                "", // evidence
                result.timestamp,
                result.validation.as_ref().map(|v| v.claimable.map(|c| if c { "YES" } else { "NO" }).unwrap_or("UNKNOWN")).unwrap_or(""),
                result.validation.as_ref().map(|v| v.details.replace(',', ";")).unwrap_or_default(),
            ));
        }
    }

    fs::write(&csv_path, csv)?;
    info!("CSV written to {}", csv_path.display());

    Ok(())
}

/// Print results to console (for non-silent mode)
pub fn print_results(results: &[TakeoverResult], only_vulnerable: bool) {
    for result in results {
        if only_vulnerable && !result.vulnerable {
            continue;
        }

        if result.vulnerable {
            println!("\n🔴 VULNERABLE: {}", result.subdomain);
            println!(
                "   Provider: {}",
                result.service_name.as_deref().unwrap_or("Unknown")
            );
            println!("   CNAME: {}", result.cname.as_deref().unwrap_or("N/A"));

            if let Some(status) = result.http_status {
                println!("   HTTP Status: {}", status);
            }

            for fp in &result.fingerprints {
                println!("   Evidence: {} (Confidence: {:?})", fp.evidence.join(", "), fp.confidence);
            }
        } else if !only_vulnerable {
            println!("✓ {} - OK", result.subdomain);
            if let Some(cname) = &result.cname {
                if !cname.is_empty() {
                    println!("   CNAME: {}", cname);
                }
            }
        }
    }

    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();
    println!("\n=== Summary ===");
    println!("Subdomains with provider matches: {}", results.len());
    println!("Vulnerable: {}", vulnerable_count);
}