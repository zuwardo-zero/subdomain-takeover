# subtake - Subdomain Takeover Detection Tool

A fast, concurrent subdomain takeover detection tool written in Rust. It enumerates subdomains via Certificate Transparency logs, DNS brute force, and BBOT, then checks each for dangling DNS records pointing to unclaimed cloud resources.

## ✨ Features

- **Certificate Transparency Log Enumeration** - Queries crt.sh, CertSpotter, and URLScan.io for historical subdomain certificates
- **DNS Brute Force** - **5000 common subdomain names** (SecLists top 1M) + custom wordlists (`-w`)
- **Subdomain Permutations** - Generates prefix/suffix/number variations (`--permute`)
- **Recursive Brute Force** - Enumerates sub-subdomains for discovered subdomains (`--recursive`)
- **BBOT Integration** - 5 modes: fast, passive, active, baddns, subdomain-enum (`--bbot --bbot-mode`)
- **Wildcard DNS Detection** - Automatically detects and filters wildcard responses
- **Cloud Provider Fingerprinting** - **78+ cloud services** with CNAME patterns, A/AAAA IP ranges, dangling CNAME / NS-based takeover checks, and HTTP signature matching
- **CNAME Chain Following** - Resolves full CNAME chains (up to 10 hops) with loop detection
- **Progress Bars** - Real-time progress for DNS resolution and HTTP checks
- **Concurrent Scanning** - Configurable concurrency for DNS (`-c`) and HTTP (`--http-concurrency`) checks
- **Multiple Output Formats** - JSON, human-readable text summary, and CSV
- **Takeover Signature Detection** - Matches known vulnerability fingerprints per cloud provider
- **Scan Duration Tracking** - Records total scan time in metadata
- **Custom DNS Resolver** - Use `--resolver 8.8.8.8` or any DNS server
- **Max Subdomains Limit** - Limit checks with `--max-subdomains N`
- **Deeper Validation** - `--validate` runs claimability validation for high-confidence findings

## 📦 Installation

### From Source

```bash
git clone https://github.com/zuwardo-zero/subdomain-takeover
cd subdomain-takeover
cargo build --release
```

## 🚀 Usage

```bash
# Basic scan with CT logs and brute force
subtake -d example.com

# Quick scan with BBOT fast mode
subtake -d example.com --bbot --bbot-mode fast

# Comprehensive scan with all features
subtake -d example.com --bbot --bbot-mode baddns --permute --recursive --max-subdomains 5000

# CT logs + brute force only
subtake -d example.com

# Only CT logs, no brute force
subtake -d example.com --no-brute-force

# Only brute force, no CT logs
subtake -d example.com --no-ct-logs

# Do not follow HTTP redirects
subtake -d example.com --no-follow-redirects

# Use custom wordlist
subtake -d example.com -w /path/to/wordlist.txt

# High concurrency for large scans
subtake -d example.com -c 200 --http-concurrency 100

# Only show vulnerable subdomains
subtake -d example.com --only-vulnerable

# Silent mode (JSON only)
subtake -d example.com --silent

# Custom DNS resolver
subtake -d example.com --resolver 8.8.8.8

# Limit subdomains to check
subtake -d example.com --max-subdomains 1000

# Enable subdomain permutations
subtake -d example.com --permute

# Enable recursive brute force (sub-subdomains)
subtake -d example.com --recursive

# Custom output file
subtake -d example.com -o my-results.json
```

## 🔧 BBOT Modes

| Mode | Description | Best For |
|------|-------------|----------|
| `fast` | Passive subdomain-enum modules (quick) | Quick reconnaissance |
| `passive` | Passive modules only (no active connections) | Stealth enumeration |
| `active` | Active + passive subdomain-enum modules | Comprehensive discovery |
| `baddns` | Subdomain takeover detection modules (`baddns-heavy`) | Takeover hunting |
| `subdomain-enum` | Comprehensive subdomain enumeration | Maximum coverage |

## 📊 Output Formats

### JSON (default)

```json
{
  "target_domain": "example.com",
  "scan_timestamp": "2026-10-19T17:58:24.508918108+00:00",
  "total_subdomains_checked": 42,
  "vulnerable_count": 2,
  "results": [
    {
      "subdomain": "dev.example.com",
      "vulnerable": true,
      "provider": "AwsS3",
      "service_name": "AWS S3",
      "cname": "dev-example-com.s3.amazonaws.com",
      "fingerprints": [
        {
          "provider": "AwsS3",
          "service_name": "AWS S3",
          "cname": "dev-example-com.s3.amazonaws.com",
          "evidence": ["S3 bucket does not exist - can be claimed"],
          "confidence": "High"
        }
      ],
      "http_status": 404,
      "http_body_snippet": "NoSuchBucket...",
      "timestamp": "2026-10-19T17:58:24.123456789+00:00"
    }
  ],
  "metadata": {
    "ct_logs_enabled": true,
    "brute_force_enabled": true,
    "bbot_enabled": true,
    "bbot_mode": "baddns",
    "permute_enabled": true,
    "recursive_enabled": true,
    "concurrency": 100,
    "http_concurrency": 50,
    "timeout_seconds": 10,
    "duration_seconds": 45.2
  }
}
```

### Text Summary (`results.txt`)

```
Subdomain Takeover Scan Results
================================

Target Domain: example.com
Scan Time: 2026-10-19T17:58:24.508918108+00:00
Total Subdomains Checked: 42
Vulnerable Subdomains: 2

VULNERABLE SUBDOMAINS:
----------------------

Subdomain: dev.example.com
  Provider: AwsS3 (AWS S3)
  CNAME: dev-example-com.s3.amazonaws.com
  HTTP Status: 404
  Evidence: S3 bucket does not exist - can be claimed (Confidence: High)
  Response Snippet: NoSuchBucket...
```

### CSV (`results.csv`)

```csv
subdomain,vulnerable,provider,service_name,cname,http_status,confidence,evidence,timestamp
dev.example.com,true,AwsS3,AWS S3,dev-example-com.s3.amazonaws.com,404,High,S3 bucket does not exist - can be claimed,2026-10-19T17:58:24.123456789+00:00
```

## ☁️ Cloud Providers Detected

| Provider | CNAME Patterns | Takeover Signatures |
|----------|---------------|---------------------|
| AWS S3 | s3.amazonaws.com, s3-website, .s3.amazonaws.com | NoSuchBucket, The specified bucket does not exist |
| AWS Elastic Beanstalk | elasticbeanstalk.com | NXDOMAIN - environment not found |
| GitHub Pages | github.io, githubusercontent.com | There isn't a GitHub Pages site here |
| Heroku | herokuapp.com, herokudns.com | No such app, There is no app configured at that hostname |
| Microsoft Azure Web App | azurewebsites.net, cloudapp.net | 404 Web Site not found, web app is stopped |
| Netlify | netlify.app, netlify.com | Not found - Netlify, Site not found |
| Fastly | fastly.net, fastlylb.net, edgekey.net | Fastly error: unknown domain |
| Shopify | myshopify.com | may have typed the web address incorrectly |
| GitLab Pages | gitlab.io | Project not found |
| Cloudflare Pages | pages.dev | Project not found, Deployment not found |
| Vercel | vercel.app, now.sh | Deployment not found |
| Firebase Hosting | firebaseapp.com, web.app | Site not found |
| Bitbucket Pages | bitbucket.io | Repository not found |
| Surge.sh | surge.sh | Not found - Surge |
| Pantheon | pantheonsite.io | The gods are wise |
| Acquia Cloud | acquia-sites.com | Site not found |
| Ghost(Pro) | ghost.io | doesn't exist |
| Webflow | webflow.io | doesn't exist |
| Wix | wixsite.com | This site has been removed |
| Squarespace | squarespace.com | This page doesn't exist |
| Agile CRM | agilecrm.com | Sorry, this page is no longer available |
| Airee.ru | airee.ru | Service unpaid - can be claimed |
| Anima | animaapp.io | The page you were looking for does not exist |
| Campaign Monitor | (no CNAME) | Trying to access your account? |
| Canny | (no CNAME) | Company Not Found, There is no such company |
| Cargo Collective | (no CNAME) | 404 Not Found |
| Cloudfront | (no CNAME) | ViewerCertificateException |
| Desk | (no CNAME) | Please try again or try Desk.com free for 14 days |
| Dreamhost | (no CNAME) | The requested URL was not found on this server |
| Feedpress | (no CNAME) | The feed has not been found |
| Fly.io | (no CNAME) | 404 Not Found |
| Freshdesk | (no CNAME) | We couldn't find servicedesk.victim.tld |
| GetResponse | (no CNAME) | With GetResponse Landing Pages, lead generation has never been easier |
| Ghost | ghost.io | The site you were looking for doesn't exist |
| Google Cloud Storage | (no CNAME) | The specified bucket does not exist |
| Google Sites | (no CNAME) | The requested URL was not found on this server |
| HubSpot | (no CNAME) | This page isn't available |
| Instapage | (no CNAME) | No Site For Domain |
| Key CDN | (no CNAME) | Unrecognized domain |
| Kinsta | (no CNAME) | No Site For Domain |
| Mailchimp | (no CNAME) | We can't find that page |
| Smugsmug | (no CNAME) | Whatever you were looking for doesn't currently exist |
| Statuspage | (no CNAME) | (empty - edge case) |
| Unbounce | (no CNAME) | The requested URL was not found on this server |
| UserVoice | (no CNAME) | This UserVoice subdomain is currently available! |
| WP Engine | (no CNAME) | (empty) |
| WordPress | wordpress.com | Do you want to register .*.wordpress.com? |
| Worksites | worksites.net | Hello! Sorry, but the website you're looking for doesn't exist. |
| Zendesk | (no CNAME) | Help Center Closed |

*(78 total providers - view full list with `subtake --help`)*

## 📋 Configuration

### Wordlists

- **Default**: 5000 common subdomain names (SecLists top 1M - 5000 most common)
- **Extended**: Default + permutations, regional variations, numbered variants
- **Minimal**: 60 most common for quick scans
- Use `-w /path/to/wordlist.txt` for custom wordlist (one subdomain per line)

### Rate Limiting

- `--ct-rate-limit`: Requests per second to crt.sh (default: 10)
- Concurrency controlled via `-c` (DNS) and `--http-concurrency` (HTTP)
- BBOT timeout scales with mode (fast=5x, passive=10x, active=15x base timeout)

### BBOT Requirements

```bash
# Install via pipx (recommended)
pipx install bbot

# Or via pip
pip install bbot
```

## ⚙️ Performance

- Concurrent DNS resolution (default 100)
- Concurrent HTTP checks (default 50)
- Async/await with tokio for efficient I/O
- Wildcard DNS detected and filtered during brute force and resolution
- Permutation candidates pre-filtered with a fast DNS existence check
- Single HTTP request per subdomain (shared across all provider signature checks)
- Response bodies read with a hard 100 KB cap
- Progress bars with real-time counters
- Optimized release builds with LTO (Link Time Optimization)
- Release binary at `target/release/subtake`

## 📄 License

MIT License - See LICENSE file for details.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Only scan domains you own or have explicit permission to test. Subdomain takeover detection may trigger security alerts on monitored infrastructure.
