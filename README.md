# urlaudit

**URL Security Analyzer — detect phishing, homographs, and suspicious URLs**

Analyze URLs for phishing indicators, typosquatting, homograph attacks, and security risks. Zero dependencies — Python 3.9+ stdlib only.

```
$ urlaudit "https://gooogle.com/login"

══════════════════════════════════════════
  urlaudit v1.0.0 — URL Security Analysis
══════════════════════════════════════════

  URL: https://gooogle.com/login
  Risk: MODERATE RISK (75/100)
  Findings: 1

  [HIGH] Possible typosquatting domain UA027
```

## Why

URLs are attack vectors. Developers process URLs from webhooks, user input, config files, and APIs — often without validation. Common URL-based attacks:

- **Typosquatting**: `gooogle.com`, `githuh.com`, `amaz0n.com`
- **IDN homographs**: Cyrillic `а` (U+0430) looks identical to Latin `a`
- **Credential stuffing**: `https://google.com@evil.com` (the real host is evil.com)
- **Open redirects**: `trusted.com/redirect?url=https://phishing.com`
- **Brand impersonation**: `google-security.com`, `login.google.evil.com`
- **Obfuscation**: Decimal IPs, double encoding, data URIs

No zero-dependency Python CLI existed to check all of these offline. urlaudit fills this gap.

## Installation

```bash
curl -O https://raw.githubusercontent.com/kriskimmerle/urlaudit/main/urlaudit.py
python3 urlaudit.py --help
```

## Usage

### Analyze URLs

```bash
# Single URL
urlaudit https://suspicious-site.tk/verify

# Multiple URLs
urlaudit https://example.com https://gooogle.com

# From a file (one URL per line)
urlaudit urls.txt

# From stdin (pipe from other tools)
grep -o 'https://[^ ]*' access.log | urlaudit -
cat webhook-payloads.json | urlaudit -
```

### CI/CD Integration

```bash
# Exit 1 if any HIGH+ findings
urlaudit --check https://webhook-target.com

# Custom threshold
urlaudit --check --check-threshold critical https://example.com

# JSON output for automation
urlaudit --json urls.txt
```

### Filtering

```bash
# Only critical findings
urlaudit --severity critical urls.txt

# Ignore specific rules
urlaudit --ignore UA001,UA025 urls.txt

# Detailed explanations
urlaudit -v https://suspicious.com
```

## Rules

33 detection rules across 8 categories:

### Scheme Analysis
| ID | Severity | Description |
|------|----------|-------------|
| UA001 | MEDIUM | Insecure HTTP scheme |
| UA002 | CRITICAL | JavaScript URI scheme |
| UA003 | HIGH | Data URI scheme |
| UA004 | MEDIUM | FTP scheme (unencrypted) |
| UA005 | LOW | Unusual URI scheme |

### Credential Exposure
| UA006 | CRITICAL | Credentials embedded in URL |
| UA007 | HIGH | Username in URL (phishing) |

### Host Analysis
| UA008 | HIGH | IP address instead of domain |
| UA009 | CRITICAL | Decimal/octal IP obfuscation |
| UA010 | CRITICAL | IDN homograph (impersonating known domain) |
| UA011 | HIGH | Mixed-script hostname (homograph) |
| UA012 | LOW | Non-Latin hostname |
| UA013 | MEDIUM | Punycode-encoded domain |
| UA014 | MEDIUM | Suspicious TLD (.tk, .xyz, .buzz, etc.) |
| UA015 | MEDIUM | Excessive subdomain depth |
| UA016 | MEDIUM | Excessively long hostname |
| UA017 | HIGH | Brand name in subdomain (impersonation) |

### Domain Impersonation
| UA027 | HIGH | Typosquatting (1 edit from popular domain) |
| UA028 | MEDIUM | Resembles popular site (2 edits) |
| UA029 | HIGH | Brand name embedded in domain |

### Path Analysis
| UA018 | HIGH | Path traversal (..) |
| UA019 | HIGH | Double URL encoding |
| UA020 | HIGH | Executable file download |
| UA021 | MEDIUM | Multiple phishing keywords in path |

### Query String
| UA022 | HIGH | Open redirect parameter |
| UA023 | MEDIUM | Sensitive parameter in query string |
| UA024 | LOW | Excessively long query string |

### Infrastructure
| UA025 | LOW | URL shortener detected |
| UA026 | varies | Non-standard/suspicious port |

### Unicode Tricks
| UA030 | LOW | Excessively long URL fragment |
| UA031 | HIGH | Script injection in fragment |
| UA032 | CRITICAL | Bidirectional text override |
| UA033 | HIGH | Zero-width characters |

## Risk Scoring

URLs are graded on a 0-100 scale:

| Score | Grade |
|-------|-------|
| 90-100 | SAFE / LOW RISK |
| 70-89 | MODERATE RISK |
| 40-69 | HIGH RISK |
| 0-39 | DANGEROUS |

## Smart Features

- **Typosquatting detection** using Damerau-Levenshtein distance against 35+ popular domains
- **IDN homograph detection** with 70+ confusable character mappings (Cyrillic, Greek, Fullwidth)
- **Popular domain impersonation** — recognizes when homoglyphs target known brands
- **Open redirect detection** — checks 15+ common redirect parameter names
- **Credit card-style port detection** — flags known backdoor/C2 ports (4444, 31337)
- **URL extraction** from text files, logs, and piped input
- **Bare domain handling** — auto-adds https:// for analysis

## GitHub Actions

```yaml
- name: Audit webhook URLs
  run: |
    echo "${{ secrets.WEBHOOK_URL }}" | python3 urlaudit.py --check -
```

## Use Cases

- **Webhook validation**: Check webhook endpoints before configuring them
- **Link auditing**: Scan documentation or user-submitted content for malicious links
- **Email security**: Pre-filter URLs from email bodies
- **CI/CD**: Validate URLs in configs, env vars, and deployment scripts
- **Agent safety**: Check URLs before an AI agent visits them

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)

## License

MIT
