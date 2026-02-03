#!/usr/bin/env python3
"""urlaudit - URL Security Analyzer.

Analyze URLs for phishing indicators, suspicious patterns, and security risks.
Zero dependencies - Python 3.9+ stdlib only.

Usage:
    python urlaudit.py <url>                  # Analyze a single URL
    python urlaudit.py <file>                 # Analyze URLs from a file
    echo "https://example.com" | python urlaudit.py -  # From stdin
    python urlaudit.py --check <url>          # CI mode (exit 1 on HIGH+)
    python urlaudit.py --json <url>           # JSON output
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from pathlib import Path
from typing import TextIO
from urllib.parse import urlparse, unquote, parse_qs

__version__ = "1.0.0"

# ─── Severity ────────────────────────────────────────────────────────────────

class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[1;91m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"

# ─── Finding ─────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    description: str
    severity: Severity
    detail: str
    url: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = str(self.severity)
        return d

# ─── Confusable Characters (Unicode Homoglyphs) ─────────────────────────────

# Latin -> lookalike mappings (Cyrillic, Greek, etc.)
# Maps confusable Unicode chars to the ASCII they impersonate
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    '\u0430': 'a',  # а → a
    '\u0435': 'e',  # е → e
    '\u0456': 'i',  # і → i
    '\u043e': 'o',  # о → o
    '\u0440': 'p',  # р → p
    '\u0441': 'c',  # с → c
    '\u0443': 'y',  # у → y
    '\u0445': 'x',  # х → x
    '\u043a': 'k',  # к → k
    '\u043d': 'h',  # н → h (approx)
    '\u0432': 'b',  # в → b (approx)
    '\u0433': 'r',  # г → r (approx)
    '\u0442': 't',  # т → t (approx)
    '\u043c': 'm',  # м → m
    '\u0410': 'A',  # А → A
    '\u0412': 'B',  # В → B
    '\u0421': 'C',  # С → C
    '\u0415': 'E',  # Е → E
    '\u041d': 'H',  # Н → H
    '\u041a': 'K',  # К → K
    '\u041c': 'M',  # М → M
    '\u041e': 'O',  # О → O
    '\u0420': 'P',  # Р → P
    '\u0422': 'T',  # Т → T
    '\u0425': 'X',  # Х → X
    # Greek
    '\u03b1': 'a',  # α → a
    '\u03b5': 'e',  # ε → e (approx)
    '\u03bf': 'o',  # ο → o
    '\u03c1': 'p',  # ρ → p
    '\u03ba': 'k',  # κ → k
    '\u03bd': 'v',  # ν → v
    '\u0391': 'A',  # Α → A
    '\u0392': 'B',  # Β → B
    '\u0395': 'E',  # Ε → E
    '\u0397': 'H',  # Η → H
    '\u039a': 'K',  # Κ → K
    '\u039c': 'M',  # Μ → M
    '\u039d': 'N',  # Ν → N
    '\u039f': 'O',  # Ο → O
    '\u03a1': 'P',  # Ρ → P
    '\u03a4': 'T',  # Τ → T
    '\u03a7': 'X',  # Χ → X
    '\u0396': 'Z',  # Ζ → Z
    # Fullwidth
    '\uff41': 'a', '\uff42': 'b', '\uff43': 'c', '\uff44': 'd',
    '\uff45': 'e', '\uff46': 'f', '\uff47': 'g', '\uff48': 'h',
    '\uff49': 'i', '\uff4a': 'j', '\uff4b': 'k', '\uff4c': 'l',
    '\uff4d': 'm', '\uff4e': 'n', '\uff4f': 'o', '\uff50': 'p',
    # Common substitutions
    '\u0131': 'i',  # ı (dotless i)
    '\u1d00': 'a',  # ᴀ (small cap A)
    '\u0251': 'a',  # ɑ (Latin alpha)
    '\u0261': 'g',  # ɡ (script g)
    '\u026a': 'i',  # ɪ (small cap I)
    '\u1d0f': 'o',  # ᴏ (small cap O)
}

# Well-known domains that are commonly impersonated
POPULAR_DOMAINS = {
    'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'meta.com',
    'amazon.com', 'aws.amazon.com', 'apple.com', 'icloud.com',
    'microsoft.com', 'outlook.com', 'live.com', 'office.com',
    'github.com', 'gitlab.com', 'bitbucket.org',
    'paypal.com', 'stripe.com', 'square.com',
    'netflix.com', 'spotify.com', 'twitter.com', 'x.com',
    'linkedin.com', 'instagram.com', 'whatsapp.com',
    'dropbox.com', 'slack.com', 'discord.com', 'zoom.us',
    'cloudflare.com', 'heroku.com', 'vercel.com', 'netlify.com',
    'bank.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    'coinbase.com', 'binance.com', 'kraken.com',
    'openai.com', 'anthropic.com',
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',  # Freenom (free, high abuse)
    '.buzz', '.xyz', '.top', '.icu', '.club',  # Cheap, high abuse
    '.work', '.click', '.link', '.surf',
    '.cam', '.rest', '.monster', '.cyou',
    '.cfd', '.sbs', '.hair', '.makeup',
    '.boats', '.beauty',
}

# Known URL shortener domains
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in',
    'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'v.gd',
    'rebrand.ly', 'surl.li', 'short.io', 'clck.ru',
    'trib.al', 'dlvr.it', 'snip.ly',
}

# ─── URL Analysis Rules ─────────────────────────────────────────────────────

def check_scheme(parsed, url: str) -> list[Finding]:
    """Check URL scheme for security issues."""
    findings = []
    scheme = parsed.scheme.lower()

    if scheme == 'http':
        findings.append(Finding(
            "UA001", "Insecure HTTP scheme", Severity.MEDIUM,
            "URL uses HTTP instead of HTTPS. Data transmitted in plaintext.",
            url,
        ))
    elif scheme == 'javascript':
        findings.append(Finding(
            "UA002", "JavaScript URI scheme", Severity.CRITICAL,
            "JavaScript URIs can execute arbitrary code. Common XSS vector.",
            url,
        ))
    elif scheme == 'data':
        findings.append(Finding(
            "UA003", "Data URI scheme", Severity.HIGH,
            "Data URIs can embed executable content. Used in phishing and XSS attacks.",
            url,
        ))
    elif scheme == 'ftp':
        findings.append(Finding(
            "UA004", "FTP scheme (unencrypted)", Severity.MEDIUM,
            "FTP transmits credentials and data in plaintext.",
            url,
        ))
    elif scheme not in ('https', 'mailto', 'tel', 'ssh', 'sftp', ''):
        findings.append(Finding(
            "UA005", "Unusual URI scheme", Severity.LOW,
            f"Uncommon scheme '{scheme}' may indicate a custom protocol handler attack.",
            url,
        ))

    return findings


def check_credentials_in_url(parsed, url: str) -> list[Finding]:
    """Check for embedded credentials in URL."""
    findings = []

    if parsed.username or parsed.password:
        if parsed.password:
            findings.append(Finding(
                "UA006", "Credentials embedded in URL", Severity.CRITICAL,
                f"URL contains username and password. Credentials visible in logs, "
                f"browser history, and referrer headers.",
                url,
            ))
        else:
            findings.append(Finding(
                "UA007", "Username in URL (possible phishing)", Severity.HIGH,
                f"URL contains a username component ('{parsed.username}@'). "
                f"Often used to make phishing URLs look legitimate "
                f"(e.g., https://google.com@evil.com).",
                url,
            ))

    # Check for @ in netloc without proper parsing (edge cases)
    if '@' in (parsed.netloc or '') and not parsed.username:
        findings.append(Finding(
            "UA007", "Username in URL (possible phishing)", Severity.HIGH,
            "URL contains '@' in the host portion. May trick users into "
            "thinking they're visiting a different domain.",
            url,
        ))

    return findings


def check_ip_based_url(parsed, url: str) -> list[Finding]:
    """Check if URL uses an IP address instead of a domain name."""
    findings = []
    hostname = parsed.hostname or ""

    # IPv4
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        findings.append(Finding(
            "UA008", "IP address instead of domain name", Severity.HIGH,
            f"URL uses IP address ({hostname}) instead of a domain. "
            f"Commonly used to evade domain-based blocklists.",
            url,
        ))

    # IPv6
    if hostname.startswith('[') or ':' in hostname:
        findings.append(Finding(
            "UA008", "IP address instead of domain name", Severity.HIGH,
            f"URL uses IPv6 address instead of a domain name.",
            url,
        ))

    # Decimal IP (e.g., http://2130706433 = 127.0.0.1)
    if hostname.isdigit() and len(hostname) >= 8:
        findings.append(Finding(
            "UA009", "Decimal/octal IP obfuscation", Severity.CRITICAL,
            f"URL uses decimal IP representation ({hostname}). "
            f"This is an obfuscation technique to hide the real destination.",
            url,
        ))

    # Hex IP (e.g., http://0x7f000001)
    if hostname.startswith('0x') and len(hostname) >= 8:
        findings.append(Finding(
            "UA009", "Decimal/octal IP obfuscation", Severity.CRITICAL,
            f"URL uses hexadecimal IP representation. "
            f"This is an obfuscation technique.",
            url,
        ))

    return findings


def check_homograph(parsed, url: str) -> list[Finding]:
    """Check for IDN homograph attacks."""
    findings = []
    hostname = parsed.hostname or ""

    # Check for non-ASCII characters (potential homograph)
    non_ascii = [(i, c) for i, c in enumerate(hostname) if ord(c) > 127]
    if not non_ascii:
        return findings

    # Check for mixed scripts
    scripts: set[str] = set()
    confusable_chars: list[tuple[str, str]] = []

    for char in hostname:
        if char in '.-':
            continue
        if ord(char) <= 127:
            scripts.add('LATIN')
        else:
            cat = unicodedata.category(char)
            try:
                name = unicodedata.name(char, '')
                if 'CYRILLIC' in name:
                    scripts.add('CYRILLIC')
                elif 'GREEK' in name:
                    scripts.add('GREEK')
                elif 'CJK' in name or 'HANGUL' in name:
                    scripts.add('CJK')
                elif 'ARABIC' in name:
                    scripts.add('ARABIC')
                else:
                    scripts.add('OTHER')
            except ValueError:
                scripts.add('OTHER')

            if char in CONFUSABLES:
                confusable_chars.append((char, CONFUSABLES[char]))

    # Mixed scripts = likely homograph
    if len(scripts) > 1 and 'LATIN' in scripts:
        ascii_version = ""
        for c in hostname:
            if c in CONFUSABLES:
                ascii_version += CONFUSABLES[c]
            elif ord(c) <= 127:
                ascii_version += c
            else:
                ascii_version += c

        detail = (
            f"Hostname contains mixed Unicode scripts ({', '.join(sorted(scripts))}). "
            f"This is a classic IDN homograph attack pattern."
        )

        if confusable_chars:
            substitutions = ", ".join(
                f"'{c}' (U+{ord(c):04X}) looks like '{a}'"
                for c, a in confusable_chars[:5]
            )
            detail += f" Confusable characters: {substitutions}."

        # Check if it impersonates a popular domain
        if ascii_version in POPULAR_DOMAINS or any(
            ascii_version.endswith('.' + d) for d in POPULAR_DOMAINS
        ):
            findings.append(Finding(
                "UA010", "IDN homograph attack (impersonating known domain)", Severity.CRITICAL,
                f"{detail} Appears to impersonate '{ascii_version}'.",
                url,
            ))
        else:
            findings.append(Finding(
                "UA011", "Mixed-script hostname (potential homograph)", Severity.HIGH,
                detail,
                url,
            ))

    # Pure non-Latin (might still be suspicious in Western context)
    elif 'LATIN' not in scripts and scripts - {'OTHER'}:
        findings.append(Finding(
            "UA012", "Non-Latin hostname", Severity.LOW,
            f"Hostname uses non-Latin characters ({', '.join(sorted(scripts))}). "
            f"May be legitimate internationalized domain or potential phishing.",
            url,
        ))

    return findings


def check_punycode(parsed, url: str) -> list[Finding]:
    """Check for punycode-encoded domains."""
    findings = []
    hostname = parsed.hostname or ""

    # Check for xn-- prefix (punycode)
    labels = hostname.split('.')
    punycode_labels = [l for l in labels if l.startswith('xn--')]

    if punycode_labels:
        # Decode punycode to see the real characters
        decoded_parts = []
        for label in labels:
            if label.startswith('xn--'):
                try:
                    decoded = label.encode('ascii').decode('idna')
                    decoded_parts.append(decoded)
                except (UnicodeError, UnicodeDecodeError):
                    decoded_parts.append(label)
            else:
                decoded_parts.append(label)

        decoded_hostname = '.'.join(decoded_parts)

        findings.append(Finding(
            "UA013", "Punycode-encoded domain", Severity.MEDIUM,
            f"Domain uses punycode encoding ({', '.join(punycode_labels)}). "
            f"Decoded: {decoded_hostname}. Punycode can hide homograph attacks.",
            url,
        ))

    return findings


def check_suspicious_tld(parsed, url: str) -> list[Finding]:
    """Check for suspicious top-level domains."""
    findings = []
    hostname = parsed.hostname or ""

    if not hostname:
        return findings

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            findings.append(Finding(
                "UA014", "Suspicious top-level domain", Severity.MEDIUM,
                f"Domain uses '{tld}' TLD, which has high abuse rates. "
                f"These TLDs are commonly used in phishing campaigns.",
                url,
            ))
            break

    return findings


def check_subdomain_abuse(parsed, url: str) -> list[Finding]:
    """Check for excessive subdomains or suspicious subdomain patterns."""
    findings = []
    hostname = parsed.hostname or ""
    labels = hostname.split('.')

    # Excessive subdomain depth
    if len(labels) > 5:
        findings.append(Finding(
            "UA015", "Excessive subdomain depth", Severity.MEDIUM,
            f"URL has {len(labels)} subdomain levels. "
            f"Deep subdomain nesting is often used to push the real domain "
            f"out of the visible URL bar.",
            url,
        ))

    # Very long hostname
    if len(hostname) > 100:
        findings.append(Finding(
            "UA016", "Excessively long hostname", Severity.MEDIUM,
            f"Hostname is {len(hostname)} characters long. "
            f"Long hostnames can hide the real domain in the URL bar.",
            url,
        ))

    # Brand name in subdomain (subdomain impersonation)
    if len(labels) >= 3:
        subdomain_part = '.'.join(labels[:-2])
        for brand in ('google', 'apple', 'microsoft', 'amazon', 'paypal',
                       'facebook', 'netflix', 'bank', 'secure', 'login',
                       'account', 'verify', 'update', 'confirm', 'signin',
                       'support', 'help', 'service', 'billing'):
            if brand in subdomain_part.lower() and brand not in labels[-2].lower():
                findings.append(Finding(
                    "UA017", "Brand name in subdomain (impersonation)", Severity.HIGH,
                    f"Subdomain contains '{brand}' but the actual domain is "
                    f"'{'.'.join(labels[-2:])}'. This is a common phishing technique.",
                    url,
                ))
                break

    return findings


def check_path_patterns(parsed, url: str) -> list[Finding]:
    """Check URL path for suspicious patterns."""
    findings = []
    path = parsed.path or ""
    decoded_path = unquote(path)

    # Path traversal
    if '..' in decoded_path:
        findings.append(Finding(
            "UA018", "Path traversal pattern", Severity.HIGH,
            "URL path contains '..' (parent directory traversal). "
            "May indicate a path traversal or directory escape attempt.",
            url,
        ))

    # Double encoding
    if '%25' in path:  # encoded %
        findings.append(Finding(
            "UA019", "Double URL encoding detected", Severity.HIGH,
            "URL contains double-encoded characters (%25). "
            "This is an evasion technique to bypass URL filters.",
            url,
        ))

    # Suspicious file extensions
    suspicious_exts = ('.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs',
                       '.msi', '.jar', '.hta', '.wsf', '.cpl')
    for ext in suspicious_exts:
        if decoded_path.lower().endswith(ext):
            findings.append(Finding(
                "UA020", "Executable file download", Severity.HIGH,
                f"URL points to an executable file ({ext}). "
                f"Direct executable downloads are a common malware vector.",
                url,
            ))
            break

    # Phishing path keywords
    phishing_paths = ('login', 'signin', 'verify', 'account', 'secure',
                      'update', 'confirm', 'banking', 'password', 'credential',
                      'authenticate', 'validation', 'recovery', 'unlock',
                      'suspended', 'limited', 'restore', 'reactivate')
    path_lower = decoded_path.lower()
    matched_keywords = [kw for kw in phishing_paths if kw in path_lower]

    if len(matched_keywords) >= 2:
        findings.append(Finding(
            "UA021", "Multiple phishing keywords in path", Severity.MEDIUM,
            f"URL path contains multiple phishing-associated keywords: "
            f"{', '.join(matched_keywords[:5])}.",
            url,
        ))

    return findings


def check_query_params(parsed, url: str) -> list[Finding]:
    """Check query parameters for suspicious patterns."""
    findings = []
    query = parsed.query or ""

    if not query:
        return findings

    # Redirect parameter (open redirect)
    redirect_params = ('redirect', 'url', 'next', 'return', 'returnurl',
                       'return_to', 'redirect_uri', 'callback', 'dest',
                       'destination', 'redir', 'continue', 'target',
                       'goto', 'link', 'forward')

    try:
        params = parse_qs(query, keep_blank_values=True)
    except ValueError:
        params = {}

    for param_name in params:
        param_lower = param_name.lower()

        # Open redirect
        if param_lower in redirect_params:
            values = params[param_name]
            for val in values:
                if val.startswith(('http://', 'https://', '//')):
                    findings.append(Finding(
                        "UA022", "Open redirect parameter", Severity.HIGH,
                        f"Query parameter '{param_name}' contains a URL redirect. "
                        f"Open redirects are used to chain phishing attacks through "
                        f"trusted domains.",
                        url,
                    ))
                    break

        # Token/credential in query string
        if param_lower in ('token', 'api_key', 'apikey', 'key', 'secret',
                           'password', 'passwd', 'auth', 'access_token',
                           'session', 'sessionid', 'sid'):
            findings.append(Finding(
                "UA023", "Sensitive parameter in query string", Severity.MEDIUM,
                f"Query parameter '{param_name}' may contain sensitive data. "
                f"Query strings are logged by web servers and visible in browser history.",
                url,
            ))

    # Very long query string (possible data exfiltration)
    if len(query) > 2000:
        findings.append(Finding(
            "UA024", "Excessively long query string", Severity.LOW,
            f"Query string is {len(query)} characters. Very long query strings "
            f"may indicate data exfiltration or injection attempts.",
            url,
        ))

    return findings


def check_url_shortener(parsed, url: str) -> list[Finding]:
    """Check if URL is from a known shortener service."""
    findings = []
    hostname = parsed.hostname or ""

    if hostname.lower() in SHORTENER_DOMAINS:
        findings.append(Finding(
            "UA025", "URL shortener detected", Severity.LOW,
            f"URL uses shortener service ({hostname}). "
            f"Shortened URLs hide the final destination and can mask "
            f"phishing or malware links.",
            url,
        ))

    return findings


def check_port(parsed, url: str) -> list[Finding]:
    """Check for suspicious port numbers."""
    findings = []
    port = parsed.port

    if port is None:
        return findings

    normal_ports = {80, 443, 8080, 8443}
    if port not in normal_ports:
        severity = Severity.LOW
        detail = f"URL uses non-standard port {port}."

        if port in (1080, 3128, 8888, 9050):
            severity = Severity.MEDIUM
            detail += " This is a common proxy port."
        elif port in (4444, 5555, 6666, 7777, 31337):
            severity = Severity.HIGH
            detail += " This port is commonly associated with backdoors/C2."
        elif port > 49152:
            severity = Severity.MEDIUM
            detail += " Ephemeral port range, unusual for web services."

        findings.append(Finding(
            "UA026", "Non-standard port", severity,
            detail,
            url,
        ))

    return findings


def check_typosquat(parsed, url: str) -> list[Finding]:
    """Check if domain looks like a typosquat of a popular domain."""
    findings = []
    hostname = parsed.hostname or ""

    if not hostname:
        return findings

    # Extract registrable domain (last two labels for .com etc, three for .co.uk etc)
    labels = hostname.split('.')
    if len(labels) < 2:
        return findings

    domain = labels[-2] + '.' + labels[-1]

    # Skip if it IS a popular domain
    if domain in POPULAR_DOMAINS:
        return findings

    # Check Damerau-Levenshtein distance to popular domains
    for popular in POPULAR_DOMAINS:
        pop_name = popular.split('.')[0]
        dom_name = labels[-2]

        if len(pop_name) < 4 or len(dom_name) < 4:
            continue

        dist = _damerau_levenshtein(dom_name, pop_name)

        if dist == 1 and len(dom_name) >= 4:
            findings.append(Finding(
                "UA027", "Possible typosquatting domain", Severity.HIGH,
                f"Domain '{domain}' is 1 edit away from '{popular}'. "
                f"This may be a typosquatting attack.",
                url,
            ))
            break
        elif dist == 2 and len(dom_name) >= 6:
            findings.append(Finding(
                "UA028", "Domain resembles popular site", Severity.MEDIUM,
                f"Domain '{domain}' is 2 edits from '{popular}'. "
                f"Possible typosquatting or brand impersonation.",
                url,
            ))
            break

    # Check for brand + hyphen patterns (e.g., google-login.com)
    dom_name = labels[-2].lower()
    for brand in ('google', 'apple', 'microsoft', 'amazon', 'paypal',
                   'facebook', 'netflix', 'github', 'openai'):
        if brand in dom_name and dom_name != brand:
            # Brand name embedded but not the whole domain
            findings.append(Finding(
                "UA029", "Brand name embedded in domain", Severity.HIGH,
                f"Domain contains brand name '{brand}' but is not the official domain. "
                f"Common phishing pattern: '{hostname}'.",
                url,
            ))
            break

    return findings


def check_fragment_abuse(parsed, url: str) -> list[Finding]:
    """Check URL fragment for suspicious content."""
    findings = []
    fragment = parsed.fragment or ""

    if not fragment:
        return findings

    # Very long fragment (possible data exfiltration via fragment)
    if len(fragment) > 500:
        findings.append(Finding(
            "UA030", "Excessively long URL fragment", Severity.LOW,
            f"URL fragment is {len(fragment)} characters. "
            f"Long fragments can be used for client-side data transfer or tracking.",
            url,
        ))

    # JavaScript in fragment
    if re.search(r'(?i)(javascript|<script|onerror|onload)', fragment):
        findings.append(Finding(
            "UA031", "Script injection in URL fragment", Severity.HIGH,
            "URL fragment contains script-like content. "
            "This may be a DOM-based XSS attack vector.",
            url,
        ))

    return findings


def check_unicode_tricks(url: str) -> list[Finding]:
    """Check for Unicode tricks in the full URL."""
    findings = []

    # Right-to-left override
    if '\u200e' in url or '\u200f' in url or '\u202a' in url or \
       '\u202b' in url or '\u202c' in url or '\u202d' in url or '\u202e' in url:
        findings.append(Finding(
            "UA032", "Bidirectional text override in URL", Severity.CRITICAL,
            "URL contains Unicode bidirectional override characters. "
            "These can make a URL appear to point to a different domain.",
            url,
        ))

    # Zero-width characters
    if '\u200b' in url or '\u200c' in url or '\u200d' in url or '\ufeff' in url:
        findings.append(Finding(
            "UA033", "Zero-width characters in URL", Severity.HIGH,
            "URL contains invisible zero-width Unicode characters. "
            "These can be used to create visually identical but different URLs.",
            url,
        ))

    return findings


# ─── Damerau-Levenshtein Distance ───────────────────────────────────────────

def _damerau_levenshtein(s1: str, s2: str) -> int:
    """Calculate Damerau-Levenshtein distance between two strings."""
    len_s1 = len(s1)
    len_s2 = len(s2)

    # Quick exit for very different lengths
    if abs(len_s1 - len_s2) > 3:
        return abs(len_s1 - len_s2)

    d = [[0] * (len_s2 + 1) for _ in range(len_s1 + 1)]

    for i in range(len_s1 + 1):
        d[i][0] = i
    for j in range(len_s2 + 1):
        d[0][j] = j

    for i in range(1, len_s1 + 1):
        for j in range(1, len_s2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,      # deletion
                d[i][j - 1] + 1,      # insertion
                d[i - 1][j - 1] + cost  # substitution
            )
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)  # transposition

    return d[len_s1][len_s2]


# ─── URL Grading ─────────────────────────────────────────────────────────────

def grade_url(findings: list[Finding]) -> tuple[str, int]:
    """Grade a URL's safety based on findings."""
    if not findings:
        return "SAFE", 100

    # Deduct points by severity
    deductions = {
        Severity.CRITICAL: 50,
        Severity.HIGH: 25,
        Severity.MEDIUM: 10,
        Severity.LOW: 3,
        Severity.INFO: 0,
    }

    score = 100
    for f in findings:
        score -= deductions.get(f.severity, 0)

    score = max(0, score)

    if score >= 90:
        grade = "LOW RISK"
    elif score >= 70:
        grade = "MODERATE RISK"
    elif score >= 40:
        grade = "HIGH RISK"
    else:
        grade = "DANGEROUS"

    return grade, score


# ─── Scanner ─────────────────────────────────────────────────────────────────

def analyze_url(url: str, ignore_rules: set[str] | None = None,
                min_severity: Severity = Severity.LOW) -> list[Finding]:
    """Run all checks on a URL."""
    url = url.strip()
    if not url:
        return []

    findings: list[Finding] = []

    # Parse URL
    try:
        parsed = urlparse(url)
    except ValueError:
        findings.append(Finding(
            "UA000", "Malformed URL", Severity.HIGH,
            "URL could not be parsed. Malformed URLs can crash parsers "
            "or be processed inconsistently.",
            url,
        ))
        return findings

    # Run all checks
    checks = [
        check_scheme,
        check_credentials_in_url,
        check_ip_based_url,
        check_homograph,
        check_punycode,
        check_suspicious_tld,
        check_subdomain_abuse,
        check_path_patterns,
        check_query_params,
        check_url_shortener,
        check_port,
        check_typosquat,
        check_fragment_abuse,
    ]

    for check_fn in checks:
        findings.extend(check_fn(parsed, url))

    # Unicode checks on raw URL
    findings.extend(check_unicode_tricks(url))

    # Filter
    if ignore_rules:
        findings = [f for f in findings if f.rule_id not in ignore_rules]
    findings = [f for f in findings if f.severity >= min_severity]

    return findings


def extract_urls(text: str) -> list[str]:
    """Extract URLs from text."""
    # Match common URL patterns
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+|'  # http(s) URLs
        r'ftp://[^\s<>"\')\]]+|'     # ftp URLs
        r'data:[^\s<>"\')\]]+|'       # data URIs
        r'javascript:[^\s<>"\')\]]*'  # javascript URIs
    )
    urls = url_pattern.findall(text)
    # Also accept bare lines that look like URLs
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '.' in line and ' ' not in line:
            if not any(line == u for u in urls):
                if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', line):
                    urls.append(line)
                elif re.match(r'^[a-zA-Z0-9].*\.[a-zA-Z]{2,}', line):
                    # Bare domain — add https:// prefix for analysis
                    urls.append(f'https://{line}')
    return urls


# ─── Output Formatters ───────────────────────────────────────────────────────

RISK_COLORS = {
    "SAFE": GREEN,
    "LOW RISK": GREEN,
    "MODERATE RISK": "\033[93m",
    "HIGH RISK": "\033[91m",
    "DANGEROUS": "\033[1;91m",
}


def print_text_report(url: str, findings: list[Finding],
                      use_color: bool = True, verbose: bool = False) -> None:
    """Print analysis for a single URL."""
    grade, score = grade_url(findings)
    grade_color = RISK_COLORS.get(grade, RESET)

    if use_color:
        print(f"\n  {BOLD}URL:{RESET} {url}")
        print(f"  {BOLD}Risk:{RESET} {grade_color}{grade} ({score}/100){RESET}")
    else:
        print(f"\n  URL: {url}")
        print(f"  Risk: {grade} ({score}/100)")

    if not findings:
        if use_color:
            print(f"  {GREEN}✓ No security issues detected{RESET}\n")
        else:
            print(f"  [OK] No security issues detected\n")
        return

    print(f"  Findings: {len(findings)}")
    print()

    for finding in findings:
        sev = f"{SEVERITY_COLORS[finding.severity]}[{finding.severity.name}]{RESET}" if use_color else f"[{finding.severity.name}]"
        rule_tag = f"{DIM}{finding.rule_id}{RESET}" if use_color else finding.rule_id

        print(f"  {sev} {finding.description} {rule_tag}")
        if verbose:
            # Wrap detail text
            detail = finding.detail
            indent = "    "
            words = detail.split()
            line = indent
            for word in words:
                if len(line) + len(word) + 1 > 80:
                    print(line)
                    line = indent + word
                else:
                    line += (" " if line != indent else "") + word
            if line.strip():
                print(line)
        print()


def print_batch_summary(all_results: list[tuple[str, list[Finding]]],
                        use_color: bool = True) -> None:
    """Print summary for batch URL analysis."""
    total_urls = len(all_results)
    safe = sum(1 for _, f in all_results if not f)
    dangerous = sum(1 for _, f in all_results if grade_url(f)[0] == "DANGEROUS")
    high_risk = sum(1 for _, f in all_results if grade_url(f)[0] == "HIGH RISK")
    moderate = sum(1 for _, f in all_results if grade_url(f)[0] == "MODERATE RISK")
    total_findings = sum(len(f) for _, f in all_results)

    if use_color:
        print(f"\n{BOLD}══════════════════════════════════════════{RESET}")
        print(f"{BOLD}  urlaudit v{__version__} — Batch Summary{RESET}")
        print(f"{BOLD}══════════════════════════════════════════{RESET}\n")
    else:
        print(f"\n{'=' * 42}")
        print(f"  urlaudit v{__version__} — Batch Summary")
        print(f"{'=' * 42}\n")

    print(f"  URLs analyzed: {total_urls}")
    print(f"  Total findings: {total_findings}")
    print(f"  Safe: {safe}  |  Moderate: {moderate}  |  High Risk: {high_risk}  |  Dangerous: {dangerous}")
    print()


def print_json_report(all_results: list[tuple[str, list[Finding]]]) -> None:
    """Print all results as JSON."""
    report = {
        "version": __version__,
        "total_urls": len(all_results),
        "results": [],
    }

    for url, findings in all_results:
        grade, score = grade_url(findings)
        report["results"].append({
            "url": url,
            "risk": grade,
            "score": score,
            "findings": [f.to_dict() for f in findings],
        })

    # Summary
    report["summary"] = {
        "safe": sum(1 for _, f in all_results if not f),
        "total_findings": sum(len(f) for _, f in all_results),
        "by_severity": {
            "critical": sum(1 for _, fl in all_results for f in fl if f.severity == Severity.CRITICAL),
            "high": sum(1 for _, fl in all_results for f in fl if f.severity == Severity.HIGH),
            "medium": sum(1 for _, fl in all_results for f in fl if f.severity == Severity.MEDIUM),
            "low": sum(1 for _, fl in all_results for f in fl if f.severity == Severity.LOW),
        },
    }

    print(json.dumps(report, indent=2))


# ─── CLI ─────────────────────────────────────────────────────────────────────

def list_rules() -> None:
    """Print all rule IDs and descriptions."""
    rules = [
        ("UA001", "MEDIUM", "Insecure HTTP scheme"),
        ("UA002", "CRITICAL", "JavaScript URI scheme"),
        ("UA003", "HIGH", "Data URI scheme"),
        ("UA004", "MEDIUM", "FTP scheme (unencrypted)"),
        ("UA005", "LOW", "Unusual URI scheme"),
        ("UA006", "CRITICAL", "Credentials embedded in URL"),
        ("UA007", "HIGH", "Username in URL (phishing)"),
        ("UA008", "HIGH", "IP address instead of domain"),
        ("UA009", "CRITICAL", "Decimal/octal IP obfuscation"),
        ("UA010", "CRITICAL", "IDN homograph (impersonating known domain)"),
        ("UA011", "HIGH", "Mixed-script hostname (homograph)"),
        ("UA012", "LOW", "Non-Latin hostname"),
        ("UA013", "MEDIUM", "Punycode-encoded domain"),
        ("UA014", "MEDIUM", "Suspicious top-level domain"),
        ("UA015", "MEDIUM", "Excessive subdomain depth"),
        ("UA016", "MEDIUM", "Excessively long hostname"),
        ("UA017", "HIGH", "Brand name in subdomain (impersonation)"),
        ("UA018", "HIGH", "Path traversal pattern"),
        ("UA019", "HIGH", "Double URL encoding"),
        ("UA020", "HIGH", "Executable file download"),
        ("UA021", "MEDIUM", "Multiple phishing keywords in path"),
        ("UA022", "HIGH", "Open redirect parameter"),
        ("UA023", "MEDIUM", "Sensitive parameter in query string"),
        ("UA024", "LOW", "Excessively long query string"),
        ("UA025", "LOW", "URL shortener detected"),
        ("UA026", "varies", "Non-standard port"),
        ("UA027", "HIGH", "Possible typosquatting domain"),
        ("UA028", "MEDIUM", "Domain resembles popular site"),
        ("UA029", "HIGH", "Brand name embedded in domain"),
        ("UA030", "LOW", "Excessively long URL fragment"),
        ("UA031", "HIGH", "Script injection in URL fragment"),
        ("UA032", "CRITICAL", "Bidirectional text override"),
        ("UA033", "HIGH", "Zero-width characters in URL"),
    ]

    print(f"\nurlaudit v{__version__} — Available Rules\n")
    print(f"  {'ID':<8} {'Severity':<10} {'Description'}")
    print(f"  {'─'*8} {'─'*10} {'─'*50}")
    for rule_id, sev, desc in rules:
        print(f"  {rule_id:<8} {sev:<10} {desc}")
    print(f"\n  Total: {len(rules)} rules\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="urlaudit",
        description="URL Security Analyzer — detect phishing, homographs, and suspicious URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  urlaudit https://example.com                Analyze a single URL
  urlaudit urls.txt                           Analyze URLs from a file
  echo "https://evil.com" | urlaudit -        From stdin
  urlaudit --json https://example.com         JSON output
  urlaudit --check https://phishing.xyz       CI mode (exit 1 on HIGH+)
  urlaudit --verbose https://example.com      Show detailed explanations
  urlaudit --list-rules                       List all detection rules""",
    )

    parser.add_argument("targets", nargs="*", default=[],
                        help="URLs, files containing URLs, or - for stdin")
    parser.add_argument("--version", action="version", version=f"urlaudit {__version__}")

    # Output
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed explanations for findings")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")

    # Filtering
    parser.add_argument("--severity", type=str, default="low",
                        choices=["info", "low", "medium", "high", "critical"],
                        help="Minimum severity to report (default: low)")
    parser.add_argument("--ignore", type=str, default="",
                        help="Comma-separated rule IDs to ignore")

    # CI mode
    parser.add_argument("--check", action="store_true",
                        help="CI mode: exit 1 if any HIGH+ findings")
    parser.add_argument("--check-threshold", type=str, default="high",
                        choices=["info", "low", "medium", "high", "critical"],
                        help="Severity threshold for CI exit code (default: high)")

    # Info
    parser.add_argument("--list-rules", action="store_true",
                        help="List all detection rules")

    args = parser.parse_args()

    if args.list_rules:
        list_rules()
        return 0

    if not args.targets and sys.stdin.isatty():
        parser.print_help()
        return 0

    if not args.targets:
        args.targets = ["-"]

    # Parse options
    severity_map = {
        "info": Severity.INFO, "low": Severity.LOW,
        "medium": Severity.MEDIUM, "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    min_severity = severity_map[args.severity]
    check_threshold = severity_map[args.check_threshold]
    ignore_rules = {r.strip() for r in args.ignore.split(",") if r.strip()}
    use_color = not args.no_color and sys.stdout.isatty() and not args.json

    # Collect URLs
    urls: list[str] = []

    for target in args.targets:
        if target == "-":
            text = sys.stdin.read()
            urls.extend(extract_urls(text))
        elif os.path.isfile(target):
            with open(target, 'r', encoding='utf-8', errors='replace') as f:
                text = f.read()
                urls.extend(extract_urls(text))
        else:
            # Treat as a URL directly
            urls.append(target)

    if not urls:
        print("No URLs to analyze.", file=sys.stderr)
        return 0

    # Analyze
    all_results: list[tuple[str, list[Finding]]] = []

    for url in urls:
        findings = analyze_url(url, ignore_rules=ignore_rules,
                              min_severity=min_severity)
        all_results.append((url, findings))

    # Output
    if args.json:
        print_json_report(all_results)
    else:
        if use_color:
            print(f"\n{BOLD}══════════════════════════════════════════{RESET}")
            print(f"{BOLD}  urlaudit v{__version__} — URL Security Analysis{RESET}")
            print(f"{BOLD}══════════════════════════════════════════{RESET}")
        else:
            print(f"\n{'=' * 42}")
            print(f"  urlaudit v{__version__} — URL Security Analysis")
            print(f"{'=' * 42}")

        for url, findings in all_results:
            print_text_report(url, findings, use_color=use_color,
                            verbose=args.verbose)

        if len(all_results) > 1:
            print_batch_summary(all_results, use_color=use_color)

    # CI mode
    if args.check:
        for _, findings in all_results:
            for f in findings:
                if f.severity >= check_threshold:
                    return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
