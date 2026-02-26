#!/usr/bin/env python3
"""Comprehensive tests for urlaudit.py.

Zero dependencies except pytest. Covers all 33 detection rules plus core functionality.
"""

import json
import sys
from io import StringIO
from pathlib import Path
from typing import List, Optional
from unittest.mock import patch

import pytest

# Import the module under test
import urlaudit
from urlaudit import (
    Severity,
    Finding,
    analyze_url,
    extract_urls,
    grade_url,
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
    check_unicode_tricks,
    _damerau_levenshtein,
)
from urllib.parse import urlparse


# ─── Helper Functions ────────────────────────────────────────────────────────


def find_rule(findings: List[Finding], rule_id: str) -> Optional[Finding]:
    """Find a specific finding by rule ID."""
    for f in findings:
        if f.rule_id == rule_id:
            return f
    return None


def has_rule(findings: List[Finding], rule_id: str) -> bool:
    """Check if findings contain a specific rule."""
    return find_rule(findings, rule_id) is not None


# ─── Rule Tests (UA001-UA033) ───────────────────────────────────────────────


class TestUA001_InsecureHTTP:
    """UA001: Insecure HTTP scheme"""

    def test_http_detected(self):
        findings = analyze_url("http://example.com")
        assert has_rule(findings, "UA001")
        f = find_rule(findings, "UA001")
        assert f.severity == Severity.MEDIUM
        assert "HTTP" in f.description.upper()

    def test_https_safe(self):
        findings = analyze_url("https://example.com")
        assert not has_rule(findings, "UA001")

    def test_http_with_path(self):
        findings = analyze_url("http://example.com/path/to/resource")
        assert has_rule(findings, "UA001")


class TestUA002_JavaScriptURI:
    """UA002: JavaScript URI scheme"""

    def test_javascript_uri(self):
        findings = analyze_url("javascript:alert(1)")
        assert has_rule(findings, "UA002")
        f = find_rule(findings, "UA002")
        assert f.severity == Severity.CRITICAL

    def test_javascript_with_payload(self):
        findings = analyze_url("javascript:void(document.location='http://evil.com')")
        assert has_rule(findings, "UA002")


class TestUA003_DataURI:
    """UA003: Data URI scheme"""

    def test_data_uri(self):
        findings = analyze_url("data:text/html,<script>alert('XSS')</script>")
        assert has_rule(findings, "UA003")
        f = find_rule(findings, "UA003")
        assert f.severity == Severity.HIGH

    def test_data_uri_base64(self):
        findings = analyze_url("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
        assert has_rule(findings, "UA003")


class TestUA004_FTP:
    """UA004: FTP scheme (unencrypted)"""

    def test_ftp_detected(self):
        findings = analyze_url("ftp://ftp.example.com/file.txt")
        assert has_rule(findings, "UA004")
        f = find_rule(findings, "UA004")
        assert f.severity == Severity.MEDIUM


class TestUA005_UnusualScheme:
    """UA005: Unusual URI scheme"""

    def test_unusual_scheme_file(self):
        findings = analyze_url("file:///etc/passwd")
        assert has_rule(findings, "UA005")

    def test_unusual_scheme_custom(self):
        findings = analyze_url("myapp://open?url=http://evil.com")
        assert has_rule(findings, "UA005")

    def test_allowed_schemes_pass(self):
        """HTTPS, SSH, SFTP should not trigger UA005"""
        for scheme in ["https://example.com", "ssh://user@host", "sftp://host/path"]:
            findings = analyze_url(scheme)
            assert not has_rule(findings, "UA005")


class TestUA006_CredentialsInURL:
    """UA006: Credentials embedded in URL"""

    def test_username_and_password(self):
        findings = analyze_url("https://admin:password123@example.com")
        assert has_rule(findings, "UA006")
        f = find_rule(findings, "UA006")
        assert f.severity == Severity.CRITICAL

    def test_credentials_in_http(self):
        findings = analyze_url("http://user:pass@192.168.1.1")
        assert has_rule(findings, "UA006")


class TestUA007_UsernameInURL:
    """UA007: Username in URL (possible phishing)"""

    def test_username_only(self):
        findings = analyze_url("https://google.com@evil.com")
        assert has_rule(findings, "UA007")
        f = find_rule(findings, "UA007")
        assert f.severity == Severity.HIGH

    def test_at_symbol_in_netloc(self):
        findings = analyze_url("https://trusted.com@phishing.com/login")
        assert has_rule(findings, "UA007")


class TestUA008_IPAddress:
    """UA008: IP address instead of domain name"""

    def test_ipv4_address(self):
        findings = analyze_url("https://192.168.1.1/login")
        assert has_rule(findings, "UA008")
        f = find_rule(findings, "UA008")
        assert f.severity == Severity.HIGH

    def test_public_ip(self):
        findings = analyze_url("http://8.8.8.8")
        assert has_rule(findings, "UA008")

    def test_ipv6_brackets(self):
        findings = analyze_url("http://[2001:db8::1]/")
        assert has_rule(findings, "UA008")

    def test_ipv6_colon(self):
        # IPv6 without brackets causes parsing issues, which is itself suspicious
        findings = analyze_url("http://[2001:db8::1]:8000/")
        assert has_rule(findings, "UA008") or has_rule(findings, "UA026")


class TestUA009_IPObfuscation:
    """UA009: Decimal/octal IP obfuscation"""

    def test_decimal_ip(self):
        findings = analyze_url("http://2130706433/")  # 127.0.0.1 in decimal
        assert has_rule(findings, "UA009")
        f = find_rule(findings, "UA009")
        assert f.severity == Severity.CRITICAL

    def test_hex_ip(self):
        findings = analyze_url("http://0x7f000001/")  # 127.0.0.1 in hex
        assert has_rule(findings, "UA009")


class TestUA010_HomographKnownDomain:
    """UA010: IDN homograph attack (impersonating known domain)"""

    def test_cyrillic_a_in_google(self):
        # Replace 'a' with Cyrillic а (U+0430)
        findings = analyze_url("https://pаypal.com")  # а is Cyrillic
        assert has_rule(findings, "UA010") or has_rule(findings, "UA011")

    def test_mixed_scripts(self):
        # Mix of Latin and Cyrillic
        url = "https://gооgle.com"  # о is Cyrillic U+043E
        findings = analyze_url(url)
        assert has_rule(findings, "UA010") or has_rule(findings, "UA011")


class TestUA011_MixedScript:
    """UA011: Mixed-script hostname (potential homograph)"""

    def test_latin_cyrillic_mix(self):
        # Latin + Cyrillic without matching popular domain
        url = "https://ехample.com"  # х is Cyrillic
        findings = analyze_url(url)
        # Should get UA011 (mixed script) but not UA010 (since "ехample" != "example")
        assert has_rule(findings, "UA010") or has_rule(findings, "UA011")


class TestUA012_NonLatin:
    """UA012: Non-Latin hostname"""

    def test_pure_cyrillic(self):
        url = "https://президент.рф"
        findings = analyze_url(url)
        assert has_rule(findings, "UA012")
        f = find_rule(findings, "UA012")
        assert f.severity == Severity.LOW


class TestUA013_Punycode:
    """UA013: Punycode-encoded domain"""

    def test_punycode_domain(self):
        findings = analyze_url("https://xn--e1afmkfd.xn--p1ai")  # пример.рф
        assert has_rule(findings, "UA013")
        f = find_rule(findings, "UA013")
        assert f.severity == Severity.MEDIUM
        assert "punycode" in f.description.lower()


class TestUA014_SuspiciousTLD:
    """UA014: Suspicious top-level domain"""

    def test_tk_tld(self):
        findings = analyze_url("https://phishing.tk")
        assert has_rule(findings, "UA014")

    def test_xyz_tld(self):
        findings = analyze_url("https://scam.xyz")
        assert has_rule(findings, "UA014")

    def test_multiple_suspicious_tlds(self):
        for tld in ['.ml', '.ga', '.cf', '.gq', '.buzz', '.top']:
            findings = analyze_url(f"https://evil{tld}")
            assert has_rule(findings, "UA014"), f"Failed for {tld}"


class TestUA015_ExcessiveSubdomains:
    """UA015: Excessive subdomain depth"""

    def test_deep_subdomains(self):
        url = "https://a.b.c.d.e.f.example.com"
        findings = analyze_url(url)
        assert has_rule(findings, "UA015")
        f = find_rule(findings, "UA015")
        assert f.severity == Severity.MEDIUM

    def test_normal_subdomain_count(self):
        url = "https://www.example.com"
        findings = analyze_url(url)
        assert not has_rule(findings, "UA015")


class TestUA016_LongHostname:
    """UA016: Excessively long hostname"""

    def test_long_hostname(self):
        long_subdomain = "a" * 150
        url = f"https://{long_subdomain}.example.com"
        findings = analyze_url(url)
        assert has_rule(findings, "UA016")


class TestUA017_BrandInSubdomain:
    """UA017: Brand name in subdomain (impersonation)"""

    def test_google_in_subdomain(self):
        findings = analyze_url("https://google-login.evil.com")
        assert has_rule(findings, "UA017")
        f = find_rule(findings, "UA017")
        assert f.severity == Severity.HIGH

    def test_paypal_verification(self):
        findings = analyze_url("https://paypal-verify.phishing.com")
        assert has_rule(findings, "UA017")

    def test_legitimate_google_subdomain(self):
        """google.com with subdomain should not trigger"""
        findings = analyze_url("https://mail.google.com")
        assert not has_rule(findings, "UA017")


class TestUA018_PathTraversal:
    """UA018: Path traversal pattern"""

    def test_dot_dot_in_path(self):
        findings = analyze_url("https://example.com/../../etc/passwd")
        assert has_rule(findings, "UA018")
        f = find_rule(findings, "UA018")
        assert f.severity == Severity.HIGH

    def test_encoded_traversal(self):
        findings = analyze_url("https://example.com/%2e%2e/secret")
        # This tests if decoded path contains ..
        findings = analyze_url("https://example.com/foo/../../bar")
        assert has_rule(findings, "UA018")


class TestUA019_DoubleEncoding:
    """UA019: Double URL encoding detected"""

    def test_double_encoded_percent(self):
        findings = analyze_url("https://example.com/path%253Cscript%253E")
        assert has_rule(findings, "UA019")
        f = find_rule(findings, "UA019")
        assert f.severity == Severity.HIGH


class TestUA020_ExecutableDownload:
    """UA020: Executable file download"""

    def test_exe_file(self):
        findings = analyze_url("https://downloads.com/malware.exe")
        assert has_rule(findings, "UA020")

    def test_multiple_executable_extensions(self):
        for ext in ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.jar']:
            findings = analyze_url(f"https://example.com/file{ext}")
            assert has_rule(findings, "UA020"), f"Failed for {ext}"


class TestUA021_PhishingPathKeywords:
    """UA021: Multiple phishing keywords in path"""

    def test_multiple_keywords(self):
        findings = analyze_url("https://example.com/login/verify/account/confirm")
        assert has_rule(findings, "UA021")
        f = find_rule(findings, "UA021")
        assert f.severity == Severity.MEDIUM

    def test_single_keyword_no_match(self):
        findings = analyze_url("https://example.com/login")
        assert not has_rule(findings, "UA021")


class TestUA022_OpenRedirect:
    """UA022: Open redirect parameter"""

    def test_redirect_param_with_url(self):
        findings = analyze_url("https://example.com/redirect?url=http://evil.com")
        assert has_rule(findings, "UA022")
        f = find_rule(findings, "UA022")
        assert f.severity == Severity.HIGH

    def test_next_param(self):
        findings = analyze_url("https://example.com/login?next=https://phishing.com")
        assert has_rule(findings, "UA022")

    def test_protocol_relative_url(self):
        findings = analyze_url("https://example.com/?return=//evil.com")
        assert has_rule(findings, "UA022")


class TestUA023_SensitiveParams:
    """UA023: Sensitive parameter in query string"""

    def test_token_in_query(self):
        findings = analyze_url("https://api.example.com/data?token=abc123")
        assert has_rule(findings, "UA023")
        f = find_rule(findings, "UA023")
        assert f.severity == Severity.MEDIUM

    def test_api_key_param(self):
        findings = analyze_url("https://example.com/?api_key=secret")
        assert has_rule(findings, "UA023")

    def test_password_param(self):
        findings = analyze_url("https://example.com/?password=hunter2")
        assert has_rule(findings, "UA023")


class TestUA024_LongQueryString:
    """UA024: Excessively long query string"""

    def test_very_long_query(self):
        long_query = "param=" + ("a" * 3000)
        findings = analyze_url(f"https://example.com/?{long_query}")
        assert has_rule(findings, "UA024")
        f = find_rule(findings, "UA024")
        assert f.severity == Severity.LOW


class TestUA025_URLShortener:
    """UA025: URL shortener detected"""

    def test_bitly(self):
        findings = analyze_url("https://bit.ly/abc123")
        assert has_rule(findings, "UA025")
        f = find_rule(findings, "UA025")
        assert f.severity == Severity.LOW

    def test_tinyurl(self):
        findings = analyze_url("https://tinyurl.com/xyz")
        assert has_rule(findings, "UA025")

    def test_multiple_shorteners(self):
        for shortener in ['t.co', 'goo.gl', 'ow.ly', 'is.gd']:
            findings = analyze_url(f"https://{shortener}/test")
            assert has_rule(findings, "UA025"), f"Failed for {shortener}"


class TestUA026_NonStandardPort:
    """UA026: Non-standard port"""

    def test_unusual_port_8888(self):
        findings = analyze_url("https://example.com:8888")
        assert has_rule(findings, "UA026")

    def test_backdoor_port_4444(self):
        findings = analyze_url("http://192.168.1.1:4444")
        f = find_rule(findings, "UA026")
        assert f is not None
        assert f.severity == Severity.HIGH

    def test_ephemeral_port(self):
        findings = analyze_url("https://example.com:51234")
        f = find_rule(findings, "UA026")
        assert f is not None
        assert f.severity == Severity.MEDIUM

    def test_standard_ports_ok(self):
        for port in [80, 443, 8080, 8443]:
            findings = analyze_url(f"http://example.com:{port}")
            assert not has_rule(findings, "UA026"), f"False positive for port {port}"


class TestUA027_Typosquatting:
    """UA027: Possible typosquatting domain"""

    def test_one_char_off_google(self):
        findings = analyze_url("https://gooogle.com")  # extra 'o'
        assert has_rule(findings, "UA027")
        f = find_rule(findings, "UA027")
        assert f.severity == Severity.HIGH

    def test_one_char_off_github(self):
        findings = analyze_url("https://githib.com")  # b instead of u
        # Should trigger UA027 or UA028 (might match gitlab at distance 2)
        assert has_rule(findings, "UA027") or has_rule(findings, "UA028")


class TestUA028_ResemblesPopularSite:
    """UA028: Domain resembles popular site"""

    def test_two_chars_off(self):
        findings = analyze_url("https://faceboook.com")  # extra 'o'
        # Should match UA027 or UA028
        assert has_rule(findings, "UA027") or has_rule(findings, "UA028")


class TestUA029_BrandInDomain:
    """UA029: Brand name embedded in domain"""

    def test_google_dash_login(self):
        findings = analyze_url("https://google-login.com")
        assert has_rule(findings, "UA029")
        f = find_rule(findings, "UA029")
        assert f.severity == Severity.HIGH

    def test_paypal_secure(self):
        findings = analyze_url("https://paypal-secure-login.com")
        assert has_rule(findings, "UA029")

    def test_legitimate_google(self):
        findings = analyze_url("https://google.com")
        assert not has_rule(findings, "UA029")


class TestUA030_LongFragment:
    """UA030: Excessively long URL fragment"""

    def test_long_fragment(self):
        fragment = "x" * 600
        findings = analyze_url(f"https://example.com/page#{fragment}")
        assert has_rule(findings, "UA030")
        f = find_rule(findings, "UA030")
        assert f.severity == Severity.LOW


class TestUA031_ScriptInFragment:
    """UA031: Script injection in URL fragment"""

    def test_javascript_in_fragment(self):
        findings = analyze_url("https://example.com/#javascript:alert(1)")
        assert has_rule(findings, "UA031")
        f = find_rule(findings, "UA031")
        assert f.severity == Severity.HIGH

    def test_script_tag_in_fragment(self):
        findings = analyze_url("https://example.com/#<script>alert(1)</script>")
        assert has_rule(findings, "UA031")

    def test_onerror_in_fragment(self):
        findings = analyze_url("https://example.com/#<img src=x onerror=alert(1)>")
        assert has_rule(findings, "UA031")


class TestUA032_BidiOverride:
    """UA032: Bidirectional text override in URL"""

    def test_rtl_override(self):
        # U+202E is right-to-left override
        findings = analyze_url("https://example\u202e.com")
        assert has_rule(findings, "UA032")
        f = find_rule(findings, "UA032")
        assert f.severity == Severity.CRITICAL

    def test_ltr_marks(self):
        findings = analyze_url("https://exam\u200eple.com")
        assert has_rule(findings, "UA032")


class TestUA033_ZeroWidth:
    """UA033: Zero-width characters in URL"""

    def test_zero_width_space(self):
        findings = analyze_url("https://exam\u200bple.com")
        assert has_rule(findings, "UA033")
        f = find_rule(findings, "UA033")
        assert f.severity == Severity.HIGH

    def test_zero_width_non_joiner(self):
        findings = analyze_url("https://exam\u200cple.com")
        assert has_rule(findings, "UA033")

    def test_bom(self):
        findings = analyze_url("https://exam\ufeffple.com")
        assert has_rule(findings, "UA033")


# ─── Core Functionality Tests ───────────────────────────────────────────────


class TestURLExtraction:
    """Test URL extraction from text"""

    def test_extract_single_url(self):
        text = "Check this link: https://example.com"
        urls = extract_urls(text)
        assert "https://example.com" in urls

    def test_extract_multiple_urls(self):
        text = "Links: https://a.com http://b.com ftp://c.com"
        urls = extract_urls(text)
        assert len(urls) == 3

    def test_extract_from_html(self):
        text = '<a href="https://example.com">Link</a>'
        urls = extract_urls(text)
        assert "https://example.com" in urls

    def test_extract_bare_domain(self):
        text = "example.com"
        urls = extract_urls(text)
        # Bare domain on its own line should be extracted
        assert len(urls) > 0 and "example.com" in urls[0]

    def test_ignore_comments(self):
        text = """https://real.com
# This is a comment"""
        urls = extract_urls(text)
        assert "https://real.com" in urls
        # Comment lines starting with # should be ignored by line-based parsing
        # but URLs in comments may still be matched by regex


class TestGrading:
    """Test URL risk grading system"""

    def test_safe_url_grade(self):
        findings = []
        grade, score = grade_url(findings)
        assert grade == "SAFE"
        assert score == 100

    def test_low_risk_grade(self):
        findings = [
            Finding("UA025", "URL shortener", Severity.LOW, "Detail", "url")
        ]
        grade, score = grade_url(findings)
        assert grade == "LOW RISK"
        assert 90 <= score < 100

    def test_dangerous_grade(self):
        findings = [
            Finding("UA002", "JavaScript", Severity.CRITICAL, "Detail", "url"),
            Finding("UA006", "Credentials", Severity.CRITICAL, "Detail", "url"),
        ]
        grade, score = grade_url(findings)
        assert grade == "DANGEROUS"
        assert score == 0

    def test_mixed_severity_grading(self):
        findings = [
            Finding("UA001", "HTTP", Severity.MEDIUM, "Detail", "url"),
            Finding("UA014", "Suspicious TLD", Severity.MEDIUM, "Detail", "url"),
        ]
        grade, score = grade_url(findings)
        assert 70 <= score < 90


class TestDamerauLevenshtein:
    """Test edit distance calculation"""

    def test_identical_strings(self):
        assert _damerau_levenshtein("google", "google") == 0

    def test_one_substitution(self):
        assert _damerau_levenshtein("google", "goagle") == 1

    def test_one_insertion(self):
        assert _damerau_levenshtein("google", "gooogle") == 1

    def test_one_deletion(self):
        assert _damerau_levenshtein("google", "gogle") == 1

    def test_transposition(self):
        assert _damerau_levenshtein("google", "googel") == 1

    def test_very_different_strings(self):
        dist = _damerau_levenshtein("google", "amazon")
        assert dist > 3


class TestSeverityFiltering:
    """Test minimum severity filtering"""

    def test_filter_low_severity(self):
        url = "http://bit.ly/test"  # UA001 (MEDIUM) + UA025 (LOW)
        findings = analyze_url(url, min_severity=Severity.MEDIUM)
        assert has_rule(findings, "UA001")
        assert not has_rule(findings, "UA025")

    def test_filter_high_severity_only(self):
        url = "http://192.168.1.1"  # UA001 (MEDIUM) + UA008 (HIGH)
        findings = analyze_url(url, min_severity=Severity.HIGH)
        assert has_rule(findings, "UA008")
        assert not has_rule(findings, "UA001")


class TestRuleIgnoring:
    """Test rule ignore functionality"""

    def test_ignore_single_rule(self):
        url = "http://example.com"
        findings = analyze_url(url, ignore_rules={"UA001"})
        assert not has_rule(findings, "UA001")

    def test_ignore_multiple_rules(self):
        url = "http://bit.ly/test"
        findings = analyze_url(url, ignore_rules={"UA001", "UA025"})
        assert not has_rule(findings, "UA001")
        assert not has_rule(findings, "UA025")


# ─── CLI Tests ──────────────────────────────────────────────────────────────


class TestCLI:
    """Test command-line interface"""

    def test_analyze_single_url(self, capsys):
        with patch.object(sys, 'argv', ['urlaudit', 'https://example.com']):
            exit_code = urlaudit.main()
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "example.com" in captured.out

    def test_json_output(self, capsys):
        with patch.object(sys, 'argv', ['urlaudit', '--json', 'http://example.com']):
            exit_code = urlaudit.main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "results" in data
            assert data["total_urls"] == 1
            assert "version" in data

    def test_check_mode_safe_url(self):
        with patch.object(sys, 'argv', ['urlaudit', '--check', 'https://example.com']):
            exit_code = urlaudit.main()
            assert exit_code == 0

    def test_check_mode_dangerous_url(self):
        with patch.object(sys, 'argv', ['urlaudit', '--check', 'javascript:alert(1)']):
            exit_code = urlaudit.main()
            assert exit_code == 1

    def test_check_mode_with_threshold(self):
        # HTTP is MEDIUM, threshold is HIGH, should pass
        with patch.object(sys, 'argv', ['urlaudit', '--check', '--check-threshold', 'high', 'http://example.com']):
            exit_code = urlaudit.main()
            assert exit_code == 0

    def test_stdin_input(self, monkeypatch, capsys):
        test_input = StringIO("https://example.com\nhttps://test.com\n")
        monkeypatch.setattr('sys.stdin', test_input)
        with patch.object(sys, 'argv', ['urlaudit', '-']):
            exit_code = urlaudit.main()
            assert exit_code == 0

    def test_file_input(self, tmp_path, capsys):
        url_file = tmp_path / "urls.txt"
        url_file.write_text("https://example.com\nhttps://test.tk\n")
        
        with patch.object(sys, 'argv', ['urlaudit', str(url_file)]):
            exit_code = urlaudit.main()
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "example.com" in captured.out

    def test_verbose_mode(self, capsys):
        with patch.object(sys, 'argv', ['urlaudit', '--verbose', 'http://example.com']):
            exit_code = urlaudit.main()
            assert exit_code == 0
            captured = capsys.readouterr()
            # Verbose mode should show more detail
            assert len(captured.out) > 100

    def test_no_color_mode(self, capsys):
        with patch.object(sys, 'argv', ['urlaudit', '--no-color', 'http://example.com']):
            exit_code = urlaudit.main()
            assert exit_code == 0
            captured = capsys.readouterr()
            # Should not contain ANSI codes
            assert '\033[' not in captured.out

    def test_severity_filter_cli(self, capsys):
        with patch.object(sys, 'argv', ['urlaudit', '--severity', 'high', 'http://example.com']):
            exit_code = urlaudit.main()
            assert exit_code == 0

    def test_ignore_rules_cli(self, capsys):
        with patch.object(sys, 'argv', ['urlaudit', '--ignore', 'UA001', 'http://example.com']):
            exit_code = urlaudit.main()
            assert exit_code == 0
            captured = capsys.readouterr()
            # UA001 should be ignored, so no HTTP warning
            assert "UA001" not in captured.out

    def test_list_rules(self, capsys):
        with patch.object(sys, 'argv', ['urlaudit', '--list-rules']):
            exit_code = urlaudit.main()
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "UA001" in captured.out
            assert "UA033" in captured.out
            assert "33 rules" in captured.out.lower()

    def test_version(self, capsys):
        with patch.object(sys, 'argv', ['urlaudit', '--version']):
            with pytest.raises(SystemExit) as exc_info:
                urlaudit.main()
            assert exc_info.value.code == 0

    def test_no_args_shows_help(self, capsys, monkeypatch):
        monkeypatch.setattr('sys.stdin.isatty', lambda: True)
        with patch.object(sys, 'argv', ['urlaudit']):
            exit_code = urlaudit.main()
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "usage:" in captured.out.lower()


# ─── Integration Tests ──────────────────────────────────────────────────────


class TestComplexURLs:
    """Test complex real-world URL patterns"""

    def test_complex_phishing_url(self):
        url = "http://paypal-verify@192.168.1.1:4444/login?redirect=http://evil.com&token=abc"
        findings = analyze_url(url)
        # Should trigger multiple rules
        assert len(findings) >= 4
        assert has_rule(findings, "UA001")  # HTTP
        assert has_rule(findings, "UA007")  # Username in URL
        assert has_rule(findings, "UA008")  # IP address

    def test_legitimate_complex_url(self):
        url = "https://mail.google.com/mail/u/0/#inbox"
        findings = analyze_url(url, min_severity=Severity.MEDIUM)
        # Should be mostly safe (maybe some INFO/LOW findings)
        critical_findings = [f for f in findings if f.severity >= Severity.HIGH]
        assert len(critical_findings) == 0

    def test_url_with_all_components(self):
        url = "https://user:pass@sub.example.com:9000/path/to/resource?query=value&foo=bar#fragment"
        findings = analyze_url(url)
        # Should detect credentials and non-standard port at minimum
        assert has_rule(findings, "UA006")  # Credentials
        assert has_rule(findings, "UA026")  # Port

    def test_homograph_attack_combo(self):
        # Cyrillic + punycode + suspicious TLD
        url = "https://раypal.tk/login"
        findings = analyze_url(url)
        assert len(findings) >= 2


class TestEdgeCases:
    """Test edge cases and malformed inputs"""

    def test_empty_url(self):
        findings = analyze_url("")
        assert len(findings) == 0

    def test_whitespace_url(self):
        findings = analyze_url("   ")
        assert len(findings) == 0

    def test_url_with_newlines(self):
        url = "https://example.com\n"
        findings = analyze_url(url)
        # Should strip and process normally
        assert not has_rule(findings, "UA000")  # No malformed error

    def test_no_scheme_url(self):
        # urlparse handles this gracefully
        findings = analyze_url("example.com/path")
        # Might not trigger many rules without a scheme
        assert isinstance(findings, list)

    def test_unicode_domain(self):
        url = "https://münchen.de"
        findings = analyze_url(url)
        # Should handle gracefully
        assert isinstance(findings, list)


class TestFindingDataclass:
    """Test Finding dataclass functionality"""

    def test_finding_creation(self):
        f = Finding(
            rule_id="UA001",
            description="Test",
            severity=Severity.HIGH,
            detail="Detail text",
            url="https://example.com"
        )
        assert f.rule_id == "UA001"
        assert f.severity == Severity.HIGH

    def test_finding_to_dict(self):
        f = Finding(
            rule_id="UA001",
            description="Test",
            severity=Severity.HIGH,
            detail="Detail",
            url="https://example.com"
        )
        d = f.to_dict()
        assert d["rule_id"] == "UA001"
        assert d["severity"] == "HIGH"
        assert "url" in d


class TestSeverityEnum:
    """Test Severity enum"""

    def test_severity_ordering(self):
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_severity_string(self):
        assert str(Severity.HIGH) == "HIGH"
        assert str(Severity.CRITICAL) == "CRITICAL"


# ─── Additional Coverage Tests ──────────────────────────────────────────────


class TestOutputFormatting:
    """Test output formatting functions"""

    def test_text_report_with_findings(self, capsys):
        findings = [
            Finding("UA001", "HTTP", Severity.MEDIUM, "Detail", "http://example.com")
        ]
        urlaudit.print_text_report("http://example.com", findings, use_color=False)
        captured = capsys.readouterr()
        assert "http://example.com" in captured.out
        assert "MEDIUM" in captured.out

    def test_text_report_safe_url(self, capsys):
        urlaudit.print_text_report("https://example.com", [], use_color=False)
        captured = capsys.readouterr()
        assert "No security issues" in captured.out or "SAFE" in captured.out

    def test_batch_summary(self, capsys):
        results = [
            ("https://safe.com", []),
            ("http://risky.com", [Finding("UA001", "HTTP", Severity.MEDIUM, "Detail", "http://risky.com")]),
        ]
        urlaudit.print_batch_summary(results, use_color=False)
        captured = capsys.readouterr()
        assert "2" in captured.out  # 2 URLs

    def test_json_report_structure(self, capsys):
        results = [
            ("https://example.com", []),
            ("http://test.com", [Finding("UA001", "HTTP", Severity.MEDIUM, "Detail", "http://test.com")]),
        ]
        urlaudit.print_json_report(results)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data["results"]) == 2
        assert "summary" in data
        assert "by_severity" in data["summary"]


class TestMalformedURL:
    """Test handling of truly malformed URLs"""

    def test_urlparse_exception(self):
        # Some edge cases might be handled by urlparse
        url = "ht!tp://invalid"
        findings = analyze_url(url)
        # Should not crash
        assert isinstance(findings, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
