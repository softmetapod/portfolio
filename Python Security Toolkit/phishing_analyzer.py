#!/usr/bin/env python3
"""
Phishing Analyzer - URL and Email Header Phishing Indicator Detection

Analyzes URLs for phishing indicators (suspicious TLDs, lookalike domains,
URL shorteners, homoglyph detection, IP-based URLs, excessive subdomains)
and email headers for spoofing indicators (SPF/DKIM/DMARC alignment).
Produces a weighted risk score from 0 to 100.

Author: Jacob Phillips | Cloud Security Engineer
Certifications: SC-200, Security+

Usage:
    python phishing_analyzer.py --url "http://paypa1-secure.login.com/verify"
    python phishing_analyzer.py --url-file suspicious_urls.txt
    python phishing_analyzer.py --email-headers headers.txt
    python phishing_analyzer.py --url "http://example.com" --output analysis.json
"""

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS: Set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Freenom free TLDs
    ".xyz", ".top", ".buzz", ".club", ".work",
    ".info", ".click", ".link", ".rest", ".icu",
    ".cam", ".surf", ".monster", ".site", ".online",
    ".fun", ".space", ".pw", ".cc", ".ws",
}

# Known URL shortener domains
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bl.ink", "lnkd.in",
    "rb.gy", "cutt.ly", "t.ly", "shorturl.at", "tiny.cc",
    "v.gd", "x.co", "soo.gd", "s.coop", "cli.gs",
}

# High-value brand targets for lookalike detection
TARGET_BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypa1", "paypai", "paypaI", "paypol", "payp4l", "pay-pal", "paypal-secure"],
    "microsoft": ["micr0soft", "mlcrosoft", "microsft", "micosoft", "micro-soft", "microsoftonline"],
    "apple": ["app1e", "appie", "appIe", "apple-id", "apple-support"],
    "google": ["g00gle", "googie", "googIe", "go0gle", "google-security"],
    "amazon": ["amaz0n", "arnazon", "arnazon", "amazon-security", "amazn"],
    "netflix": ["netf1ix", "netfiix", "netfIix", "netflix-billing"],
    "facebook": ["faceb00k", "facebok", "facebook-security", "faceb0ok"],
    "chase": ["chas3", "chase-secure", "chase-verify", "chas-e"],
    "wellsfargo": ["wells-fargo", "welisfargo", "wellsfarg0"],
    "bankofamerica": ["bank0famerica", "bankofamer1ca", "bofa-secure"],
}

# Homoglyph character substitution map
HOMOGLYPHS: Dict[str, List[str]] = {
    "a": ["\u0430", "\u00e0", "\u00e1", "\u00e2", "\u00e3"],  # Cyrillic а, etc.
    "e": ["\u0435", "\u00e8", "\u00e9", "\u00ea"],
    "o": ["\u043e", "\u00f2", "\u00f3", "\u00f4", "0"],
    "i": ["\u0456", "\u00ec", "\u00ed", "1", "l", "|"],
    "l": ["1", "I", "|", "\u006c"],
    "c": ["\u0441", "\u00e7"],
    "p": ["\u0440"],
    "s": ["\u0455", "$", "5"],
    "u": ["\u00fc", "\u00f9", "\u00fa"],
    "n": ["\u0578"],
    "d": ["\u0501"],
    "g": ["q", "9"],
    "t": ["\u0442", "+"],
    "0": ["O", "o", "\u043e"],
    "1": ["l", "I", "|", "i"],
}

# Suspicious URL path keywords
SUSPICIOUS_PATHS: Set[str] = {
    "login", "signin", "sign-in", "verify", "verification",
    "account", "update", "confirm", "secure", "banking",
    "password", "credential", "authenticate", "wallet",
    "billing", "payment", "invoice", "security",
    "unlock", "suspended", "limited", "restore",
}

# Suspicious query parameter keys
SUSPICIOUS_PARAMS: Set[str] = {
    "token", "session", "redirect", "return", "callback",
    "next", "continue", "ref", "source",
}

# Risk score weights
WEIGHTS: Dict[str, int] = {
    "suspicious_tld": 15,
    "lookalike_domain": 35,
    "homoglyph_detected": 30,
    "url_shortener": 20,
    "ip_based_url": 25,
    "excessive_subdomains": 15,
    "no_https": 10,
    "suspicious_path": 12,
    "suspicious_params": 8,
    "long_domain": 10,
    "double_extension": 15,
    "at_symbol_in_url": 20,
    "encoded_characters": 10,
    "spf_fail": 25,
    "dkim_fail": 25,
    "dmarc_fail": 25,
    "from_mismatch": 20,
    "suspicious_reply_to": 15,
}

RISK_LEVELS = {
    (0, 25): "LOW",
    (25, 50): "MODERATE",
    (50, 75): "HIGH",
    (75, 101): "CRITICAL",
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class RiskIndicator:
    """A single risk indicator found during analysis."""

    name: str
    weight: int
    description: str
    detail: str = ""


@dataclass
class URLAnalysis:
    """Complete analysis result for a single URL."""

    url: str
    parsed_domain: str
    risk_score: int
    risk_level: str
    indicators: List[dict]
    recommendation: str


@dataclass
class EmailHeaderAnalysis:
    """Analysis result for email headers."""

    from_header: str
    return_path: str
    spf_result: str
    dkim_result: str
    dmarc_result: str
    risk_score: int
    risk_level: str
    indicators: List[dict]
    recommendation: str


@dataclass
class AnalysisReport:
    """Full phishing analysis report."""

    analysis_timestamp: str
    url_analyses: List[dict]
    email_header_analyses: List[dict]
    summary: dict


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------


def configure_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the application logger.

    Args:
        verbose: If True, set log level to DEBUG; otherwise INFO.

    Returns:
        Configured Logger instance.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("phishing_analyzer")
    logger.setLevel(log_level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


# ---------------------------------------------------------------------------
# URL analysis functions
# ---------------------------------------------------------------------------


def extract_domain_parts(url: str) -> Tuple[str, str, str, str]:
    """Parse a URL into its component parts.

    Args:
        url: The URL to parse.

    Returns:
        Tuple of (scheme, full_hostname, path, query_string).
    """
    # Ensure URL has a scheme for proper parsing
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    hostname = parsed.hostname or parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""

    return scheme, hostname.lower(), path.lower(), query


def check_suspicious_tld(hostname: str) -> Optional[RiskIndicator]:
    """Check if the domain uses a TLD commonly associated with phishing.

    Args:
        hostname: The hostname to check.

    Returns:
        A RiskIndicator if suspicious, None otherwise.
    """
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return RiskIndicator(
                name="suspicious_tld",
                weight=WEIGHTS["suspicious_tld"],
                description="Suspicious top-level domain",
                detail=f"TLD '{tld}' is commonly used in phishing campaigns",
            )
    return None


def check_lookalike_domain(hostname: str) -> Optional[RiskIndicator]:
    """Check if the hostname resembles a known brand (typosquatting).

    Args:
        hostname: The hostname to check.

    Returns:
        A RiskIndicator if a lookalike is detected, None otherwise.
    """
    # Strip TLD for comparison
    domain_base = hostname.split(".")[0] if "." in hostname else hostname

    for brand, variants in TARGET_BRANDS.items():
        # Check if a known variant appears in the hostname
        for variant in variants:
            if variant in hostname and brand not in hostname:
                return RiskIndicator(
                    name="lookalike_domain",
                    weight=WEIGHTS["lookalike_domain"],
                    description="Lookalike/typosquat domain detected",
                    detail=f'"{variant}" in hostname resembles "{brand}"',
                )

        # Check if brand name is part of hostname but not the registrable domain
        # e.g., paypal.attacker.com
        parts = hostname.split(".")
        if len(parts) >= 3 and brand in parts[0] and brand not in ".".join(parts[-2:]):
            return RiskIndicator(
                name="lookalike_domain",
                weight=WEIGHTS["lookalike_domain"],
                description="Brand name used as subdomain",
                detail=f'"{brand}" appears as subdomain, not registrable domain',
            )

    return None


def check_homoglyphs(hostname: str) -> Optional[RiskIndicator]:
    """Detect homoglyph/unicode substitution characters in hostname.

    Args:
        hostname: The hostname to check.

    Returns:
        A RiskIndicator if homoglyphs detected, None otherwise.
    """
    found_substitutions: List[str] = []

    for char in hostname:
        for original, glyphs in HOMOGLYPHS.items():
            if char in glyphs and char != original:
                found_substitutions.append(f"'{char}' for '{original}'")

    if found_substitutions:
        return RiskIndicator(
            name="homoglyph_detected",
            weight=WEIGHTS["homoglyph_detected"],
            description="Homoglyph character substitution detected",
            detail=f"Substitutions: {', '.join(found_substitutions[:5])}",
        )
    return None


def check_url_shortener(hostname: str) -> Optional[RiskIndicator]:
    """Check if the URL uses a known URL shortener service.

    Args:
        hostname: The hostname to check.

    Returns:
        A RiskIndicator if a shortener is detected, None otherwise.
    """
    for shortener in URL_SHORTENERS:
        if hostname == shortener or hostname.endswith("." + shortener):
            return RiskIndicator(
                name="url_shortener",
                weight=WEIGHTS["url_shortener"],
                description="URL shortener service detected",
                detail=f"Shortener: {shortener} (obscures true destination)",
            )
    return None


def check_ip_based_url(hostname: str) -> Optional[RiskIndicator]:
    """Check if the URL uses an IP address instead of a domain name.

    Args:
        hostname: The hostname to check.

    Returns:
        A RiskIndicator if IP-based, None otherwise.
    """
    # IPv4 pattern
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    # Decimal/hex IP patterns (obfuscation)
    decimal_ip = re.compile(r"^\d{8,10}$")
    hex_ip = re.compile(r"^0x[0-9a-fA-F]+$")

    if ipv4_pattern.match(hostname) or decimal_ip.match(hostname) or hex_ip.match(hostname):
        return RiskIndicator(
            name="ip_based_url",
            weight=WEIGHTS["ip_based_url"],
            description="IP address used instead of domain name",
            detail=f"Host: {hostname} (legitimate sites use domain names)",
        )

    # Check for IPv6
    if hostname.startswith("[") and "]" in hostname:
        return RiskIndicator(
            name="ip_based_url",
            weight=WEIGHTS["ip_based_url"],
            description="IPv6 address used instead of domain name",
            detail=f"Host: {hostname}",
        )

    return None


def check_excessive_subdomains(hostname: str) -> Optional[RiskIndicator]:
    """Check if the hostname has an unusual number of subdomains.

    Args:
        hostname: The hostname to check.

    Returns:
        A RiskIndicator if excessive subdomains found, None otherwise.
    """
    parts = hostname.split(".")
    # More than 3 parts means excessive subdomains (e.g., a.b.c.example.com)
    if len(parts) > 4:
        return RiskIndicator(
            name="excessive_subdomains",
            weight=WEIGHTS["excessive_subdomains"],
            description="Excessive number of subdomains",
            detail=f"{len(parts)} domain levels detected (normal: 2-3)",
        )
    return None


def check_no_https(scheme: str, path: str) -> Optional[RiskIndicator]:
    """Check if a login/sensitive page is served over HTTP.

    Args:
        scheme: URL scheme (http/https).
        path: URL path.

    Returns:
        A RiskIndicator if insecure, None otherwise.
    """
    if scheme == "http":
        sensitive_keywords = {"login", "signin", "account", "password", "banking", "verify"}
        if any(kw in path for kw in sensitive_keywords):
            return RiskIndicator(
                name="no_https",
                weight=WEIGHTS["no_https"],
                description="Sensitive page served over HTTP (no TLS)",
                detail="Login/financial pages should always use HTTPS",
            )
        else:
            return RiskIndicator(
                name="no_https",
                weight=max(5, WEIGHTS["no_https"] - 5),
                description="HTTP used (no TLS encryption)",
                detail="Page served without encryption",
            )
    return None


def check_suspicious_path(path: str) -> Optional[RiskIndicator]:
    """Check URL path for suspicious keywords.

    Args:
        path: The URL path.

    Returns:
        A RiskIndicator if suspicious keywords found, None otherwise.
    """
    found = [kw for kw in SUSPICIOUS_PATHS if kw in path]
    if found:
        return RiskIndicator(
            name="suspicious_path",
            weight=WEIGHTS["suspicious_path"],
            description="Suspicious keywords in URL path",
            detail=f"Found: {', '.join(found[:5])}",
        )
    return None


def check_suspicious_query_params(query: str) -> Optional[RiskIndicator]:
    """Check URL query parameters for suspicious patterns.

    Args:
        query: The URL query string.

    Returns:
        A RiskIndicator if suspicious parameters found, None otherwise.
    """
    if not query:
        return None

    try:
        params = parse_qs(query)
        found = [k for k in params if k.lower() in SUSPICIOUS_PARAMS]
        if found:
            return RiskIndicator(
                name="suspicious_params",
                weight=WEIGHTS["suspicious_params"],
                description="Suspicious query parameters",
                detail=f"Parameters: {', '.join(found)}",
            )
    except Exception:
        pass

    return None


def check_long_domain(hostname: str) -> Optional[RiskIndicator]:
    """Check if the domain name is unusually long.

    Args:
        hostname: The hostname to check.

    Returns:
        A RiskIndicator if the domain is excessively long, None otherwise.
    """
    if len(hostname) > 50:
        return RiskIndicator(
            name="long_domain",
            weight=WEIGHTS["long_domain"],
            description="Unusually long domain name",
            detail=f"Domain length: {len(hostname)} characters",
        )
    return None


def check_at_symbol(url: str) -> Optional[RiskIndicator]:
    """Check for @ symbol in URL (used to obfuscate the real destination).

    Args:
        url: The full URL.

    Returns:
        A RiskIndicator if @ is found in the URL, None otherwise.
    """
    # The @ symbol before the hostname causes browsers to ignore everything before it
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        return RiskIndicator(
            name="at_symbol_in_url",
            weight=WEIGHTS["at_symbol_in_url"],
            description="@ symbol in URL (credential-based obfuscation)",
            detail="The @ symbol can trick users about the true destination",
        )
    return None


def check_encoded_chars(url: str) -> Optional[RiskIndicator]:
    """Check for excessive URL-encoded characters (obfuscation).

    Args:
        url: The full URL.

    Returns:
        A RiskIndicator if excessive encoding found, None otherwise.
    """
    encoded_count = url.count("%")
    if encoded_count > 5:
        return RiskIndicator(
            name="encoded_characters",
            weight=WEIGHTS["encoded_characters"],
            description="Excessive URL-encoded characters",
            detail=f"{encoded_count} encoded characters (possible obfuscation)",
        )
    return None


def analyze_url(url: str, logger: logging.Logger) -> URLAnalysis:
    """Perform comprehensive phishing analysis on a single URL.

    Args:
        url: The URL to analyze.
        logger: Logger instance.

    Returns:
        A URLAnalysis object with risk score and indicators.
    """
    scheme, hostname, path, query = extract_domain_parts(url)
    indicators: List[RiskIndicator] = []

    # Run all checks
    checks = [
        check_suspicious_tld(hostname),
        check_lookalike_domain(hostname),
        check_homoglyphs(hostname),
        check_url_shortener(hostname),
        check_ip_based_url(hostname),
        check_excessive_subdomains(hostname),
        check_no_https(scheme, path),
        check_suspicious_path(path),
        check_suspicious_query_params(query),
        check_long_domain(hostname),
        check_at_symbol(url),
        check_encoded_chars(url),
    ]

    for result in checks:
        if result is not None:
            indicators.append(result)

    # Calculate risk score (capped at 100)
    raw_score = sum(ind.weight for ind in indicators)
    risk_score = min(100, raw_score)

    # Determine risk level
    risk_level = "LOW"
    for (low, high), level in RISK_LEVELS.items():
        if low <= risk_score < high:
            risk_level = level
            break

    # Generate recommendation
    if risk_score >= 75:
        recommendation = "CRITICAL RISK - Block immediately and investigate"
    elif risk_score >= 50:
        recommendation = "HIGH RISK - Block and investigate"
    elif risk_score >= 25:
        recommendation = "MODERATE RISK - Exercise caution, investigate further"
    else:
        recommendation = "LOW RISK - Appears benign, but verify if suspicious"

    logger.info("URL analyzed: %s -> Score: %d (%s)", url, risk_score, risk_level)

    return URLAnalysis(
        url=url,
        parsed_domain=hostname,
        risk_score=risk_score,
        risk_level=risk_level,
        indicators=[asdict(ind) for ind in indicators],
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# Email header analysis
# ---------------------------------------------------------------------------


def parse_email_headers(header_text: str) -> Dict[str, str]:
    """Parse raw email headers into a dictionary.

    Simple parser that handles multi-line header values (continuation
    lines starting with whitespace).

    Args:
        header_text: Raw email header text.

    Returns:
        Dictionary mapping lowercase header names to values.
    """
    headers: Dict[str, str] = {}
    current_key: Optional[str] = None
    current_value: str = ""

    for line in header_text.split("\n"):
        if line.startswith((" ", "\t")) and current_key:
            # Continuation line
            current_value += " " + line.strip()
        elif ":" in line:
            # Save previous header
            if current_key:
                headers[current_key] = current_value.strip()

            key, _, value = line.partition(":")
            current_key = key.strip().lower()
            current_value = value.strip()
        else:
            continue

    # Save last header
    if current_key:
        headers[current_key] = current_value.strip()

    return headers


def check_spf_result(headers: Dict[str, str]) -> Tuple[str, Optional[RiskIndicator]]:
    """Check SPF authentication result from email headers.

    Args:
        headers: Parsed email headers dictionary.

    Returns:
        Tuple of (SPF result string, RiskIndicator or None).
    """
    # Look for Authentication-Results or Received-SPF header
    auth_results = headers.get("authentication-results", "")
    received_spf = headers.get("received-spf", "")

    spf_text = auth_results + " " + received_spf
    spf_text_lower = spf_text.lower()

    if "spf=pass" in spf_text_lower or "pass" in received_spf.lower().split(";")[0]:
        return "pass", None
    elif "spf=fail" in spf_text_lower or "fail" in received_spf.lower().split(";")[0]:
        return "fail", RiskIndicator(
            name="spf_fail",
            weight=WEIGHTS["spf_fail"],
            description="SPF authentication failed",
            detail="Sender IP not authorized to send for this domain",
        )
    elif "spf=softfail" in spf_text_lower or "softfail" in received_spf.lower():
        return "softfail", RiskIndicator(
            name="spf_fail",
            weight=WEIGHTS["spf_fail"] - 10,
            description="SPF soft fail",
            detail="Sender IP not explicitly authorized (softfail)",
        )
    elif "spf=none" in spf_text_lower:
        return "none", RiskIndicator(
            name="spf_fail",
            weight=5,
            description="No SPF record found",
            detail="Domain does not publish an SPF policy",
        )

    return "unknown", None


def check_dkim_result(headers: Dict[str, str]) -> Tuple[str, Optional[RiskIndicator]]:
    """Check DKIM authentication result from email headers.

    Args:
        headers: Parsed email headers dictionary.

    Returns:
        Tuple of (DKIM result string, RiskIndicator or None).
    """
    auth_results = headers.get("authentication-results", "").lower()

    if "dkim=pass" in auth_results:
        return "pass", None
    elif "dkim=fail" in auth_results:
        return "fail", RiskIndicator(
            name="dkim_fail",
            weight=WEIGHTS["dkim_fail"],
            description="DKIM signature verification failed",
            detail="Email content may have been tampered with",
        )
    elif "dkim=none" in auth_results:
        return "none", RiskIndicator(
            name="dkim_fail",
            weight=5,
            description="No DKIM signature present",
            detail="Email was not signed with DKIM",
        )

    return "unknown", None


def check_dmarc_result(headers: Dict[str, str]) -> Tuple[str, Optional[RiskIndicator]]:
    """Check DMARC authentication result from email headers.

    Args:
        headers: Parsed email headers dictionary.

    Returns:
        Tuple of (DMARC result string, RiskIndicator or None).
    """
    auth_results = headers.get("authentication-results", "").lower()

    if "dmarc=pass" in auth_results:
        return "pass", None
    elif "dmarc=fail" in auth_results:
        return "fail", RiskIndicator(
            name="dmarc_fail",
            weight=WEIGHTS["dmarc_fail"],
            description="DMARC policy check failed",
            detail="Message does not align with sender's DMARC policy",
        )
    elif "dmarc=none" in auth_results:
        return "none", RiskIndicator(
            name="dmarc_fail",
            weight=5,
            description="No DMARC policy found",
            detail="Sender domain does not publish a DMARC policy",
        )

    return "unknown", None


def check_from_mismatch(headers: Dict[str, str]) -> Optional[RiskIndicator]:
    """Check for mismatches between From, Return-Path, and Reply-To.

    Args:
        headers: Parsed email headers dictionary.

    Returns:
        A RiskIndicator if a mismatch is detected, None otherwise.
    """
    from_header = headers.get("from", "")
    return_path = headers.get("return-path", "")
    reply_to = headers.get("reply-to", "")

    # Extract domains from email addresses
    def extract_domain(addr: str) -> str:
        match = re.search(r"@([\w.-]+)", addr)
        return match.group(1).lower() if match else ""

    from_domain = extract_domain(from_header)
    return_domain = extract_domain(return_path)
    reply_domain = extract_domain(reply_to)

    mismatches: List[str] = []

    if from_domain and return_domain and from_domain != return_domain:
        mismatches.append(f"From ({from_domain}) != Return-Path ({return_domain})")

    if from_domain and reply_domain and from_domain != reply_domain:
        mismatches.append(f"From ({from_domain}) != Reply-To ({reply_domain})")

    if mismatches:
        return RiskIndicator(
            name="from_mismatch",
            weight=WEIGHTS["from_mismatch"],
            description="Sender address mismatch detected",
            detail="; ".join(mismatches),
        )

    return None


def analyze_email_headers(
    header_text: str, logger: logging.Logger
) -> EmailHeaderAnalysis:
    """Perform phishing analysis on email headers.

    Args:
        header_text: Raw email header text.
        logger: Logger instance.

    Returns:
        An EmailHeaderAnalysis object.
    """
    headers = parse_email_headers(header_text)
    indicators: List[RiskIndicator] = []

    # Extract key header values
    from_header = headers.get("from", "unknown")
    return_path = headers.get("return-path", "unknown")

    # Run checks
    spf_result, spf_indicator = check_spf_result(headers)
    if spf_indicator:
        indicators.append(spf_indicator)

    dkim_result, dkim_indicator = check_dkim_result(headers)
    if dkim_indicator:
        indicators.append(dkim_indicator)

    dmarc_result, dmarc_indicator = check_dmarc_result(headers)
    if dmarc_indicator:
        indicators.append(dmarc_indicator)

    mismatch_indicator = check_from_mismatch(headers)
    if mismatch_indicator:
        indicators.append(mismatch_indicator)

    # Calculate risk score
    raw_score = sum(ind.weight for ind in indicators)
    risk_score = min(100, raw_score)

    risk_level = "LOW"
    for (low, high), level in RISK_LEVELS.items():
        if low <= risk_score < high:
            risk_level = level
            break

    if risk_score >= 75:
        recommendation = "CRITICAL RISK - Likely spoofed, quarantine immediately"
    elif risk_score >= 50:
        recommendation = "HIGH RISK - Probable spoofing, quarantine and investigate"
    elif risk_score >= 25:
        recommendation = "MODERATE RISK - Some spoofing indicators, review carefully"
    else:
        recommendation = "LOW RISK - Headers appear consistent"

    logger.info(
        "Email headers analyzed: From=%s -> Score: %d (%s)",
        from_header,
        risk_score,
        risk_level,
    )

    return EmailHeaderAnalysis(
        from_header=from_header,
        return_path=return_path,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        risk_score=risk_score,
        risk_level=risk_level,
        indicators=[asdict(ind) for ind in indicators],
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def print_url_analysis(analysis: URLAnalysis) -> None:
    """Print a formatted URL analysis to the console.

    Args:
        analysis: The URLAnalysis to display.
    """
    print("\n" + "=" * 62)
    print("              PHISHING ANALYSIS REPORT")
    print("=" * 62)
    print(f"  URL: {analysis.url}")
    print(f"  Domain: {analysis.parsed_domain}")
    print(f"\n  Risk Score: {analysis.risk_score}/100 [{analysis.risk_level}]")

    if analysis.indicators:
        print(f"\n  Indicators Found:")
        for ind in analysis.indicators:
            print(f"    [+{ind['weight']:>2}] {ind['description']}")
            if ind.get("detail"):
                print(f"           {ind['detail']}")
    else:
        print("\n  No phishing indicators detected.")

    print(f"\n  Recommendation: {analysis.recommendation}")
    print("=" * 62)


def print_email_analysis(analysis: EmailHeaderAnalysis) -> None:
    """Print a formatted email header analysis to the console.

    Args:
        analysis: The EmailHeaderAnalysis to display.
    """
    print("\n" + "=" * 62)
    print("            EMAIL HEADER ANALYSIS REPORT")
    print("=" * 62)
    print(f"  From: {analysis.from_header}")
    print(f"  Return-Path: {analysis.return_path}")
    print(f"  SPF: {analysis.spf_result}")
    print(f"  DKIM: {analysis.dkim_result}")
    print(f"  DMARC: {analysis.dmarc_result}")
    print(f"\n  Risk Score: {analysis.risk_score}/100 [{analysis.risk_level}]")

    if analysis.indicators:
        print(f"\n  Indicators Found:")
        for ind in analysis.indicators:
            print(f"    [+{ind['weight']:>2}] {ind['description']}")
            if ind.get("detail"):
                print(f"           {ind['detail']}")
    else:
        print("\n  No spoofing indicators detected.")

    print(f"\n  Recommendation: {analysis.recommendation}")
    print("=" * 62)


def save_report(
    url_analyses: List[URLAnalysis],
    email_analyses: List[EmailHeaderAnalysis],
    output_path: str,
    logger: logging.Logger,
) -> None:
    """Save the complete analysis report as JSON.

    Args:
        url_analyses: List of URL analysis results.
        email_analyses: List of email header analysis results.
        output_path: File path for JSON output.
        logger: Logger instance.
    """
    import datetime

    report = {
        "analysis_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url_analyses": [asdict(a) for a in url_analyses],
        "email_header_analyses": [asdict(a) for a in email_analyses],
        "summary": {
            "total_urls_analyzed": len(url_analyses),
            "total_emails_analyzed": len(email_analyses),
            "high_risk_urls": sum(
                1 for a in url_analyses if a.risk_score >= 50
            ),
            "high_risk_emails": sum(
                1 for a in email_analyses if a.risk_score >= 50
            ),
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info("Report saved to %s", output_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_arguments() -> argparse.Namespace:
    """Parse and return command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        description="Phishing Analyzer - URL and email header phishing detection",
        epilog=(
            "Examples:\n"
            '  python phishing_analyzer.py --url "http://paypa1.secure-login.com/verify"\n'
            "  python phishing_analyzer.py --url-file suspicious_urls.txt\n"
            "  python phishing_analyzer.py --email-headers headers.txt\n"
            '  python phishing_analyzer.py --url "http://example.com" --output report.json'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--url",
        "-u",
        default=None,
        help="Single URL to analyze",
    )
    parser.add_argument(
        "--url-file",
        "-f",
        default=None,
        help="File containing URLs to analyze (one per line)",
    )
    parser.add_argument(
        "--email-headers",
        "-e",
        default=None,
        help="File containing email headers to analyze",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path for JSON report (optional)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    """Main entry point for the phishing analyzer.

    Returns:
        Exit code: 0 for success, 1 for high-risk findings, 2 for errors.
    """
    args = parse_arguments()
    logger = configure_logging(verbose=args.verbose)

    if not any([args.url, args.url_file, args.email_headers]):
        logger.error(
            "No input provided. Use --url, --url-file, or --email-headers."
        )
        return 2

    logger.info("Phishing Analyzer starting...")

    url_analyses: List[URLAnalysis] = []
    email_analyses: List[EmailHeaderAnalysis] = []

    # Analyze single URL
    if args.url:
        analysis = analyze_url(args.url, logger)
        url_analyses.append(analysis)
        print_url_analysis(analysis)

    # Analyze URLs from file
    if args.url_file:
        if not os.path.isfile(args.url_file):
            logger.error("URL file not found: %s", args.url_file)
            return 2

        with open(args.url_file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        logger.info("Analyzing %d URLs from %s", len(urls), args.url_file)

        for url in urls:
            analysis = analyze_url(url, logger)
            url_analyses.append(analysis)
            print_url_analysis(analysis)

    # Analyze email headers
    if args.email_headers:
        if not os.path.isfile(args.email_headers):
            logger.error("Email headers file not found: %s", args.email_headers)
            return 2

        with open(args.email_headers, "r", encoding="utf-8") as f:
            header_text = f.read()

        analysis = analyze_email_headers(header_text, logger)
        email_analyses.append(analysis)
        print_email_analysis(analysis)

    # Print summary if multiple analyses
    total = len(url_analyses) + len(email_analyses)
    if total > 1:
        high_risk = sum(1 for a in url_analyses if a.risk_score >= 50) + sum(
            1 for a in email_analyses if a.risk_score >= 50
        )
        print(f"\n{'=' * 62}")
        print(f"  SUMMARY: {total} items analyzed, {high_risk} high-risk findings")
        print(f"{'=' * 62}\n")

    # Save report if requested
    if args.output:
        save_report(url_analyses, email_analyses, args.output, logger)

    # Exit code based on findings
    has_high_risk = any(a.risk_score >= 50 for a in url_analyses) or any(
        a.risk_score >= 50 for a in email_analyses
    )
    return 1 if has_high_risk else 0


if __name__ == "__main__":
    sys.exit(main())
