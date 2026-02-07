#!/usr/bin/env python3
"""
IOC Scanner - Indicator of Compromise File Hash Scanner

Scans a target directory, computes file hashes (MD5, SHA-1, SHA-256), and
compares them against a local IOC feed in CSV format. Designed for rapid
triage during incident response or routine threat hunting.

Author: Jacob Phillips | Cloud Security Engineer
Certifications: SC-200, Security+

IOC Feed CSV Format:
    hash,type,threat_name,severity
    d41d8cd98f00b204e9800998ecf8427e,md5,EmptyFile Test,low
    da39a3ee5e6b4b0d3255bfef95601890afd80709,sha1,Example Threat,medium
    e3b0c44298fc1c149afbf4c8996fb924...,sha256,Critical Malware,critical

Severity levels: low, medium, high, critical

Usage:
    python ioc_scanner.py --target /path/to/scan --ioc-feed iocs.csv
    python ioc_scanner.py --target /tmp --ioc-feed iocs.csv --output report.json
    python ioc_scanner.py --target /var --ioc-feed iocs.csv --hash-types sha256
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_HASH_TYPES: Set[str] = {"md5", "sha1", "sha256"}

HASH_LENGTH_MAP: Dict[int, str] = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}

SEVERITY_ORDER: Dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

BUFFER_SIZE: int = 65536  # 64 KB read buffer for hashing

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class IOCEntry:
    """Represents a single Indicator of Compromise from the feed."""

    hash_value: str
    hash_type: str
    threat_name: str
    severity: str


@dataclass
class ScanMatch:
    """Represents a file that matched an IOC entry."""

    file_path: str
    file_size: int
    hash_type: str
    hash_value: str
    threat_name: str
    severity: str


@dataclass
class ScanReport:
    """Final scan report structure."""

    target_directory: str
    ioc_feed_file: str
    scan_start: str
    scan_end: str
    scan_duration_seconds: float
    total_files_scanned: int
    total_ioc_entries: int
    total_matches: int
    matches: List[dict]


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
    logger = logging.getLogger("ioc_scanner")
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
# IOC feed loader
# ---------------------------------------------------------------------------


def load_ioc_feed(feed_path: str, logger: logging.Logger) -> Dict[str, IOCEntry]:
    """Load IOC entries from a CSV file into a lookup dictionary.

    The CSV must have columns: hash, type, threat_name, severity.
    Hashes are normalized to lowercase for comparison.

    Args:
        feed_path: Path to the IOC feed CSV file.
        logger: Logger instance.

    Returns:
        Dictionary mapping lowercase hash strings to IOCEntry objects.

    Raises:
        FileNotFoundError: If the feed file does not exist.
        ValueError: If the CSV is malformed or missing required columns.
    """
    feed_file = Path(feed_path)
    if not feed_file.is_file():
        raise FileNotFoundError(f"IOC feed file not found: {feed_path}")

    ioc_lookup: Dict[str, IOCEntry] = {}
    required_columns = {"hash", "type", "threat_name", "severity"}

    with open(feed_file, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)

        if reader.fieldnames is None:
            raise ValueError("IOC feed CSV is empty or has no header row.")

        # Normalize column names (strip whitespace)
        normalized_fields = {col.strip().lower() for col in reader.fieldnames}
        missing = required_columns - normalized_fields
        if missing:
            raise ValueError(
                f"IOC feed CSV missing required columns: {', '.join(missing)}"
            )

        for row_num, row in enumerate(reader, start=2):
            # Normalize keys
            row = {k.strip().lower(): v.strip() for k, v in row.items()}

            hash_value = row.get("hash", "").lower()
            hash_type = row.get("type", "").lower()
            threat_name = row.get("threat_name", "Unknown")
            severity = row.get("severity", "medium").lower()

            if not hash_value:
                logger.debug("Skipping row %d: empty hash value", row_num)
                continue

            if hash_type not in SUPPORTED_HASH_TYPES:
                # Try to infer type from hash length
                inferred = HASH_LENGTH_MAP.get(len(hash_value))
                if inferred:
                    logger.debug(
                        "Row %d: inferred hash type '%s' from length %d",
                        row_num,
                        inferred,
                        len(hash_value),
                    )
                    hash_type = inferred
                else:
                    logger.warning(
                        "Row %d: unsupported hash type '%s', skipping",
                        row_num,
                        hash_type,
                    )
                    continue

            if severity not in SEVERITY_ORDER:
                logger.warning(
                    "Row %d: unknown severity '%s', defaulting to 'medium'",
                    row_num,
                    severity,
                )
                severity = "medium"

            entry = IOCEntry(
                hash_value=hash_value,
                hash_type=hash_type,
                threat_name=threat_name,
                severity=severity,
            )
            ioc_lookup[hash_value] = entry

    logger.info("Loaded %d IOC entries from %s", len(ioc_lookup), feed_path)
    return ioc_lookup


# ---------------------------------------------------------------------------
# File hashing
# ---------------------------------------------------------------------------


def compute_file_hashes(
    file_path: str, hash_types: Optional[Set[str]] = None
) -> Dict[str, str]:
    """Compute cryptographic hashes for a file.

    Reads the file once and updates all requested hash algorithms
    simultaneously for efficiency.

    Args:
        file_path: Path to the file to hash.
        hash_types: Set of hash types to compute. Defaults to all supported.

    Returns:
        Dictionary mapping hash type names to hex digest strings.

    Raises:
        OSError: If the file cannot be read.
    """
    if hash_types is None:
        hash_types = SUPPORTED_HASH_TYPES

    hashers = {}
    if "md5" in hash_types:
        hashers["md5"] = hashlib.md5()
    if "sha1" in hash_types:
        hashers["sha1"] = hashlib.sha1()
    if "sha256" in hash_types:
        hashers["sha256"] = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            data = f.read(BUFFER_SIZE)
            if not data:
                break
            for hasher in hashers.values():
                hasher.update(data)

    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


# ---------------------------------------------------------------------------
# Directory scanner
# ---------------------------------------------------------------------------


def scan_directory(
    target_dir: str,
    ioc_lookup: Dict[str, IOCEntry],
    hash_types: Optional[Set[str]],
    logger: logging.Logger,
) -> tuple:
    """Scan all files in a directory tree and check against IOC lookup.

    Args:
        target_dir: Root directory to scan recursively.
        ioc_lookup: Dictionary of IOC entries keyed by hash value.
        hash_types: Set of hash types to compute. None means all.
        logger: Logger instance.

    Returns:
        Tuple of (files_scanned count, list of ScanMatch objects).
    """
    target = Path(target_dir)
    if not target.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: {target_dir}")

    matches: List[ScanMatch] = []
    files_scanned: int = 0
    errors: int = 0

    for root, _dirs, files in os.walk(target):
        for filename in files:
            file_path = os.path.join(root, filename)

            try:
                # Skip symlinks to avoid loops and confusion
                if os.path.islink(file_path):
                    logger.debug("Skipping symlink: %s", file_path)
                    continue

                file_size = os.path.getsize(file_path)
                hashes = compute_file_hashes(file_path, hash_types)
                files_scanned += 1

                if files_scanned % 500 == 0:
                    logger.info("Progress: %d files scanned...", files_scanned)

                # Check each computed hash against the IOC lookup
                for hash_type, hash_value in hashes.items():
                    if hash_value in ioc_lookup:
                        ioc = ioc_lookup[hash_value]
                        match = ScanMatch(
                            file_path=file_path,
                            file_size=file_size,
                            hash_type=hash_type,
                            hash_value=hash_value,
                            threat_name=ioc.threat_name,
                            severity=ioc.severity,
                        )
                        matches.append(match)

                        severity_tag = match.severity.upper()
                        logger.warning(
                            "MATCH FOUND: %s\n"
                            "                                Hash Type : %s\n"
                            "                                Hash      : %s\n"
                            "                                Threat    : %s\n"
                            "                                Severity  : %s",
                            file_path,
                            hash_type.upper(),
                            hash_value,
                            ioc.threat_name,
                            severity_tag,
                        )

            except PermissionError:
                logger.debug("Permission denied: %s", file_path)
                errors += 1
            except OSError as exc:
                logger.debug("Error reading %s: %s", file_path, exc)
                errors += 1

    if errors > 0:
        logger.info("Skipped %d files due to read errors", errors)

    return files_scanned, matches


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_report(
    target_dir: str,
    feed_path: str,
    scan_start: float,
    scan_end: float,
    files_scanned: int,
    ioc_count: int,
    matches: List[ScanMatch],
) -> ScanReport:
    """Build a structured scan report.

    Args:
        target_dir: The directory that was scanned.
        feed_path: Path to the IOC feed used.
        scan_start: Scan start timestamp (time.time()).
        scan_end: Scan end timestamp (time.time()).
        files_scanned: Number of files hashed.
        ioc_count: Number of IOC entries loaded.
        matches: List of ScanMatch objects.

    Returns:
        A ScanReport dataclass instance.
    """
    duration = round(scan_end - scan_start, 2)
    start_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan_start))
    end_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan_end))

    # Sort matches by severity (critical first)
    sorted_matches = sorted(
        matches,
        key=lambda m: SEVERITY_ORDER.get(m.severity, 0),
        reverse=True,
    )

    return ScanReport(
        target_directory=target_dir,
        ioc_feed_file=feed_path,
        scan_start=start_str,
        scan_end=end_str,
        scan_duration_seconds=duration,
        total_files_scanned=files_scanned,
        total_ioc_entries=ioc_count,
        total_matches=len(matches),
        matches=[asdict(m) for m in sorted_matches],
    )


def print_summary(report: ScanReport) -> None:
    """Print a formatted summary of the scan to stdout.

    Args:
        report: The completed ScanReport.
    """
    print("\n" + "=" * 62)
    print("                    IOC SCAN SUMMARY")
    print("=" * 62)
    print(f"  Target           : {report.target_directory}")
    print(f"  IOC feed         : {report.ioc_feed_file}")
    print(f"  Scan start       : {report.scan_start}")
    print(f"  Scan end         : {report.scan_end}")
    print(f"  Duration         : {report.scan_duration_seconds}s")
    print(f"  Files scanned    : {report.total_files_scanned}")
    print(f"  IOC entries      : {report.total_ioc_entries}")
    print(f"  Matches found    : {report.total_matches}")

    if report.total_matches > 0:
        print("-" * 62)
        print("  MATCHED FILES:")
        for match in report.matches:
            severity = match["severity"].upper()
            print(f"    [{severity}] {match['file_path']}")
            print(f"           {match['hash_type'].upper()}: {match['hash_value']}")
            print(f"           Threat: {match['threat_name']}")

    print("=" * 62 + "\n")


def save_report(report: ScanReport, output_path: str, logger: logging.Logger) -> None:
    """Save the scan report as a JSON file.

    Args:
        report: The completed ScanReport.
        output_path: File path for the JSON output.
        logger: Logger instance.
    """
    report_dict = asdict(report)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)
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
        description="IOC Scanner - Scan files against Indicator of Compromise feeds",
        epilog=(
            "Example: python ioc_scanner.py --target /var/log "
            "--ioc-feed sample_data/sample_ioc_feed.csv --output report.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="Target directory to scan recursively",
    )
    parser.add_argument(
        "--ioc-feed",
        "-i",
        required=True,
        help="Path to IOC feed CSV file (columns: hash, type, threat_name, severity)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path for JSON report (optional)",
    )
    parser.add_argument(
        "--hash-types",
        nargs="+",
        choices=sorted(SUPPORTED_HASH_TYPES),
        default=None,
        help="Hash types to compute (default: all). Options: md5, sha1, sha256",
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
    """Main entry point for the IOC scanner.

    Returns:
        Exit code: 0 for clean scan, 1 for matches found, 2 for errors.
    """
    args = parse_arguments()
    logger = configure_logging(verbose=args.verbose)

    logger.info("IOC Scanner starting...")

    # Validate target directory
    target_dir = os.path.abspath(args.target)
    if not os.path.isdir(target_dir):
        logger.error("Target directory does not exist: %s", target_dir)
        return 2

    # Load IOC feed
    try:
        ioc_lookup = load_ioc_feed(args.ioc_feed, logger)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Failed to load IOC feed: %s", exc)
        return 2

    if not ioc_lookup:
        logger.warning("IOC feed is empty -- nothing to compare against.")
        return 0

    # Determine hash types
    hash_types = set(args.hash_types) if args.hash_types else None

    logger.info(
        "Scanning %s against %d IOC entries...", target_dir, len(ioc_lookup)
    )

    # Run scan
    scan_start = time.time()
    try:
        files_scanned, matches = scan_directory(
            target_dir, ioc_lookup, hash_types, logger
        )
    except NotADirectoryError as exc:
        logger.error(str(exc))
        return 2

    scan_end = time.time()

    # Build and display report
    report = generate_report(
        target_dir=target_dir,
        feed_path=args.ioc_feed,
        scan_start=scan_start,
        scan_end=scan_end,
        files_scanned=files_scanned,
        ioc_count=len(ioc_lookup),
        matches=matches,
    )

    print_summary(report)

    # Save JSON report if requested
    if args.output:
        save_report(report, args.output, logger)

    # Exit code based on results
    if matches:
        return 1  # Matches found (useful for CI/CD gating)
    return 0


if __name__ == "__main__":
    sys.exit(main())
