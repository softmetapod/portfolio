#!/usr/bin/env python3
"""
Security Log Analyzer - Linux Auth Log Parser and Threat Detector

Parses Linux authentication logs (auth.log, syslog) and detects security-
relevant events: brute-force login attempts, privilege escalation, SSH
anomalies, successful logins after failures, and account lockouts.

Author: Jacob Phillips | Cloud Security Engineer
Certifications: SC-200, Security+

Usage:
    python log_analyzer.py --logfile /var/log/auth.log
    python log_analyzer.py --logfile /var/log/auth.log --threshold 3 --window 300
    python log_analyzer.py --logfile /var/log/auth.log --output findings.json
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default detection thresholds
DEFAULT_BRUTE_FORCE_THRESHOLD: int = 5
DEFAULT_TIME_WINDOW_SECONDS: int = 600  # 10 minutes

# Current year fallback (auth.log does not include year)
CURRENT_YEAR: int = datetime.now().year

# Common auth.log timestamp format: "Jan 15 09:23:41"
TIMESTAMP_PATTERN: str = r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

# Detection patterns
PATTERNS = {
    "failed_login": re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
        re.IGNORECASE,
    ),
    "successful_login": re.compile(
        r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)",
        re.IGNORECASE,
    ),
    "ssh_disconnect": re.compile(
        r"Disconnected from (?:authenticating )?user (\S+) (\S+) port (\d+)",
        re.IGNORECASE,
    ),
    "sudo_command": re.compile(
        r"(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)",
        re.IGNORECASE,
    ),
    "sudo_failure": re.compile(
        r"(\S+)\s*:\s*.*authentication failure.*",
        re.IGNORECASE,
    ),
    "account_lockout": re.compile(
        r"pam_tally2?\(.*\):\s*account (\S+).*locked",
        re.IGNORECASE,
    ),
    "account_lockout_faillock": re.compile(
        r"pam_faillock\(.*\):\s*Consecutive login failures for user (\S+)",
        re.IGNORECASE,
    ),
    "session_opened": re.compile(
        r"session opened for user (\S+)",
        re.IGNORECASE,
    ),
    "session_closed": re.compile(
        r"session closed for user (\S+)",
        re.IGNORECASE,
    ),
    "invalid_user": re.compile(
        r"Invalid user (\S+) from (\S+)",
        re.IGNORECASE,
    ),
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class LogEvent:
    """Represents a single parsed log event."""

    timestamp: Optional[datetime]
    raw_line: str
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[str] = None
    detail: Optional[str] = None


@dataclass
class BruteForceAlert:
    """Alert for detected brute-force activity."""

    source_ip: str
    attempt_count: int
    time_window_seconds: int
    first_attempt: str
    last_attempt: str
    targeted_users: List[str]


@dataclass
class LoginAfterFailureAlert:
    """Alert for successful login after prior failures."""

    username: str
    source_ip: str
    login_time: str
    prior_failure_count: int


@dataclass
class SudoEvent:
    """A recorded sudo/privilege escalation event."""

    timestamp: str
    invoking_user: str
    target_user: str
    command: str


@dataclass
class AnalysisReport:
    """Complete analysis report."""

    log_file: str
    lines_parsed: int
    time_range_start: Optional[str]
    time_range_end: Optional[str]
    analysis_timestamp: str
    thresholds: dict
    summary: dict
    brute_force_alerts: List[dict]
    login_after_failure_alerts: List[dict]
    sudo_events: List[dict]
    account_lockouts: List[str]
    flagged_ips: List[str]
    ssh_source_ips: List[str]
    invalid_usernames: List[str]


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
    logger = logging.getLogger("log_analyzer")
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
# Timestamp parsing
# ---------------------------------------------------------------------------


def parse_syslog_timestamp(line: str) -> Optional[datetime]:
    """Extract and parse the syslog-style timestamp from a log line.

    Syslog timestamps lack a year, so the current year is assumed.

    Args:
        line: A raw log line.

    Returns:
        A datetime object if parsing succeeded, otherwise None.
    """
    match = re.match(TIMESTAMP_PATTERN, line)
    if not match:
        return None

    timestamp_str = match.group(1)
    try:
        dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        return dt.replace(year=CURRENT_YEAR)
    except ValueError:
        # Handle double-space day padding ("Jan  5")
        try:
            dt = datetime.strptime(timestamp_str, "%b  %d %H:%M:%S")
            return dt.replace(year=CURRENT_YEAR)
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Log parser
# ---------------------------------------------------------------------------


def parse_log_file(
    log_path: str, logger: logging.Logger
) -> Tuple[List[LogEvent], int]:
    """Parse a log file and extract security-relevant events.

    Args:
        log_path: Path to the auth.log or syslog file.
        logger: Logger instance.

    Returns:
        Tuple of (list of LogEvent objects, total lines parsed).

    Raises:
        FileNotFoundError: If the log file does not exist.
    """
    if not os.path.isfile(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")

    events: List[LogEvent] = []
    lines_parsed: int = 0

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            lines_parsed += 1
            timestamp = parse_syslog_timestamp(line)

            # Check each pattern
            for event_type, pattern in PATTERNS.items():
                match = pattern.search(line)
                if not match:
                    continue

                event = _build_event(event_type, match, timestamp, line)
                if event:
                    events.append(event)
                    break  # Only match first pattern per line

    logger.info("Parsed %d lines, extracted %d events", lines_parsed, len(events))
    return events, lines_parsed


def _build_event(
    event_type: str,
    match: re.Match,
    timestamp: Optional[datetime],
    raw_line: str,
) -> Optional[LogEvent]:
    """Build a LogEvent from a regex match.

    Args:
        event_type: The type/name of the matched pattern.
        match: The regex match object.
        timestamp: Parsed timestamp or None.
        raw_line: The original log line.

    Returns:
        A LogEvent instance, or None if the match could not be parsed.
    """
    groups = match.groups()

    if event_type == "failed_login":
        return LogEvent(
            timestamp=timestamp,
            raw_line=raw_line,
            event_type=event_type,
            username=groups[0],
            source_ip=groups[1],
            source_port=groups[2],
        )

    if event_type == "successful_login":
        return LogEvent(
            timestamp=timestamp,
            raw_line=raw_line,
            event_type=event_type,
            username=groups[0],
            source_ip=groups[1],
            source_port=groups[2],
        )

    if event_type == "sudo_command":
        return LogEvent(
            timestamp=timestamp,
            raw_line=raw_line,
            event_type=event_type,
            username=groups[0],
            detail=f"USER={groups[1]} COMMAND={groups[2].strip()}",
        )

    if event_type == "sudo_failure":
        return LogEvent(
            timestamp=timestamp,
            raw_line=raw_line,
            event_type=event_type,
            username=groups[0],
        )

    if event_type in ("account_lockout", "account_lockout_faillock"):
        return LogEvent(
            timestamp=timestamp,
            raw_line=raw_line,
            event_type="account_lockout",
            username=groups[0],
        )

    if event_type == "invalid_user":
        return LogEvent(
            timestamp=timestamp,
            raw_line=raw_line,
            event_type=event_type,
            username=groups[0],
            source_ip=groups[1],
        )

    if event_type in ("session_opened", "session_closed"):
        return LogEvent(
            timestamp=timestamp,
            raw_line=raw_line,
            event_type=event_type,
            username=groups[0],
        )

    if event_type == "ssh_disconnect":
        return LogEvent(
            timestamp=timestamp,
            raw_line=raw_line,
            event_type=event_type,
            username=groups[0],
            source_ip=groups[1],
            source_port=groups[2],
        )

    return None


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------


def detect_brute_force(
    events: List[LogEvent],
    threshold: int,
    window_seconds: int,
    logger: logging.Logger,
) -> List[BruteForceAlert]:
    """Detect brute-force login attempts by source IP.

    Groups failed login events by source IP and checks if the number
    of failures within any sliding time window exceeds the threshold.

    Args:
        events: List of all parsed log events.
        threshold: Minimum number of failures to trigger an alert.
        window_seconds: Time window in seconds for grouping attempts.
        logger: Logger instance.

    Returns:
        List of BruteForceAlert objects.
    """
    # Group failed logins by source IP
    failures_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "failed_login" and event.source_ip:
            failures_by_ip[event.source_ip].append(event)

    alerts: List[BruteForceAlert] = []

    for ip, fails in failures_by_ip.items():
        # Sort by timestamp
        timed_fails = [f for f in fails if f.timestamp is not None]
        timed_fails.sort(key=lambda e: e.timestamp)

        if len(timed_fails) < threshold:
            # Even without timing, check total count
            if len(fails) >= threshold:
                users = list({f.username for f in fails if f.username})
                alert = BruteForceAlert(
                    source_ip=ip,
                    attempt_count=len(fails),
                    time_window_seconds=window_seconds,
                    first_attempt="unknown",
                    last_attempt="unknown",
                    targeted_users=users,
                )
                alerts.append(alert)
            continue

        # Sliding window check
        window = timedelta(seconds=window_seconds)
        i = 0
        max_count = 0
        best_start = 0
        best_end = 0

        for j in range(len(timed_fails)):
            while timed_fails[j].timestamp - timed_fails[i].timestamp > window:
                i += 1
            count = j - i + 1
            if count > max_count:
                max_count = count
                best_start = i
                best_end = j

        if max_count >= threshold:
            users = list(
                {f.username for f in timed_fails[best_start : best_end + 1] if f.username}
            )
            alert = BruteForceAlert(
                source_ip=ip,
                attempt_count=max_count,
                time_window_seconds=window_seconds,
                first_attempt=timed_fails[best_start].timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                last_attempt=timed_fails[best_end].timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                targeted_users=users,
            )
            alerts.append(alert)
            logger.warning(
                "BRUTE FORCE: %s - %d failed attempts in %ds",
                ip,
                max_count,
                window_seconds,
            )

    return alerts


def detect_login_after_failure(
    events: List[LogEvent], logger: logging.Logger
) -> List[LoginAfterFailureAlert]:
    """Detect successful logins from IPs that previously had failures.

    Args:
        events: List of all parsed log events.
        logger: Logger instance.

    Returns:
        List of LoginAfterFailureAlert objects.
    """
    # Track failure counts per (user, ip)
    failure_counts: Dict[Tuple[str, str], int] = defaultdict(int)
    alerts: List[LoginAfterFailureAlert] = []

    # Process events in order
    timed_events = sorted(
        [e for e in events if e.timestamp],
        key=lambda e: e.timestamp,
    )

    for event in timed_events:
        if event.event_type == "failed_login" and event.username and event.source_ip:
            failure_counts[(event.username, event.source_ip)] += 1

        elif (
            event.event_type == "successful_login"
            and event.username
            and event.source_ip
        ):
            key = (event.username, event.source_ip)
            if failure_counts.get(key, 0) > 0:
                ts = (
                    event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    if event.timestamp
                    else "unknown"
                )
                alert = LoginAfterFailureAlert(
                    username=event.username,
                    source_ip=event.source_ip,
                    login_time=ts,
                    prior_failure_count=failure_counts[key],
                )
                alerts.append(alert)
                logger.warning(
                    "LOGIN AFTER FAILURES: User '%s' from %s after %d failures",
                    event.username,
                    event.source_ip,
                    failure_counts[key],
                )

    return alerts


def extract_sudo_events(events: List[LogEvent]) -> List[SudoEvent]:
    """Extract privilege escalation (sudo) events.

    Args:
        events: List of all parsed log events.

    Returns:
        List of SudoEvent objects.
    """
    sudo_events: List[SudoEvent] = []

    for event in events:
        if event.event_type == "sudo_command" and event.detail:
            ts = (
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if event.timestamp
                else "unknown"
            )
            # Parse USER and COMMAND from detail
            parts = event.detail.split(" COMMAND=")
            target_user = parts[0].replace("USER=", "") if parts else "unknown"
            command = parts[1] if len(parts) > 1 else "unknown"

            sudo_events.append(
                SudoEvent(
                    timestamp=ts,
                    invoking_user=event.username or "unknown",
                    target_user=target_user,
                    command=command,
                )
            )

    return sudo_events


def extract_account_lockouts(events: List[LogEvent]) -> List[str]:
    """Extract unique locked-out account names.

    Args:
        events: List of all parsed log events.

    Returns:
        List of locked-out usernames.
    """
    locked = set()
    for event in events:
        if event.event_type == "account_lockout" and event.username:
            locked.add(event.username)
    return sorted(locked)


def extract_ssh_source_ips(events: List[LogEvent]) -> List[str]:
    """Extract unique source IPs from SSH login events.

    Args:
        events: List of all parsed log events.

    Returns:
        Sorted list of unique SSH source IPs.
    """
    ips: Set[str] = set()
    for event in events:
        if event.event_type in ("successful_login", "failed_login") and event.source_ip:
            ips.add(event.source_ip)
    return sorted(ips)


def extract_invalid_usernames(events: List[LogEvent]) -> List[str]:
    """Extract unique invalid usernames attempted.

    Args:
        events: List of all parsed log events.

    Returns:
        Sorted list of unique invalid usernames.
    """
    users: Set[str] = set()
    for event in events:
        if event.event_type == "invalid_user" and event.username:
            users.add(event.username)
    return sorted(users)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def build_report(
    log_path: str,
    lines_parsed: int,
    events: List[LogEvent],
    brute_force_alerts: List[BruteForceAlert],
    login_after_failure_alerts: List[LoginAfterFailureAlert],
    sudo_events: List[SudoEvent],
    lockouts: List[str],
    ssh_ips: List[str],
    invalid_users: List[str],
    threshold: int,
    window: int,
) -> AnalysisReport:
    """Build the final analysis report.

    Args:
        log_path: Path to the analyzed log file.
        lines_parsed: Total lines parsed.
        events: All extracted log events.
        brute_force_alerts: Detected brute-force alerts.
        login_after_failure_alerts: Detected login-after-failure alerts.
        sudo_events: Extracted sudo events.
        lockouts: Locked-out account names.
        ssh_ips: All SSH source IPs.
        invalid_users: Invalid usernames attempted.
        threshold: Brute-force threshold used.
        window: Time window used.

    Returns:
        An AnalysisReport instance.
    """
    # Determine time range
    timestamps = [e.timestamp for e in events if e.timestamp]
    time_start = min(timestamps).strftime("%Y-%m-%d %H:%M:%S") if timestamps else None
    time_end = max(timestamps).strftime("%Y-%m-%d %H:%M:%S") if timestamps else None

    # Summary counts
    failed_count = sum(1 for e in events if e.event_type == "failed_login")
    success_count = sum(1 for e in events if e.event_type == "successful_login")
    sudo_count = len(sudo_events)

    # Flagged IPs = those involved in brute-force alerts
    flagged_ips = sorted({a.source_ip for a in brute_force_alerts})

    return AnalysisReport(
        log_file=log_path,
        lines_parsed=lines_parsed,
        time_range_start=time_start,
        time_range_end=time_end,
        analysis_timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        thresholds={
            "brute_force_threshold": threshold,
            "time_window_seconds": window,
        },
        summary={
            "total_events_extracted": len(events),
            "failed_logins": failed_count,
            "successful_logins": success_count,
            "sudo_events": sudo_count,
            "account_lockouts": len(lockouts),
            "brute_force_alerts": len(brute_force_alerts),
            "login_after_failure_alerts": len(login_after_failure_alerts),
            "unique_ssh_source_ips": len(ssh_ips),
            "invalid_usernames_attempted": len(invalid_users),
        },
        brute_force_alerts=[asdict(a) for a in brute_force_alerts],
        login_after_failure_alerts=[asdict(a) for a in login_after_failure_alerts],
        sudo_events=[asdict(e) for e in sudo_events],
        account_lockouts=lockouts,
        flagged_ips=flagged_ips,
        ssh_source_ips=ssh_ips,
        invalid_usernames=invalid_users,
    )


def print_report(report: AnalysisReport) -> None:
    """Print a formatted report to the console.

    Args:
        report: The completed AnalysisReport.
    """
    print("\n" + "=" * 62)
    print("              SECURITY LOG ANALYSIS REPORT")
    print("=" * 62)
    print(f"  Log file         : {report.log_file}")
    print(f"  Lines parsed     : {report.lines_parsed:,}")
    if report.time_range_start and report.time_range_end:
        print(f"  Time range       : {report.time_range_start} -> {report.time_range_end}")
    print(f"  Analysis time    : {report.analysis_timestamp}")
    print("-" * 62)

    s = report.summary
    print(f"  Events extracted : {s['total_events_extracted']}")
    print(f"  Failed logins    : {s['failed_logins']}")
    print(f"  Successful logins: {s['successful_logins']}")
    print(f"  Sudo events      : {s['sudo_events']}")
    print(f"  Account lockouts : {s['account_lockouts']}")
    print(f"  Unique SSH IPs   : {s['unique_ssh_source_ips']}")

    # Brute force alerts
    print("\n" + "-" * 62)
    print("  [BRUTE FORCE DETECTION]")
    if report.brute_force_alerts:
        for alert in report.brute_force_alerts:
            print(
                f"    ALERT: {alert['source_ip']} - {alert['attempt_count']} failed "
                f"attempts in {alert['time_window_seconds']}s "
                f"(threshold: {report.thresholds['brute_force_threshold']})"
            )
            print(f"           Users targeted: {', '.join(alert['targeted_users'])}")
            print(f"           Window: {alert['first_attempt']} -> {alert['last_attempt']}")
    else:
        print("    No brute-force activity detected.")

    # Login after failure
    print("\n  [SUCCESSFUL LOGIN AFTER FAILURES]")
    if report.login_after_failure_alerts:
        for alert in report.login_after_failure_alerts:
            print(
                f"    WARNING: User '{alert['username']}' logged in from "
                f"{alert['source_ip']} after {alert['prior_failure_count']} failures"
            )
            print(f"             Login time: {alert['login_time']}")
    else:
        print("    No suspicious post-failure logins detected.")

    # Privilege escalation
    print("\n  [PRIVILEGE ESCALATION]")
    if report.sudo_events:
        unique_sudo_users = {e["invoking_user"] for e in report.sudo_events}
        print(
            f"    INFO: {len(report.sudo_events)} sudo events across "
            f"{len(unique_sudo_users)} user(s)"
        )
        for event in report.sudo_events:
            print(
                f"      [{event['timestamp']}] {event['invoking_user']} -> "
                f"{event['target_user']}: {event['command']}"
            )
    else:
        print("    No sudo events detected.")

    # Account lockouts
    print("\n  [ACCOUNT LOCKOUTS]")
    if report.account_lockouts:
        for user in report.account_lockouts:
            print(f"    ALERT: Account locked - {user}")
    else:
        print("    No account lockouts detected.")

    # SSH patterns
    print("\n  [SSH PATTERNS]")
    print(f"    Unique source IPs: {len(report.ssh_source_ips)}")
    if report.flagged_ips:
        for ip in report.flagged_ips:
            print(f"    WARNING: SSH activity from flagged IP - {ip}")

    # Invalid usernames
    if report.invalid_usernames:
        print(f"\n  [INVALID USERNAMES ATTEMPTED]")
        print(f"    {', '.join(report.invalid_usernames)}")

    # Totals
    alert_count = (
        len(report.brute_force_alerts) + len(report.account_lockouts)
    )
    warning_count = len(report.login_after_failure_alerts) + len(report.flagged_ips)
    print("\n" + "-" * 62)
    print(f"  Total alerts   : {alert_count}")
    print(f"  Total warnings : {warning_count}")
    print("=" * 62 + "\n")


def save_report(
    report: AnalysisReport, output_path: str, logger: logging.Logger
) -> None:
    """Save the analysis report as a JSON file.

    Args:
        report: The completed AnalysisReport.
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
        description="Security Log Analyzer - Parse auth logs and detect threats",
        epilog=(
            "Example: python log_analyzer.py --logfile /var/log/auth.log "
            "--threshold 5 --window 600 --output findings.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--logfile",
        "-l",
        required=True,
        help="Path to the auth.log or syslog file to analyze",
    )
    parser.add_argument(
        "--threshold",
        "-t",
        type=int,
        default=DEFAULT_BRUTE_FORCE_THRESHOLD,
        help=f"Failed login threshold for brute-force detection (default: {DEFAULT_BRUTE_FORCE_THRESHOLD})",
    )
    parser.add_argument(
        "--window",
        "-w",
        type=int,
        default=DEFAULT_TIME_WINDOW_SECONDS,
        help=f"Time window in seconds for brute-force grouping (default: {DEFAULT_TIME_WINDOW_SECONDS})",
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
    """Main entry point for the log analyzer.

    Returns:
        Exit code: 0 for no alerts, 1 for alerts found, 2 for errors.
    """
    args = parse_arguments()
    logger = configure_logging(verbose=args.verbose)

    logger.info("Security Log Analyzer starting...")

    # Parse log file
    try:
        events, lines_parsed = parse_log_file(args.logfile, logger)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return 2

    if not events:
        logger.warning("No security-relevant events found in %s", args.logfile)

    # Run detections
    brute_force_alerts = detect_brute_force(
        events, args.threshold, args.window, logger
    )
    login_after_failure_alerts = detect_login_after_failure(events, logger)
    sudo_events = extract_sudo_events(events)
    lockouts = extract_account_lockouts(events)
    ssh_ips = extract_ssh_source_ips(events)
    invalid_users = extract_invalid_usernames(events)

    # Build and display report
    report = build_report(
        log_path=args.logfile,
        lines_parsed=lines_parsed,
        events=events,
        brute_force_alerts=brute_force_alerts,
        login_after_failure_alerts=login_after_failure_alerts,
        sudo_events=sudo_events,
        lockouts=lockouts,
        ssh_ips=ssh_ips,
        invalid_users=invalid_users,
        threshold=args.threshold,
        window=args.window,
    )

    print_report(report)

    # Save JSON report if requested
    if args.output:
        save_report(report, args.output, logger)

    # Exit code based on findings
    has_alerts = bool(brute_force_alerts or login_after_failure_alerts or lockouts)
    return 1 if has_alerts else 0


if __name__ == "__main__":
    sys.exit(main())
