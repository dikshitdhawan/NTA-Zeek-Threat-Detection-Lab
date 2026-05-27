import argparse
import csv
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple


DEFAULT_THRESHOLD = 50
DEFAULT_WINDOW_SECONDS = 300
DEFAULT_CSV_OUTPUT = "port_scan_alerts.csv"


@dataclass(frozen=True)
class ConnectionEvent:
    timestamp: float
    destination_port: int
    connection_state: str


@dataclass
class ScanFinding:
    source_ip: str
    target_ip: str
    severity: str
    unique_ports_in_peak_window: int
    connections_in_peak_window: int
    peak_window_start: float
    peak_window_end: float
    peak_window_states: Counter
    sample_ports: List[int]
    total_unique_ports_observed: int
    total_connections_observed: int
    observation_start: float
    observation_end: float


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect possible TCP port scanning activity from a Zeek conn.log file."
    )
    parser.add_argument("log_file", type=Path, help="Path to Zeek conn.log.")
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help="Minimum unique TCP destination ports in the rolling window required for an alert. "
             "Default: %(default)s",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=DEFAULT_WINDOW_SECONDS,
        help="Rolling analysis window in seconds. Default: %(default)s",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Optional destination IP filter. Leave unset to detect against all targets.",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=Path(DEFAULT_CSV_OUTPUT),
        help="CSV evidence output path. Default: %(default)s",
    )
    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> None:
    if args.threshold <= 0:
        raise ValueError("--threshold must be greater than zero.")
    if args.window <= 0:
        raise ValueError("--window must be greater than zero.")
    if not args.log_file.exists():
        raise FileNotFoundError("Zeek conn.log not found: {}".format(args.log_file))


def parse_zeek_conn_log(
    log_path: Path,
    target_filter: Optional[str],
) -> Dict[Tuple[str, str], List[ConnectionEvent]]:
    required_fields = {"ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "conn_state"}
    fields: List[str] = []
    events: Dict[Tuple[str, str], List[ConnectionEvent]] = defaultdict(list)

    with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                missing = required_fields.difference(fields)
                if missing:
                    raise ValueError(
                        "Required Zeek fields missing from conn.log: {}".format(
                            ", ".join(sorted(missing))
                        )
                    )
                continue

            if line.startswith("#") or not line.strip():
                continue

            if not fields:
                raise ValueError("No #fields header found in the supplied Zeek conn.log.")

            values = line.rstrip("\n").split("\t")
            if len(values) != len(fields):
                continue

            row = dict(zip(fields, values))
            if row.get("proto") != "tcp":
                continue

            source_ip = row.get("id.orig_h", "")
            target_ip = row.get("id.resp_h", "")
            if not source_ip or not target_ip:
                continue
            if target_filter and target_ip != target_filter:
                continue

            try:
                event = ConnectionEvent(
                    timestamp=float(row["ts"]),
                    destination_port=int(row["id.resp_p"]),
                    connection_state=row.get("conn_state", "-"),
                )
            except (ValueError, KeyError):
                continue

            events[(source_ip, target_ip)].append(event)

    for pair_events in events.values():
        pair_events.sort(key=lambda item: item.timestamp)

    return events


def classify_severity(unique_ports: int) -> str:
    if unique_ports >= 10000:
        return "High"
    if unique_ports >= 1000:
        return "Medium-High"
    if unique_ports >= 50:
        return "Medium"
    return "Low"


def analyse_pair(
    source_ip: str,
    target_ip: str,
    events: List[ConnectionEvent],
    window_seconds: int,
) -> ScanFinding:
    active: Deque[ConnectionEvent] = deque()
    active_ports: Counter = Counter()
    active_states: Counter = Counter()

    peak_unique_ports = 0
    peak_connection_count = 0
    peak_start = events[0].timestamp
    peak_end = events[0].timestamp
    peak_states: Counter = Counter()
    peak_ports: List[int] = []

    for event in events:
        active.append(event)
        active_ports[event.destination_port] += 1
        active_states[event.connection_state] += 1

        while active and event.timestamp - active[0].timestamp > window_seconds:
            expired = active.popleft()

            active_ports[expired.destination_port] -= 1
            if active_ports[expired.destination_port] == 0:
                del active_ports[expired.destination_port]

            active_states[expired.connection_state] -= 1
            if active_states[expired.connection_state] == 0:
                del active_states[expired.connection_state]

        unique_ports = len(active_ports)
        connections = len(active)

        if unique_ports > peak_unique_ports or (
            unique_ports == peak_unique_ports and connections > peak_connection_count
        ):
            peak_unique_ports = unique_ports
            peak_connection_count = connections
            peak_start = active[0].timestamp
            peak_end = active[-1].timestamp
            peak_states = Counter(active_states)
            peak_ports = sorted(active_ports.keys())

    all_ports = {event.destination_port for event in events}

    return ScanFinding(
        source_ip=source_ip,
        target_ip=target_ip,
        severity=classify_severity(peak_unique_ports),
        unique_ports_in_peak_window=peak_unique_ports,
        connections_in_peak_window=peak_connection_count,
        peak_window_start=peak_start,
        peak_window_end=peak_end,
        peak_window_states=peak_states,
        sample_ports=peak_ports[:15],
        total_unique_ports_observed=len(all_ports),
        total_connections_observed=len(events),
        observation_start=events[0].timestamp,
        observation_end=events[-1].timestamp,
    )


def format_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def format_states(states: Counter) -> str:
    if not states:
        return "None"
    return ", ".join(
        "{}={}".format(state, count) for state, count in states.most_common()
    )


def print_alert(finding: ScanFinding, threshold: int, window_seconds: int) -> None:
    print("=" * 78)
    print("[ALERT] TCP Port Scan Activity Detected")
    print("=" * 78)
    print("Severity                    : {}".format(finding.severity))
    print("Suspected Scanner IP        : {}".format(finding.source_ip))
    print("Target IP                   : {}".format(finding.target_ip))
    print("Unique Ports in Peak Window : {}".format(finding.unique_ports_in_peak_window))
    print("Connections in Peak Window  : {}".format(finding.connections_in_peak_window))
    print("Configured Threshold        : {} unique ports".format(threshold))
    print("Rolling Analysis Window     : {} seconds".format(window_seconds))
    print("Peak Window Start           : {}".format(format_timestamp(finding.peak_window_start)))
    print("Peak Window End             : {}".format(format_timestamp(finding.peak_window_end)))
    print("Peak Window Duration        : {:.2f} seconds".format(
        finding.peak_window_end - finding.peak_window_start
    ))
    print("Peak Window States          : {}".format(format_states(finding.peak_window_states)))
    print("Sample Probed Ports         : {}".format(
        ", ".join(str(port) for port in finding.sample_ports)
    ))
    print("Total Unique Ports Observed : {}".format(finding.total_unique_ports_observed))
    print("Total Connections Observed  : {}".format(finding.total_connections_observed))
    print("Full Observation Duration   : {:.2f} seconds".format(
        finding.observation_end - finding.observation_start
    ))
    print("Detection Basis             : High unique TCP destination-port count")
    print("MITRE ATT&CK                : T1046 - Network Service Discovery")
    print("=" * 78)


def export_csv(
    findings: List[ScanFinding],
    output_path: Path,
    threshold: int,
    window_seconds: int,
) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "severity",
            "suspected_scanner_ip",
            "target_ip",
            "unique_ports_in_peak_window",
            "connections_in_peak_window",
            "threshold",
            "rolling_window_seconds",
            "peak_window_start",
            "peak_window_end",
            "peak_window_duration_seconds",
            "peak_window_connection_states",
            "total_unique_ports_observed",
            "total_connections_observed",
            "full_observation_duration_seconds",
            "mitre_attack",
        ])

        for finding in findings:
            writer.writerow([
                finding.severity,
                finding.source_ip,
                finding.target_ip,
                finding.unique_ports_in_peak_window,
                finding.connections_in_peak_window,
                threshold,
                window_seconds,
                format_timestamp(finding.peak_window_start),
                format_timestamp(finding.peak_window_end),
                "{:.2f}".format(finding.peak_window_end - finding.peak_window_start),
                format_states(finding.peak_window_states),
                finding.total_unique_ports_observed,
                finding.total_connections_observed,
                "{:.2f}".format(finding.observation_end - finding.observation_start),
                "T1046 - Network Service Discovery",
            ])


def main() -> int:
    args = parse_arguments()

    try:
        validate_arguments(args)
        pair_events = parse_zeek_conn_log(args.log_file, args.target)
    except (FileNotFoundError, ValueError) as error:
        print("[ERROR] {}".format(error), file=sys.stderr)
        return 1

    findings: List[ScanFinding] = []

    for (source_ip, target_ip), events in pair_events.items():
        finding = analyse_pair(source_ip, target_ip, events, args.window)
        if finding.unique_ports_in_peak_window >= args.threshold:
            findings.append(finding)

    findings.sort(
        key=lambda finding: finding.unique_ports_in_peak_window,
        reverse=True,
    )

    if not findings:
        print("[INFO] No TCP port scan exceeded the configured threshold.")
        print("[INFO] Threshold: {} unique ports within {} seconds.".format(
            args.threshold, args.window
        ))
        return 0

    for finding in findings:
        print_alert(finding, args.threshold, args.window)

    export_csv(findings, args.csv_output, args.threshold, args.window)
    print("\n[INFO] Alert evidence exported to: {}".format(args.csv_output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
