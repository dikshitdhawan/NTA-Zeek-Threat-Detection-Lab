
import argparse
import csv
import math
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class DnsEvent:
    ts: float
    query: str
    rcode: str


@dataclass
class Finding:
    source: str
    resolver: str
    total: int
    unique: int
    suspicious_total: int
    suspicious_unique: int
    start: float
    end: float
    rcodes: Counter
    samples: list


def arguments():
    parser = argparse.ArgumentParser(
        description="Detect DNS tunneling-like unique-subdomain bursts in Zeek dns.log."
    )
    parser.add_argument("log_file", type=Path, help="Path to Zeek dns.log")
    parser.add_argument("--resolver", help="Optional resolver destination IP filter")
    parser.add_argument("--domain", help="Optional base-domain filter, e.g. lab.test")
    parser.add_argument("--threshold", type=int, default=50,
                        help="Unique suspicious subdomains required for alert; default: 50")
    parser.add_argument("--window", type=int, default=300,
                        help="Rolling analysis window in seconds; default: 300")
    parser.add_argument("--min-label-length", type=int, default=25,
                        help="Minimum longest-label length; default: 25")
    parser.add_argument("--min-entropy", type=float, default=3.0,
                        help="Minimum longest-label Shannon entropy; default: 3.0")
    parser.add_argument("--csv-output", type=Path, default=Path("dns_anomaly_alerts.csv"),
                        help="CSV evidence output; default: dns_anomaly_alerts.csv")
    return parser.parse_args()


def entropy(text):
    counts = Counter(text.lower())
    size = float(len(text))
    return -sum((count / size) * math.log(count / size, 2) for count in counts.values()) if text else 0.0


def suspicious(query, min_length, min_entropy):
    label = max(query.rstrip(".").split("."), key=len)
    return len(label) >= min_length and entropy(label) >= min_entropy


def read_dns_log(path, resolver_filter=None, domain_filter=None):
    if not path.exists():
        raise FileNotFoundError("Zeek dns.log not found: {}".format(path))

    required = {"ts", "id.orig_h", "id.resp_h", "query", "rcode_name"}
    fields = []
    events = defaultdict(list)
    domain = domain_filter.lower().rstrip(".") if domain_filter else None

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                missing = required.difference(fields)
                if missing:
                    raise ValueError("Missing required Zeek fields: {}".format(", ".join(sorted(missing))))
                continue
            if line.startswith("#") or not line.strip():
                continue
            if not fields:
                raise ValueError("No #fields header found in supplied dns.log")

            values = line.rstrip("\n").split("\t")
            if len(values) != len(fields):
                continue
            row = dict(zip(fields, values))

            source = row.get("id.orig_h", "")
            resolver = row.get("id.resp_h", "")
            query = row.get("query", "").lower().rstrip(".")
            if not source or not resolver or not query:
                continue
            if resolver_filter and resolver != resolver_filter:
                continue
            if domain and not (query == domain or query.endswith("." + domain)):
                continue

            try:
                event = DnsEvent(float(row["ts"]), query, row.get("rcode_name", "-"))
            except ValueError:
                continue
            events[(source, resolver)].append(event)

    for pair in events:
        events[pair].sort(key=lambda item: item.ts)
    return events


def best_window(events, window, min_length, min_entropy):
    active = deque()
    queries = Counter()
    suspicious_queries = Counter()
    rcodes = Counter()
    best = None

    for event in events:
        active.append(event)
        queries[event.query] += 1
        rcodes[event.rcode] += 1
        if suspicious(event.query, min_length, min_entropy):
            suspicious_queries[event.query] += 1

        while active and event.ts - active[0].ts > window:
            old = active.popleft()
            queries[old.query] -= 1
            if queries[old.query] == 0:
                del queries[old.query]
            rcodes[old.rcode] -= 1
            if rcodes[old.rcode] == 0:
                del rcodes[old.rcode]
            if suspicious(old.query, min_length, min_entropy):
                suspicious_queries[old.query] -= 1
                if suspicious_queries[old.query] == 0:
                    del suspicious_queries[old.query]

        current = (
            len(suspicious_queries),
            len(active),
            len(queries),
            sum(suspicious_queries.values()),
            active[0].ts,
            active[-1].ts,
            Counter(rcodes),
            sorted(suspicious_queries.keys())[:8],
        )
        if best is None or (current[0], current[1]) > (best[0], best[1]):
            best = current
    return best


def severity(count):
    if count >= 200:
        return "High"
    if count >= 100:
        return "Medium-High"
    if count >= 50:
        return "Medium"
    return "Low"


def stamp(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def state_text(counter):
    return ", ".join("{}={}".format(k, v) for k, v in counter.most_common()) or "None"


def print_alert(finding, args):
    ratio = (finding.suspicious_total / finding.total * 100) if finding.total else 0
    print("=" * 84)
    print("[ALERT] Suspicious DNS Unique-Subdomain Burst Detected")
    print("=" * 84)
    print("Severity                         : {}".format(severity(finding.suspicious_unique)))
    print("Suspected DNS Source IP          : {}".format(finding.source))
    print("DNS Resolver IP                  : {}".format(finding.resolver))
    print("Base Domain Analysed             : {}".format(args.domain or "All domains"))
    print("Total Queries in Peak Window     : {}".format(finding.total))
    print("Unique Queries in Peak Window    : {}".format(finding.unique))
    print("Suspicious Long-Label Queries    : {}".format(finding.suspicious_total))
    print("Unique Suspicious Subdomains     : {}".format(finding.suspicious_unique))
    print("Suspicious Query Ratio           : {:.2f}%".format(ratio))
    print("Configured Threshold             : {} unique suspicious subdomains".format(args.threshold))
    print("Rolling Analysis Window          : {} seconds".format(args.window))
    print("Peak Window Start                : {}".format(stamp(finding.start)))
    print("Peak Window End                  : {}".format(stamp(finding.end)))
    print("Peak Window Duration             : {:.2f} seconds".format(finding.end - finding.start))
    print("DNS Response Codes               : {}".format(state_text(finding.rcodes)))
    print("Detection Basis                  : Unique, long and high-entropy subdomain burst")
    print("ATT&CK Reference                 : T1048.003 - Exfiltration Over Alternative Protocol: DNS")
    print("Classification Note              : DNS tunneling-like anomaly; exfiltration not confirmed")
    print("Sample Suspicious Queries:")
    for item in finding.samples:
        print("  - {}".format(item))
    print("=" * 84)


def write_csv(findings, args):
    with args.csv_output.open("w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow([
            "severity", "suspected_dns_source_ip", "dns_resolver_ip", "base_domain",
            "total_queries_peak_window", "unique_queries_peak_window",
            "suspicious_long_label_queries", "unique_suspicious_subdomains",
            "threshold", "window_seconds", "window_start", "window_end",
            "dns_response_codes", "attack_reference", "classification_note"
        ])
        for finding in findings:
            writer.writerow([
                severity(finding.suspicious_unique), finding.source, finding.resolver,
                args.domain or "All domains", finding.total, finding.unique,
                finding.suspicious_total, finding.suspicious_unique, args.threshold,
                args.window, stamp(finding.start), stamp(finding.end),
                state_text(finding.rcodes),
                "T1048.003 - Exfiltration Over Alternative Protocol: DNS",
                "DNS tunneling-like anomaly; exfiltration not confirmed"
            ])


def main():
    args = arguments()
    if args.threshold < 1 or args.window < 1 or args.min_label_length < 1:
        print("[ERROR] Threshold, window and minimum label length must be positive.", file=sys.stderr)
        return 1
    try:
        pairs = read_dns_log(args.log_file, args.resolver, args.domain)
    except (FileNotFoundError, ValueError) as error:
        print("[ERROR] {}".format(error), file=sys.stderr)
        return 1

    findings = []
    for (source, resolver), events in pairs.items():
        result = best_window(events, args.window, args.min_label_length, args.min_entropy)
        if not result:
            continue
        suspicious_unique, total, unique, suspicious_total, start, end, rcodes, samples = result
        if suspicious_unique >= args.threshold:
            findings.append(Finding(source, resolver, total, unique, suspicious_total,
                                    suspicious_unique, start, end, rcodes, samples))

    findings.sort(key=lambda item: item.suspicious_unique, reverse=True)
    if not findings:
        print("[INFO] No DNS anomaly exceeded the configured threshold.")
        return 0

    for finding in findings:
        print_alert(finding, args)
    write_csv(findings, args)
    print("\n[INFO] Alert evidence exported to: {}".format(args.csv_output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
