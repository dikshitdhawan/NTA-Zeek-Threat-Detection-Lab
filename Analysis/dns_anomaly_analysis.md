# DNS Anomaly Analysis Report

## Phase 03: Detection of DNS Tunneling-Like Activity

### 1. Objective

The objective of this phase was to examine DNS traffic collected through Zeek and identify behaviour that deviates from normal domain resolution activity. The focus of the analysis was on repeated queries containing long, unique and high-entropy subdomains, as such patterns may indicate the use of DNS as a covert channel for data transfer or command-and-control communication.

A custom Python-based detector was executed against the captured `dns.log` file to identify bursts of suspicious DNS query activity within a rolling time window.

---

## 2. Evidence Source

| Evidence Item | Details |
|---|---|
| Log Source | Zeek `dns.log` |
| Analysed File | `zeek-output/dns.log` |
| Detection Script | `scripts/dns_anomaly_detect.py` |
| Detection Output | `results/dns_detection_output.txt` |
| CSV Findings | `results/dns_anomaly_results.csv` |
| Analysis Phase | Phase 03 – DNS Anomaly Detection |

The Zeek DNS log was used as the primary source of evidence because it records DNS requests, responding systems, queried domains and response codes in a structured format suitable for investigation.

---

## 3. Detection Methodology

The detection script analysed DNS queries using the following indicators:

- Volume of DNS queries occurring within a short rolling analysis window.
- Number of unique subdomains observed in the same time period.
- Presence of unusually long query labels.
- High-entropy or random-looking subdomain values.
- Ratio of suspicious queries to total queries.
- Threshold breach based on the number of unique suspicious subdomains.

The configured detection threshold was:

| Detection Parameter | Configured Value |
|---|---:|
| Unique Suspicious Subdomain Threshold | 50 |
| Rolling Analysis Window | 300 seconds |

The script generated a high-severity alert when a burst of suspicious subdomains exceeded the configured threshold and displayed characteristics commonly associated with DNS tunneling-like behaviour.

---

## 4. Detection Execution

The detector was executed against the Zeek DNS log generated during the DNS anomaly simulation:

```bash
python3 scripts/dns_anomaly_detect.py \
zeek-output/dns.log \
--csv-output results/dns_anomaly_results.csv
```

To preserve terminal findings as analysis evidence, the output was also stored in a text file:

```bash
python3 scripts/dns_anomaly_detect.py \
zeek-output/dns.log \
--csv-output results/dns_anomaly_results.csv \
| tee results/dns_detection_output.txt
```

---

## 5. Alert Summary

The detector successfully generated the following alert:

> **High-Severity Alert: Suspicious DNS Unique-Subdomain Burst Detected**

| Field | Observed Value |
|---|---|
| Severity | High |
| Suspected DNS Source IP | `192.168.16.132` |
| DNS Resolver IP | `192.168.16.131` |
| Base Domain Analysed | All domains |
| Total Queries in Peak Window | 255 |
| Unique Queries in Peak Window | 253 |
| Suspicious Long-Label Queries | 250 |
| Unique Suspicious Subdomains | 250 |
| Suspicious Query Ratio | 98.04% |
| Configured Threshold | 50 unique suspicious subdomains |
| Rolling Analysis Window | 300 seconds |
| Peak Window Start | `2026-05-26 21:33:49` |
| Peak Window End | `2026-05-26 21:35:33` |
| Peak Window Duration | 104.46 seconds |
| DNS Response Codes | `NOERROR=255` |

The alert confirms that the DNS traffic was not simply a small number of unusual lookups. Instead, a concentrated burst of largely unique and suspicious subdomain queries occurred within approximately 104 seconds.

---

## 6. Suspicious Query Pattern Observed

The detector reported sample queries in the following format:

```text
chunk001-f137fa53a835cab9745e769d.lab.test
chunk002-76ea95deb667328e96c3c3d5.lab.test
chunk003-e12e9ee844dc3ae3cc219917.lab.test
chunk004-9db676c72ce855c9cd466a35.lab.test
chunk005-1d9a20f9608a323f1c37595c.lab.test
```

These requests show a consistent structure:

```text
<chunk identifier>-<random/encoded-looking value>.lab.test
```

The pattern is suspicious because legitimate DNS use generally does not create hundreds of rapidly changing, long and unique subdomains under the same activity period. The inclusion of sequential chunk identifiers combined with random-looking content is consistent with a simulation of information being divided into parts and transmitted through DNS query names.

---

## 7. Technical Analysis

### 7.1 Source and Destination Behaviour

The suspicious DNS activity originated from `192.168.16.132` and was directed toward the DNS resolver at `192.168.16.131`. This establishes the likely source system responsible for generating the unusual queries and identifies the internal resolver involved in processing them.

A total of 255 DNS requests were observed during the peak window, of which 250 were classified as suspicious based on long-label and entropy-based characteristics. The extremely high suspicious query ratio of `98.04%` shows that the observed activity was dominated by anomaly-generating requests rather than normal background resolution traffic.

### 7.2 Unique Subdomain Burst

The most significant indicator was the presence of `250` unique suspicious subdomains against a configured threshold of only `50`. The activity exceeded the threshold by five times.

| Measurement | Value |
|---|---:|
| Threshold | 50 |
| Detected Unique Suspicious Subdomains | 250 |
| Threshold Exceeded By | 200 |
| Multiple of Threshold | 5x |

A large number of unique DNS labels in a short time window is a recognised indicator of possible DNS tunneling or DNS-based data transfer because each unique query can carry a separate portion of encoded content.

### 7.3 Timing Analysis

The activity occurred between `21:33:49` and `21:35:33` on `2026-05-26`, lasting approximately `104.46 seconds`.

The short duration combined with a high number of queries indicates automated behaviour rather than ordinary user browsing. Approximately 2.44 DNS queries per second were issued during the detected peak window:

```text
255 queries / 104.46 seconds ≈ 2.44 queries per second
```

This rate, when combined with high uniqueness and encoded-looking subdomains, strengthens the assessment that the traffic represented a deliberate anomaly simulation.

### 7.4 DNS Response Analysis

All 255 observed queries received `NOERROR` responses. This indicates that the resolver processed the requests successfully rather than rejecting them or failing to resolve them.

From an analyst perspective, successful DNS responses do not prove that data was exfiltrated. However, they demonstrate that the suspicious query channel was operational during the captured activity and that the unusual requests passed through the DNS resolution process.

---

## 8. Classification and Analyst Verdict

### Detection Basis

The activity was classified as suspicious based on the combined presence of:

- A rapid burst of DNS queries within a limited time window.
- A very high number of unique subdomains.
- Long and high-entropy subdomain labels.
- Chunk-based query naming behaviour.
- A suspicious query ratio of `98.04%`.
- A five-times breach of the configured alert threshold.

### Analyst Verdict

The captured activity is assessed as a **high-confidence DNS tunneling-like anomaly** originating from `192.168.16.132` and communicating through resolver `192.168.16.131`.

The evidence strongly supports an attempted or simulated DNS-based covert communication pattern. However, the logs alone cannot confirm that real sensitive information was successfully exfiltrated. Confirmation of actual data loss would require endpoint investigation, packet payload validation, file access evidence or correlation with known sensitive data movement.

---

## 9. MITRE ATT&CK Mapping

| MITRE ATT&CK Item | Mapping |
|---|---|
| Tactic | Exfiltration |
| Technique ID | `T1048.003` |
| Technique Name | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol |
| Protocol Observed | DNS |
| Mapping Rationale | Large-scale transfer-like DNS query patterns containing repeated unique encoded-looking subdomains may indicate the use of DNS for concealed outbound data movement. |

The mapping is appropriate because DNS is a non-C2 protocol that may be abused to transmit encoded information in query labels. The detection does not confirm completed exfiltration, but it provides strong network-level indicators associated with this technique.

---

## 10. Evidence Screenshot

The terminal execution screenshot should be stored at:

```text
screenshots/dns_anomaly_detection_alert.png
```

Embed the screenshot in the repository after saving it:

![DNS Anomaly Detection Alert](../Screenshots/dns_anomaly/dns_anomaly_detection_alert.png)

**Evidence shown in the screenshot:**

- Execution of the custom Python detector.
- High-severity DNS unique-subdomain burst alert.
- Source and resolver IP addresses.
- Suspicious query ratio and threshold information.
- Peak detection timeframe.
- MITRE ATT&CK reference.
- Sample suspicious DNS queries.

---

## 11. Detection Strengths

The custom detector successfully provided several SOC-relevant capabilities:

| Capability | Observation |
|---|---|
| Automated log analysis | Parsed Zeek DNS logs without requiring manual review of every record. |
| Behavioural detection | Focused on query uniqueness, label length and entropy rather than relying only on known malicious domains. |
| Threshold-based alerting | Triggered an alert after suspicious activity exceeded a measurable configured baseline. |
| Evidence preservation | Produced both terminal findings and CSV output for investigation records. |
| ATT&CK alignment | Connected the detected activity to a recognised adversary technique. |

This approach is valuable because DNS tunneling-like behaviour may use previously unseen domains or locally generated query patterns, making simple blacklist-based detection insufficient.

---

## 12. Limitations

Although the detector accurately flagged abnormal DNS activity in this capture, the following limitations remain:

- The detector identifies suspicious behaviour but cannot independently confirm successful data exfiltration.
- High volumes of unusual DNS traffic may sometimes occur in legitimate environments, such as security testing, content delivery systems or specialised applications.
- Threshold values may require tuning when applied to larger or noisier production networks.
- DNS log analysis alone does not reveal the exact original content represented by encoded-looking query values.
- Additional endpoint and packet-level evidence would be needed for a complete incident conclusion.

These limitations are important because a SOC analyst must distinguish a strong detection signal from a final proof of compromise or data loss.

---

## 13. Recommended Response Actions

If similar traffic were observed in a real organisational network, the following actions would be recommended:

1. Isolate or closely monitor the suspected source host `192.168.16.132`.
2. Review endpoint processes and command execution history associated with DNS generation.
3. Collect packet capture data for detailed inspection of DNS requests and responses.
4. Search for repeated activity from the same host outside the identified peak window.
5. Block or monitor suspicious base domains where operationally appropriate.
6. Correlate the DNS anomaly with authentication, file access and outbound connection logs.
7. Adjust SIEM or network monitoring detections to alert on similar unique-subdomain bursts.
8. Preserve the Zeek logs, CSV results and screenshots as incident evidence.

---

## 14. Project Files Generated in This Phase

```text
phase-03-dns-anomaly/
├── dns_anomaly_analysis.md
├── scripts/
│   └── dns_anomaly_detect.py
├── results/
│   ├── dns_anomaly_results.csv
│   └── dns_detection_output.txt
├── screenshots/
│   └── dns_anomaly_detection_alert.png
└── zeek-output/
    └── dns.log
```

---

## 15. Conclusion

The DNS anomaly detection phase successfully demonstrated how Zeek logs and a custom Python detection script can be used to identify suspicious DNS communication patterns. The investigation detected 250 unique suspicious subdomains generated within a short peak period from `192.168.16.132`, exceeding the configured threshold by five times and producing a suspicious query ratio of `98.04%`.

The combination of rapid query generation, long high-entropy labels and chunk-style subdomain values provides strong evidence of DNS tunneling-like behaviour. The activity was therefore classified as a high-severity anomaly and mapped to MITRE ATT&CK technique `T1048.003`.

This phase strengthens the overall Network Traffic Analysis project by moving beyond raw packet collection and demonstrating practical detection, evidence handling, technical interpretation and incident-response thinking expected in an entry-level SOC investigation workflow.
