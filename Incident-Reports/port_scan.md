# Incident Report: Full TCP Port Scan Against Windows Target

## Incident Details

| Field | Value |
|---|---|
| Incident Title | Full TCP Port Scan Detected Against Windows Target |
| Incident Category | Network Reconnaissance / Service Discovery |
| Severity | High |
| Lab Phase | Phase 2 — Port Scan Detection |
| Observation Date | 26 May 2026 |
| Suspected Scanner IP | `192.168.16.132` |
| Target IP | `192.168.16.130` |
| Primary Detection Source | Zeek `conn.log` and Python port-scan detector |
| Validation Sources | PCAP, Wireshark evidence, and Nmap service verification |
| MITRE ATT&CK Mapping | `T1046 - Network Service Discovery` |
| Environment | Isolated Host-Only virtual lab network |

## Executive Summary

During Phase 2 of the NTA Zeek Threat Detection Lab, a high-volume TCP port scan was detected against the Windows 11 target host at `192.168.16.130`. Analysis of Zeek connection telemetry identified `192.168.16.132` as the suspicious scanning source after it contacted the target across all `65,535` TCP destination ports.

The activity generated `65,747` observed TCP connections within `738.27` seconds. A Python-based detector analyzed the Zeek traffic and produced a High-severity alert after the scan exceeded the configured threshold of `50` unique destination ports within the analysis window. Nmap verification confirmed that the target exposed multiple responding services, including SSH and Windows networking services.

The evidence confirms automated reconnaissance activity. This investigation does not claim successful exploitation or compromise of the target system; the incident is documented as network service discovery that could precede follow-on attacks in a real environment.

## Scope of Analysis

This incident report covers the following investigation tasks:

- Review of packet capture collected during the scan activity.
- Identification of the scanning source from Zeek logs rather than prior lab assumptions.
- Measurement of scan breadth and connection volume.
- Analysis of Zeek connection states.
- Verification of responding services using retained Nmap output.
- Packet-level validation using Wireshark.
- Automated detection using a Python rule based on unique destination-port count.
- MITRE ATT&CK mapping and defensive recommendations.

## Lab Environment

| System | Role | Investigation Relevance |
|---|---|---|
| Kali Linux | Simulated scan source | Generated controlled TCP reconnaissance traffic |
| Windows 11 | Target system | Hosted services evaluated during the scan |
| Ubuntu Linux | Monitoring system | Captured traffic and produced Zeek telemetry |
| Host-Only Network | Isolated lab network | Kept activity controlled and separated from external networks |

## Evidence Inventory

| Artifact | Repository Location | Purpose |
|---|---|---|
| Packet Capture | [`PCAP/port_scan/port_scan.pcap`](../PCAP/port_scan/port_scan.pcap) | Raw network evidence |
| Zeek Connection Log | [`Zeek-Logs/port_scan/conn.log`](../Zeek-Logs/port_scan/conn.log) | Primary telemetry used for investigation |
| Detector Script | [`Detection-Scripts/port_scan_detect.py`](../Detection-Scripts/port_scan_detect.py) | Behavior-based port-scan detector |
| Detection Output | [`Logs/port_scan/port_scan_detection_output.txt`](../Logs/port_scan/port_scan_detection_output.txt) | Human-readable alert record |
| CSV Alert Export | [`Logs/port_scan/port_scan_alerts.csv`](../Logs/port_scan/port_scan_alerts.csv) | Structured detector output |
| Full Scan Output | [`Logs/port_scan/nmap/port_scan_full_tcp.txt`](../Logs/port_scan/nmap/port_scan_full_tcp.txt) | Retained Nmap full-scan evidence |
| Service Verification | [`Logs/port_scan/nmap/port_scan_service_verification.txt`](../Logs/port_scan/nmap/port_scan_service_verification.txt) | Verification of responding services |
| Analysis Notes | [`Analysis/port_scan_analysis.md`](../Analysis/port_scan_analysis.md) | Detailed technical investigation record |
| Screenshots | [`Screenshots/port_scan/`](../Screenshots/port_scan/) | Visual evidence supporting the incident timeline |

## Detection and Investigation Timeline

| Stage | Activity | Result |
|---|---|---|
| Visibility Validation | Confirmed monitoring system could observe traffic to the target | Traffic visibility established |
| Packet Collection | Captured traffic during the controlled scan | PCAP evidence preserved |
| Scan Activity | TCP port scanning performed against the Windows host | Reconnaissance activity recorded |
| Zeek Analysis | Processed PCAP and analyzed `conn.log` | Scanner and target relationship identified |
| Source Identification | Counted unique ports contacted per source-to-target pair | `192.168.16.132` identified as suspicious source |
| State Analysis | Reviewed connection-state distribution | Predominantly rejected probes observed |
| Service Verification | Reviewed retained Nmap service-verification output | Four open/responding services confirmed |
| Packet Validation | Reviewed PCAP in Wireshark | SYN-based probing pattern supported |
| Automated Detection | Executed Python detector on Zeek telemetry | High-severity alert generated |

## Detection Findings

### Scanner Identification

Zeek-based traffic analysis identified the following source-to-target relationship:

| Detection Indicator | Observed Result |
|---|---:|
| Suspected Scanner IP | `192.168.16.132` |
| Target IP | `192.168.16.130` |
| Unique TCP Destination Ports Probed | `65,535` |
| Total TCP Connections Observed | `65,747` |
| Observation Duration | `738.27 seconds` |
| Activity Classification | Full TCP Port Scan |

The source contacted every possible TCP destination port on the target host. This level of port enumeration is consistent with automated network reconnaissance and is not representative of ordinary system communication.

### Automated Alert Result

The final Python detector output generated the following alert:

| Alert Field | Result |
|---|---|
| Severity | High |
| Detection Basis | High unique TCP destination-port count |
| Analysis Window | `1,800 seconds` |
| Unique Ports in Peak Window | `65,535` |
| Connections in Peak Window | `65,747` |
| Configured Threshold | `50 unique ports` |
| ATT&CK Technique | `T1046 - Network Service Discovery` |

The alert output was exported as both readable text and structured CSV evidence for documentation and further review.

## Connection-State Analysis

The detector summarized the observed Zeek connection states during the consolidated scan window:

| Zeek State | Count | Interpretation |
|---|---:|---|
| `REJ` | `65,620` | Most destination ports rejected the probe, indicating closed or non-listening services. |
| `S0` | `112` | SYN attempts were observed without a complete response in the captured traffic. |
| `RSTO` | `15` | A small group of connections showed distinct reset behavior and required targeted validation. |

This distribution supports the port-scan conclusion: the source generated large-scale probing activity across the target's TCP port range, with the majority of attempts failing or being rejected.

## Verified Services on the Target

Targeted Nmap service verification was performed for ports identified during investigation as responding-service candidates. The verification evidence confirmed the following services on `192.168.16.130`:

| Port | State | Service | Verification Detail |
|---:|---|---|---|
| `22/tcp` | Open | SSH | `OpenSSH for Windows 9.5 (protocol 2.0)` |
| `135/tcp` | Open | MSRPC | `Microsoft Windows RPC` |
| `139/tcp` | Open | NetBIOS-SSN | `Microsoft Windows netbios-ssn` |
| `445/tcp` | Open | `microsoft-ds?` | Responded with SYN-ACK; Nmap retained uncertainty in service label |

The verification identified the target as a Windows system and confirmed that exposed services were reachable during the controlled assessment.

## Packet-Level Validation

Wireshark evidence was retained to validate the Zeek findings at packet level. The packet inspection supported three important observations:

| Evidence | Observation |
|---|---|
| SYN scan analysis | One source repeatedly sent TCP SYN probes to the same target while destination ports changed rapidly. |
| SYN-ACK responses | The target returned positive responses for responding services that warranted verification. |
| Rejected/reset traffic | Large numbers of unsuccessful probes matched the rejected-port behavior visible in Zeek states. |

Supporting screenshots:

- [`wireshark_syn_scan_analysis.png`](../Screenshots/port_scan/wireshark_syn_scan_analysis.png)
- [`wireshark_synack_responses.png`](../Screenshots/port_scan/wireshark_synack_responses.png)
- [`wireshark_rejected_ports.png`](../Screenshots/port_scan/wireshark_rejected_ports.png)

## Indicators of Activity

| Indicator Type | Value |
|---|---|
| Suspicious Source IP | `192.168.16.132` |
| Target IP | `192.168.16.130` |
| Protocol | TCP |
| Destination-Port Scope | `1-65535` observed |
| Confirmed Responding Ports | `22`, `135`, `139`, `445` |
| Key Behavior | One source probing the complete TCP port range of one target |
| Detection Severity | High |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Mapping Justification |
|---|---|---|---|
| Discovery | Network Service Discovery | `T1046` | The source systematically probed TCP services on the target host to identify reachable network services. |

## Severity and Impact Assessment

This event is classified as **High severity for detection and investigation purposes** because the source enumerated the complete TCP port range of the target host within a short period and identified reachable services.

The evidence establishes reconnaissance activity, not compromise. No exploit execution, unauthorized authentication, or command execution is claimed in this incident report. In a production network, however, this scan would warrant investigation because discovered services such as SSH or Windows file-sharing interfaces may be followed by password attacks, exploitation attempts, or lateral movement.

## Recommended Response Actions

| Priority | Recommendation | Reason |
|---:|---|---|
| 1 | Confirm whether ports `22`, `135`, `139`, and `445` are required on the target | Reduce unnecessary service exposure |
| 2 | Restrict administrative and file-sharing services to trusted network segments | Limit reconnaissance and follow-on access attempts |
| 3 | Create alerts for high unique destination-port counts per source-to-target pair | Detect scan behavior early |
| 4 | Correlate scan alerts with authentication failures or endpoint events | Identify escalation after reconnaissance |
| 5 | Preserve PCAP, Zeek logs, detector exports, and Nmap evidence | Maintain investigation records |
| 6 | Apply segmentation and host firewall controls where required | Reduce attack surface and scanning visibility |

## Evidence Screenshot Index

| Screenshot | Evidence Demonstrated |
|---|---|
| [`traffic_visibility_test.png`](../Screenshots/port_scan/traffic_visibility_test.png) | Monitoring visibility validation |
| [`nmap_portscan_test.png`](../Screenshots/port_scan/nmap_portscan_test.png) | Initial controlled probing |
| [`nmap_port_scan_execution.png`](../Screenshots/port_scan/nmap_port_scan_execution.png) | Port scan execution |
| [`nmap_port_scan_full_execution.png`](../Screenshots/port_scan/nmap_port_scan_full_execution.png) | Full TCP port scan |
| [`tcpdump_port_scan_capture.png`](../Screenshots/port_scan/tcpdump_port_scan_capture.png) | Raw packet collection |
| [`scanner_ip_identification.png`](../Screenshots/port_scan/scanner_ip_identification.png) | Log-based scanner identification |
| [`scanned_ports_analysis.png`](../Screenshots/port_scan/scanned_ports_analysis.png) | Destination-port evidence |
| [`connection_state_analysis.png`](../Screenshots/port_scan/connection_state_analysis.png) | Connection-state review |
| [`responding_ports_candidates.png`](../Screenshots/port_scan/responding_ports_candidates.png) | Ports selected for further validation |
| [`nmap_service_verification.png`](../Screenshots/port_scan/nmap_service_verification.png) | Verified open/responding services |
| [`wireshark_syn_scan_analysis.png`](../Screenshots/port_scan/wireshark_syn_scan_analysis.png) | Packet-level scan behavior |
| [`wireshark_synack_responses.png`](../Screenshots/port_scan/wireshark_synack_responses.png) | Packet-level responses |
| [`wireshark_rejected_ports.png`](../Screenshots/port_scan/wireshark_rejected_ports.png) | Rejected/reset packet evidence |
| [`python_peak_window_detection.png`](../Screenshots/port_scan/python_peak_window_detection.png) | Short-window automated detection |
| [`python_port_scan_alert.png`](../Screenshots/port_scan/python_port_scan_alert.png) | Final consolidated High-severity alert |

## Analyst Conclusion

The investigation confirmed a full TCP port scan from `192.168.16.132` against the Windows target at `192.168.16.130`. The suspicious source contacted all `65,535` TCP destination ports and generated `65,747` observed TCP connections in approximately twelve minutes. Zeek connection telemetry established the scan pattern, while the Python detector generated a High-severity alert and exported structured evidence. Nmap service verification confirmed that ports `22`, `135`, `139`, and `445` were open/responding on the target, and Wireshark evidence supported the packet-level scan behavior.

This case is recorded as reconnaissance activity mapped to MITRE ATT&CK technique `T1046 - Network Service Discovery`. No compromise is claimed. The incident demonstrates a complete SOC-style workflow: evidence collection, log analysis, suspicious-source identification, response validation, behavioral detection, and structured incident reporting.
