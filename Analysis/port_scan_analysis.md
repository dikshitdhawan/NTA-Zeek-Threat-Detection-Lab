# Port Scan Analysis — Phase 2

## What I Investigated

This phase focuses on TCP port scanning against the Windows target in my isolated lab network. The goal was not just to run Nmap and capture a screenshot, but to investigate the activity the way a SOC analyst would: capture the traffic, identify the suspicious source from logs, validate the packet behavior, and create a detection rule that can alert on similar activity.

## Lab Setup Used for This Case

| System | Role | IP Address Observed in Evidence |
|---|---|---|
| Kali Linux | Scan source identified during analysis | `192.168.16.132` |
| Windows 11 | Target host | `192.168.16.130` |
| Ubuntu | Monitoring and analysis system | Captured traffic and generated Zeek logs |

All testing was carried out in a controlled Host-Only virtual network.

## Evidence Used

| Artifact | Location in Repository | Why It Matters |
|---|---|---|
| Packet capture | `PCAP/port_scan/port_scan.pcap` | Raw traffic captured during the scan |
| Zeek connection log | `Zeek-Logs/port_scan/conn.log` | Main source for identifying scanner, target, ports, and connection states |
| Detection script | `Detection-Scripts/port_scan_detect.py` | Automated behavior-based port-scan detector |
| Detector output | `Logs/port_scan/port_scan_detection_output.txt` | Saved alert output |
| CSV alert evidence | `Logs/port_scan/port_scan_alerts.csv` | Structured evidence exported by the detector |
| Nmap scan outputs | `Logs/port_scan/nmap/` | Scan execution and service-verification results |
| Screenshots | `Screenshots/port_scan/` | Visual evidence of analysis and validation steps |

## How the Scanner Was Identified

I did not begin the analysis by labeling the Kali machine as the attacker. Instead, I used Zeek `conn.log` to identify the source that contacted the highest number of unique TCP destination ports on the Windows host.

The Zeek analysis showed:

| Finding | Result |
|---|---|
| Suspicious source IP | `192.168.16.132` |
| Target IP | `192.168.16.130` |
| Unique TCP ports contacted | `65,535` |
| Total TCP connections recorded | `65,747` |

A source communicating with one target across the entire TCP port range is not normal user activity. This is sufficient to classify the behavior as an automated full TCP port scan.

Supporting screenshot: [`scanner_ip_identification.png`](../Screenshots/port_scan/scanner_ip_identification.png)

## Connection-State Review

The final detector output summarized the following Zeek connection states across the scan:

| Zeek State | Count | Interpretation |
|---|---:|---|
| `REJ` | `65,620` | Most probes were rejected, consistent with closed or non-listening ports. |
| `S0` | `112` | Attempts were observed without a completed response in the captured traffic. |
| `RSTO` | `15` | A small set of connections behaved differently and required verification. |

This state distribution matches a scan pattern: a very large number of probes against unavailable ports, with only a small number of ports showing different response behavior.

Supporting screenshots:

- [`connection_state_analysis.png`](../Screenshots/port_scan/connection_state_analysis.png)
- [`responding_ports_candidates.png`](../Screenshots/port_scan/responding_ports_candidates.png)

## Service Verification

After identifying the ports that behaved differently from the majority of rejected probes, I used targeted Nmap service detection to verify the exposed services on the Windows host.

The verification scan confirmed:

| Port | State | Service | Identified Version / Detail |
|---:|---|---|---|
| `22/tcp` | Open | SSH | `OpenSSH for Windows 9.5` |
| `135/tcp` | Open | MSRPC | `Microsoft Windows RPC` |
| `139/tcp` | Open | NetBIOS-SSN | `Microsoft Windows netbios-ssn` |
| `445/tcp` | Open | `microsoft-ds?` | Service identified with uncertainty by Nmap |

The Nmap output identified the target operating system as Windows and reported SYN-ACK responses for these open ports. Port `445/tcp` is recorded exactly as identified by Nmap, including the uncertainty marker, rather than being overstated as a fully confirmed service type.

Raw verification output: [`port_scan_service_verification.txt`](../Logs/port_scan/nmap/port_scan_service_verification.txt)

Supporting screenshot: [`nmap_service_verification.png`](../Screenshots/port_scan/nmap_service_verification.png)

## Wireshark Validation

Zeek provided the structured detection evidence, while Wireshark was used to validate the traffic pattern at packet level.

The packet capture showed:

- repeated TCP SYN probes from `192.168.16.132` to `192.168.16.130`;
- rapidly changing destination ports, consistent with service discovery;
- SYN-ACK responses associated with responding services;
- reset/rejection behavior for ports that did not accept the probes.

Supporting screenshots:

- [`wireshark_syn_scan_analysis.png`](../Screenshots/port_scan/wireshark_syn_scan_analysis.png)
- [`wireshark_synack_responses.png`](../Screenshots/port_scan/wireshark_synack_responses.png)
- [`wireshark_rejected_ports.png`](../Screenshots/port_scan/wireshark_rejected_ports.png)

## Automated Detection

To move beyond manual log review, I created a Python detector that processes Zeek `conn.log` and evaluates TCP behavior per source-to-target pair. The script does not require a pre-defined attacker IP. It detects a possible scan when a source contacts more unique destination ports than the configured threshold within the selected analysis window.

For the final consolidated analysis, the detector produced:

| Alert Field | Result |
|---|---|
| Severity | High |
| Suspected scanner IP | `192.168.16.132` |
| Target IP | `192.168.16.130` |
| Unique ports in analysis window | `65,535` |
| Connections in analysis window | `65,747` |
| Threshold | `50 unique ports` |
| Window configured | `1,800 seconds` |
| Observed duration | `738.27 seconds` |
| ATT&CK mapping | `T1046 - Network Service Discovery` |

The detector also exports alert results as CSV so the evidence can be retained outside terminal screenshots.

Supporting evidence:

- [`port_scan_detect.py`](../Detection-Scripts/port_scan_detect.py)
- [`port_scan_detection_output.txt`](../Logs/port_scan/port_scan_detection_output.txt)
- [`port_scan_alerts.csv`](../Logs/port_scan/port_scan_alerts.csv)
- [`python_port_scan_alert.png`](../Screenshots/port_scan/python_port_scan_alert.png)

## Final Finding

The evidence confirms a full TCP port scan from `192.168.16.132` against `192.168.16.130`. The source contacted all `65,535` TCP ports and generated `65,747` TCP connection records over approximately twelve minutes. Zeek connection-state data, the Python detector output, the retained Nmap service verification, and Wireshark packet inspection all support the same conclusion.

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Discovery | Network Service Discovery | `T1046` |

## Analyst Notes and Limitations

This case confirms reconnaissance activity, not compromise. The scan revealed responding services on the Windows target, including SSH and Windows networking services, but no exploitation attempt was evaluated in this phase. In a production environment, this event should be correlated with subsequent login failures, exploit traffic, or endpoint alerts to determine whether reconnaissance progressed into an intrusion attempt.

## Recommended Actions

- Review whether ports `22`, `135`, `139`, and `445` need to be accessible from the observed network segment.
- Restrict administrative and file-sharing services where they are not operationally required.
- Alert on unusually high unique destination-port counts from a single source.
- Correlate port-scan detections with authentication or endpoint activity.
- Preserve PCAP, Zeek telemetry, Nmap outputs, and detector evidence for timeline review.

## Conclusion

Phase 2 successfully demonstrates how a port scan can be detected and investigated using network evidence instead of assumption. The workflow covered capture, Zeek analysis, packet validation, service verification, automated detection, and ATT&CK mapping. This makes the case useful as a practical SOC investigation example rather than only an attack simulation.
