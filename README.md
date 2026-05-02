# Network Traffic Analysis and Threat Detection using Zeek

A practical SOC-style cybersecurity lab focused on detecting and investigating suspicious network traffic using **Zeek**, **tcpdump**, **Wireshark**, and **Python**.

This project demonstrates how network traffic can be captured, analyzed, validated, and documented using a structured security investigation workflow.

---

## Project Overview

The goal of this project is to simulate real attack traffic in an isolated lab environment and analyze it from a defender’s perspective.

The workflow followed in this project:

1. Capture network traffic using tcpdump
2. Generate structured logs using Zeek
3. Identify suspicious hosts and services
4. Validate findings using Wireshark
5. Build Python-based detection logic
6. Document the incident in a SOC-style report

This project was built as part of my hands-on SOC analyst preparation, with a focus on understanding how network evidence is collected, validated, and documented during an investigation.

---

## Lab Architecture

| Role | Machine | Purpose |
|---|---|---|
| Attacker | Kali Linux | Generates attack traffic |
| Target | Windows 11 | Victim system running target services |
| Monitoring System | Ubuntu | Captures and analyzes traffic using Zeek, tcpdump, and Wireshark |

All machines were connected through an isolated host-only network.

---

## Tools Used

| Tool | Purpose |
|---|---|
| Zeek | Network log generation and analysis |
| tcpdump | Packet capture |
| Wireshark | PCAP inspection and validation |
| Python | Detection scripting |
| Kali Linux tools | Attack simulation |

---

## Completed Scenarios

| Scenario | Status |
|---|---|
| SSH Brute Force Detection | Completed |
| Port Scan Detection | Pending |
| DNS Anomaly Detection | Pending |

---

## SSH Brute Force Detection

The first completed case study focuses on detecting SSH brute force activity.

### Scenario Summary

| Field | Value |
|---|---|
| Attack Type | SSH Brute Force |
| Attacker IP | 192.168.16.132 |
| Target IP | 192.168.16.130 |
| Targeted Service | SSH |
| Destination Port | 22 |
| Approximate Attempts | 8000+ |

---

## Evidence Collected

| Evidence | Location |
|---|---|
| PCAP File | `PCAP/brute_force/bruteforce.pcap` |
| Zeek Logs | `Zeek-Logs/brute_force/` |
| Detection Script | `Detection-Scripts/brute_force_detect.py` |
| Incident Report | `Incident-Reports/brute_force.md` |
| Technical Analysis | `Analysis/brute_force_analysis.md` |
| Screenshots | `Screenshots/brute_force/` |

---

## Investigation Approach

### 1. Top Talker Analysis

Zeek `conn.log` was used to identify the most active source hosts in the network traffic.

```bash
awk '{print $3}' conn.log | sort | uniq -c | sort -nr | head
```

This helped identify the host generating abnormal connection volume.

### 2. SSH Port Analysis

After identifying the suspicious source IP, destination port activity was analyzed.

```bash
grep 192.168.16.132 conn.log | awk '{print $6}' | sort | uniq -c
```

The result showed repeated traffic targeting port `22`, confirming SSH-focused activity.

### 3. PCAP Validation

The captured PCAP was opened in Wireshark and filtered using:

```text
ip.addr == 192.168.16.132 && tcp.port == 22
```

The filtered traffic showed repeated TCP connection attempts and SSH communication between the attacker and target.

### 4. Detection Script

A Python script was created to parse Zeek `conn.log`, count SSH connections, and raise an alert when the threshold was exceeded.

---

## Key Findings

- A high number of repeated SSH connections were observed.
- The suspicious traffic originated from `192.168.16.132`.
- The target system was `192.168.16.130`.
- Most suspicious traffic was directed toward SSH port `22`.
- Wireshark validated repeated SSH communication.
- The detection script successfully generated an alert.
- The analysis was performed without assuming the attacker IP initially; the suspicious host was identified from Zeek connection patterns and later validated against the lab machines.

---

## Repository Structure

```text
NTA-Zeek-Threat-Detection-Lab/
|
|-- Analysis/
|   |-- brute_force_analysis.md
|
|-- Detection-Scripts/
|   |-- brute_force_detect.py
|
|-- Incident-Reports/
|   |-- brute_force.md
|
|-- Notes/
|   |-- brute_force_notes.txt
|
|-- PCAP/
|   |-- brute_force/
|       |-- bruteforce.pcap
|
|-- Screenshots/
|   |-- brute_force/
|       |-- kali_hydra_command.png
|       |-- top_talkers.png
|       |-- port_22_analysis.png
|       |-- wireshark_bruteforce.png
|       |-- detection_alert.png
|
|-- Zeek-Logs/
|   |-- brute_force/
|       |-- conn.log
|       |-- dns.log
|       |-- ssh.log
|       |-- weird.log
|
|-- README.md
```

---

## Skills Demonstrated

- Network traffic analysis
- Zeek log investigation
- PCAP analysis using Wireshark
- SSH brute force detection
- Python-based detection scripting
- SOC-style incident documentation
- Evidence-based security investigation

---

## Next Steps

Planned improvements:

- Add port scan detection using Zeek `conn.log`
- Add DNS anomaly detection using Zeek `dns.log`
- Improve detection scripts with better thresholds
- Add final project report after completing all scenarios

---

## Project Status

| Phase | Description | Status |
|---|---|---|
| Phase 1 | SSH Brute Force Detection | Completed |
| Phase 2 | Port Scan Detection | Pending |
| Phase 3 | DNS Anomaly Detection | Pending |

---

## Conclusion

This project demonstrates a practical approach to network traffic analysis using open-source tools. The completed SSH brute force case study shows how packet captures, Zeek logs, Wireshark validation, Python detection logic, and incident documentation can be combined into a SOC-style investigation workflow.