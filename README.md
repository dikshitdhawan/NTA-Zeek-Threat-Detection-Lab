\# Network Traffic Analysis and Threat Detection using Zeek



A hands-on cybersecurity project focused on detecting and investigating suspicious network activity using \*\*Zeek\*\*, \*\*tcpdump\*\*, \*\*Wireshark\*\*, and \*\*Python\*\*.



This lab follows a SOC-style workflow: traffic capture, Zeek log analysis, packet-level validation, detection scripting, and incident documentation.



\---



\## Project Overview



The objective of this project is to build a practical Network Traffic Analysis lab that simulates real attack traffic and investigates it using network logs and packet captures.



Instead of only running attacks, this project focuses on how a SOC analyst would approach an investigation:



1\. Capture network traffic

2\. Generate Zeek logs

3\. Identify suspicious hosts

4\. Validate activity using PCAP evidence

5\. Write detection logic

6\. Document findings in an incident report



\---



\## Lab Architecture



The lab was built using three virtual machines connected through an isolated host-only network.



| Role | Machine | Purpose |

|---|---|---|

| Attacker | Kali Linux | Generates attack traffic |

| Target | Windows 11 | Victim machine running target services |

| Monitoring System | Ubuntu | Captures and analyzes traffic using Zeek, tcpdump, and Wireshark |



\---



\## Tools Used



| Tool | Purpose |

|---|---|

| Zeek | Network log generation and traffic analysis |

| tcpdump | Packet capture |

| Wireshark | PCAP validation and packet inspection |

| Python | Custom detection scripting |

| Kali Linux tools | Attack simulation |



\---



\## Completed Scenarios



| Scenario | Status |

|---|---|

| SSH Brute Force Detection | Completed |

| Port Scan Detection | Pending |

| DNS Anomaly Detection | Pending |



\---



\## Current Completed Case Study



\### SSH Brute Force Detection



The first completed scenario investigates SSH brute force activity generated from Kali Linux against a Windows target machine running SSH.



The investigation includes:



\- Packet capture using tcpdump

\- Zeek log generation

\- Top talker analysis

\- SSH port analysis

\- Wireshark validation

\- Python-based detection alert

\- SOC-style incident report

\- Technical traffic analysis



\---



\## Evidence Collected



| Evidence | Location |

|---|---|

| PCAP file | `PCAP/brute\_force/bruteforce.pcap` |

| Zeek logs | `Zeek-Logs/brute\_force/` |

| Wireshark screenshot | `Screenshots/brute\_force/wireshark\_bruteforce.png` |

| Detection alert screenshot | `Screenshots/brute\_force/detection\_alert.png` |

| Incident report | `Incident-Reports/brute\_force.md` |

| Technical analysis | `Analysis/brute\_force\_analysis.md` |



\---



\## Repository Structure



```text

NTA-Zeek-Threat-Detection-Lab/

│

├── README.md

│

├── Analysis/

│   └── brute\_force\_analysis.md

│

├── Detection-Scripts/

│   └── brute\_force\_detect.py

│

├── Incident-Reports/

│   └── brute\_force.md

│

├── Notes/

│   └── brute\_force\_notes.txt

│

├── PCAP/

│   ├── brute\_force/

│   │   └── bruteforce.pcap

│   ├── port\_scan/

│   └── dns\_anomaly/

│

├── Screenshots/

│   ├── brute\_force/

│   │   ├── both\_terminals.png

│   │   ├── detection\_alert.png

│   │   ├── kali\_hydra\_command.png

│   │   ├── port\_22\_analysis.png

│   │   ├── tcpdump\_capture\_running.png

│   │   ├── top\_talkers.png

│   │   ├── wireshark\_bruteforce.png

│   │   └── zeek\_capture.png

│   ├── port\_scan/

│   └── dns\_anomaly/

│

└── Zeek-Logs/

&#x20;   ├── brute\_force/

&#x20;   │   ├── conn.log

&#x20;   │   ├── dhcp.log

&#x20;   │   ├── dns.log

&#x20;   │   ├── packet\_filter.log

&#x20;   │   ├── reporter.log

&#x20;   │   ├── ssh.log

&#x20;   │   └── weird.log

&#x20;   ├── port\_scan/

&#x20;   └── dns\_anomaly/

```



\---



\## SSH Brute Force Investigation Summary



During the SSH brute force scenario, repeated SSH connection attempts were observed from a single source host.



| Field | Value |

|---|---|

| Attack Type | SSH Brute Force |

| Attacker IP | 192.168.16.132 |

| Target IP | 192.168.16.130 |

| Targeted Service | SSH |

| Destination Port | 22 |

| Approximate Attempts | 8000+ |



\---



\## Analysis Approach



\### 1. Top Talker Identification



Zeek `conn.log` was used to identify the most active source hosts.



```bash

awk '{print $3}' conn.log | sort | uniq -c | sort -nr | head

```



This helped identify high-volume communication from the attacker machine.



\---



\### 2. SSH Port Analysis



The suspicious source IP was analyzed further to identify the destination service being targeted.



```bash

grep 192.168.16.132 conn.log | awk '{print $6}' | sort | uniq -c

```



The output showed a high number of connections targeting port `22`, confirming SSH-focused activity.



\---



\### 3. PCAP Validation



The captured traffic was opened in Wireshark and filtered using:



```text

ip.addr == 192.168.16.132 \&\& tcp.port == 22

```



The filtered packet view showed repeated TCP connection attempts and SSHv2 communication between the attacker and target.



\---



\### 4. Detection Script



A Python script was written to parse Zeek `conn.log`, count repeated SSH connections, and generate an alert when the threshold was exceeded.



Detection script:



```text

Detection-Scripts/brute\_force\_detect.py

```



The script generated an alert for repeated SSH activity from the attacking host.



\---



\## Detection Logic



The brute force detection script follows this logic:



1\. Read Zeek `conn.log`

2\. Ignore Zeek metadata lines

3\. Extract source IP and destination port

4\. Count connections targeting SSH port `22`

5\. Trigger an alert when the connection count crosses the threshold



This is a simple threshold-based detection approach suitable for understanding the fundamentals of network-based detection engineering.



\---



\## Key Findings



\- A high number of repeated SSH connections were observed.

\- The traffic originated from `192.168.16.132`.

\- The target system was `192.168.16.130`.

\- Most suspicious traffic was directed toward port `22`.

\- Wireshark confirmed repeated SSH communication.

\- The Python script successfully generated a brute force alert.



\---



\## Incident Report



The full incident report is available here:



```text

Incident-Reports/brute\_force.md

```



The detailed technical analysis is available here:



```text

Analysis/brute\_force\_analysis.md

```



\---



\## Skills Demonstrated



This project demonstrates practical skills relevant to SOC Analyst and cybersecurity intern roles:



\- Network traffic analysis

\- Zeek log investigation

\- PCAP analysis using Wireshark

\- SSH brute force detection

\- Basic detection engineering

\- Python scripting for log analysis

\- Evidence-based incident documentation

\- SOC-style investigation workflow



\---



\## Next Planned Scenarios



The project will be extended with additional network threat detection scenarios:



\### Port Scan Detection



Planned investigation:



\- Detect multiple destination ports contacted by a single source

\- Analyze scan behavior using Zeek `conn.log`

\- Validate SYN traffic in Wireshark

\- Write a port scan detection script



\### DNS Anomaly Detection



Planned investigation:



\- Analyze unusual DNS query patterns

\- Detect repeated or suspicious domain lookups

\- Use Zeek `dns.log` for investigation

\- Write a DNS anomaly detection script



\---



\## Project Status



| Phase | Description | Status |

|---|---|---|

| Phase 1 | SSH Brute Force Detection | Completed |

| Phase 2 | Port Scan Detection | In Progress |

| Phase 3 | DNS Anomaly Detection | Planned |



\---



\## Conclusion



This project provides a practical demonstration of network traffic analysis using open-source tools. The completed SSH brute force scenario shows how raw packet captures, Zeek logs, Wireshark analysis, and Python-based detection can be combined to investigate and document suspicious activity in a SOC-style workflow.

