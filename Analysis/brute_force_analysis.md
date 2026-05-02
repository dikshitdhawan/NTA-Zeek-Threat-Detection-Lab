# SSH Brute Force Traffic Analysis

## 1. Objective

The objective of this analysis was to identify and validate SSH brute force activity using network traffic evidence collected from a controlled lab environment.

The investigation focused on identifying the attacking host, confirming the targeted service, validating the traffic using packet capture, and documenting the findings in a SOC-style format.

---

## 2. Lab Environment

| Role | Machine | Purpose |
|---|---|---|
| Attacker | Kali Linux | Generated SSH brute force traffic |
| Target | Windows 11 | Hosted SSH service |
| Monitoring System | Ubuntu | Captured and analyzed traffic using Zeek, tcpdump and Wireshark |

All machines were connected through a host-only network to keep the traffic isolated and controlled.

---

## 3. Evidence Sources

| Source | Purpose |
|---|---|
| Zeek conn.log | Connection-level visibility |
| Zeek ssh.log | SSH-specific activity |
| PCAP file | Raw packet-level evidence |
| Wireshark | Packet validation |
| Python detection script | Alert generation |

---

## 4. Investigation Methodology

The analysis followed this workflow:

1. Captured traffic using tcpdump.
2. Generated Zeek logs from the monitored interface.
3. Identified active source hosts from conn.log.
4. Checked destination ports to confirm the targeted service.
5. Validated the activity using Wireshark.
6. Ran a Python detection script to generate an alert.
7. Documented the findings.

---

## 5. Top Talker Analysis

The first step was to identify the most active source hosts in the network traffic.

Command used:

    awk '{print $3}' conn.log | sort | uniq -c | sort -nr | head

Observed output:

    8048 192.168.16.132
    489  192.168.16.131
    157  192.168.16.130

The output showed that 192.168.16.132 generated the highest number of connection entries. This host was later verified as the Kali Linux machine used to perform the attack.

This step helped identify suspicious activity from the logs instead of assuming the attacker IP in advance.

---

## 6. Service-Specific Analysis

After identifying the most active host, the destination ports contacted by that host were analyzed.

Command used:

    grep 192.168.16.132 conn.log | awk '{print $6}' | sort | uniq -c

Observed output:

    8045 22

The result showed that most of the traffic from 192.168.16.132 was directed toward port 22, which is used by SSH.

This confirmed that the activity was focused on the SSH service and was not random background traffic.

---

## 7. PCAP Validation

The packet capture was reviewed in Wireshark using the following filter:

    ip.addr == 192.168.16.132 && tcp.port == 22

The filtered traffic showed repeated TCP connection attempts and SSHv2 communication between the attacker and the target.

This packet-level evidence supported the Zeek log findings and confirmed repeated SSH activity.

---

## 8. Detection Script Output

A Python detection script was used to count repeated SSH connections and raise an alert when the threshold was exceeded.

Detection logic:

- Read Zeek conn.log
- Extract source IP and destination port
- Count repeated connections to port 22
- Trigger an alert when the count crosses the threshold

Observed alert:

    ALERT: Possible SSH brute force from 192.168.16.132 with 8045 attempts

---

## 9. Findings

| Field | Value |
|---|---|
| Attack Type | SSH Brute Force |
| Attacker IP | 192.168.16.132 |
| Target IP | 192.168.16.130 |
| Targeted Service | SSH |
| Destination Port | 22 |
| Approximate Attempts | 8000+ |
| Evidence | Zeek logs, PCAP, Wireshark, Python detection script |

---

## 10. Analyst Assessment

The traffic pattern indicates automated SSH brute force activity. A single source repeatedly attempted to connect to the SSH service on the target system within a short time window.

The activity was considered suspicious because of the high repetition, single-service focus, and consistent connection pattern.

---

## 11. Conclusion

The investigation confirms that 192.168.16.132 performed an SSH brute force attack against 192.168.16.130.

The conclusion was based on Zeek connection logs, service-specific port analysis, PCAP validation in Wireshark, and alert generation using a custom Python detection script.

---

## 12. Recommendations

- Disable password-based SSH authentication where possible.
- Use SSH key-based authentication.
- Apply login rate limiting.
- Restrict SSH access using firewall rules.
- Monitor repeated SSH connection attempts.
- Review authentication logs on the target system for failed login attempts.
