### Incident: SSH Brute Force Activity

**Environment:** Host-only lab  
**Attacker:** Kali Linux  
**Target:** Windows 11  
**Monitoring:** Ubuntu with Zeek, tcpdump and Wireshark  

---

#### Summary
Unusual SSH activity was observed during network traffic analysis. A single source host generated a high number of repeated connection attempts against the SSH service running on the target system.

---

#### Key Findings
- Source IP: **192.168.16.132**
- Destination IP: **192.168.16.130**
- Targeted service: **SSH**
- Destination port: **22**
- Detected SSH connection attempts: **8045**

---

#### Evidence Collected
- Zeek `conn.log` showed repeated SSH connections from the same source IP
- Top talker analysis highlighted abnormal traffic volume from the attacker machine
- Port analysis confirmed repeated targeting of port 22
- Wireshark PCAP analysis showed repeated TCP SYN packets and SSH handshakes
- Custom Python detection script generated a brute force alert

---

#### Analysis
The observed traffic pattern indicates automated SSH brute force behavior. The attacker repeatedly attempted to establish SSH connections with the target system within a short time window. The volume and repetition of connections strongly suggest tool-based activity rather than normal user login behavior.

---

#### Conclusion
The activity was confirmed as an **SSH brute force attack** originating from **192.168.16.132** against **192.168.16.130** on port **22**.

---

#### Recommendations
- Disable password-based SSH authentication where possible
- Use key-based authentication
- Apply account lockout or rate-limiting controls
- Restrict SSH access using firewall rules
- Monitor repeated authentication attempts through network logs

