from collections import Counter

ips = []

with open("conn.log") as f:
    for line in f:
        if not line.startswith("#"):
            parts = line.split()
            src_ip = parts[2]     # id.orig_h
            dest_port = parts[5]  # id.resp_p

            if dest_port == "22":
                ips.append(src_ip)

count = Counter(ips)

for ip, c in count.items():
    if c > 50:
        print("ALERT: Possible SSH brute force from", ip, "with", c, "attempts")
