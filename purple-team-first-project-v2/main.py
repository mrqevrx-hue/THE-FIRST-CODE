# purple-team-toolkit - first project
# made by ikram - learning SOC detection
# date: oct 2026

import re
import json
import os
from collections import Counter
from datetime import datetime

# load my config
try:
    with open("config.json", "r") as f:
        config = json.load(f)
except:
    config = {"brute_force_threshold": 5, "log_file": "sample_logs/auth.log"}

THRESHOLD = config.get("brute_force_threshold", 5)
LOG_FILE = config.get("log_file", "sample_logs/auth.log")

# these patterns i collected from tryhackme and notes
# might need to update later
patterns = {
    "SQLi": r"' OR 1=1|UNION SELECT|' OR '1'='1",
    "XSS": r"<script|javascript:|onerror=",
    "LFI": r"\.\./|etc/passwd",
    "Failed Login": r"Failed password|authentication failure|Invalid user"
}

print("=== purple team toolkit ===")
print(f"scanning file: {LOG_FILE}")
print(f"threshold: {THRESHOLD}")
print()

# check if file exists
if not os.path.exists(LOG_FILE):
    print(f"file not found yaar: {LOG_FILE}")
    exit()

with open(LOG_FILE, "r", errors="ignore") as f:
    lines = f.readlines()

failed_ips = []
alerts = []
all_ips = set()

# simple ip regex - found on stackoverflow
ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

for num, line in enumerate(lines, 1):
    # find ips
    ips = re.findall(ip_pattern, line)
    for ip in ips:
        all_ips.add(ip)

    # brute force check
    if re.search(patterns["Failed Login"], line, re.I):
        if ips:
            failed_ips.extend(ips)

    # other attacks
    for attack, pat in patterns.items():
        if attack == "Failed Login":
            continue
        if re.search(pat, line, re.I):
            alerts.append((num, attack, ips[0] if ips else "?", line.strip()[:100]))
            print(f"[ALERT] {attack} found at line {num} - IP: {ips[0] if ips else '?'}")
            # print(f"  -> {line.strip()[:80]}")

print()
print("-" * 40)
print("BRUTE FORCE CHECK")
print("-" * 40)

counter = Counter(failed_ips)
found = False
for ip, count in counter.items():
    if count >= THRESHOLD:
        print(f"[CRITICAL] brute force from {ip} - {count} tries")
        alerts.append(("N/A", "Brute Force", ip, f"{count} fails"))
        found = True

if not found:
    if failed_ips:
        most = counter.most_common(1)[0]
        print(f"no brute force above threshold, but max fails: {most[0]} = {most[1]}")
    else:
        print("no failed logins")

# make reports folder
os.makedirs("reports", exist_ok=True)

# txt report - simple one
with open("reports/report.txt", "w") as out:
    out.write(f"Report - {datetime.now()}\n")
    out.write(f"File: {LOG_FILE}\n")
    out.write(f"Total lines: {len(lines)}\n")
    out.write(f"Alerts: {len(alerts)}\n\n")
    for a in alerts:
        out.write(str(a) + "\n")

# html report - basic one, will make better later
html = f"""
<html>
<head><title>report</title></head>
<body style="font-family: monospace; background: #111; color: #eee; padding: 20px;">
<h2>purple team report - {datetime.now()}</h2>
<p>file: {LOG_FILE} | lines: {len(lines)} | ips: {len(all_ips)}</p>
<h3>alerts: {len(alerts)}</h3>
"""

for a in alerts:
    html += f"<div style='border:1px solid #333; padding:10px; margin:5px;'><b>{a[1]}</b> - {a[2]} - line {a[0]}<br><small>{a[3]}</small></div>\n"

html += "<br><p>made by ikram - first project</p></body></html>"

with open("reports/report.html", "w") as out:
    out.write(html)

print()
print(f"done. reports saved in reports/ folder")
print(f"total alerts: {len(alerts)}")
