# Network Packet Sniffer & Security Threat Detector - Complete Script Explanation

## 📋 Overview
This Python script is a **network security monitoring tool** that:
- Captures live network packets using Scapy
- Detects potential security threats (port scans, ICMP floods)
- Generates timestamped alerts and comprehensive reports
- Automatically saves captures and reports with sequential numbering
- Auto-elevates to admin privileges when run from VS Code

---

## 🔧 Imports & Dependencies

```python
from scapy.all import sniff, wrpcap
import os
from collections import defaultdict
from datetime import datetime
import ctypes
import sys
```

| Import | Purpose |
|--------|---------|
| `scapy.all` | Network packet capture and writing (`sniff`, `wrpcap`) |
| `os` | File system operations (path expansion, directory listing) |
| `defaultdict` | Dictionary that auto-initializes default values |
| `datetime` | Timestamp generation for alerts |
| `ctypes` | Windows API calls for admin elevation |
| `sys` | System operations (exit, arguments) |

---

## 🔐 Auto-Elevation Mechanism

```python
def is_admin():
    try:
        return ctypes.windll.shell.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=' '.join(sys.argv))
    sys.exit()
```

**What it does:**
1. **`is_admin()`** - Checks if the script is running with administrator privileges using Windows API
2. **`if not is_admin()`** - If NOT running as admin:
   - Uses Windows ShellExecuteEx API with `runas` verb (admin elevation)
   - Re-launches Python with the same script file
   - Exits the current non-admin instance
3. **Result:** UAC popup appears asking for permission, then script restarts as admin

**Why needed:** Scapy requires raw socket access, which only admin accounts have

---

## 📊 Data Structures

```python
port_hits = defaultdict(set)
icmp_count = defaultdict(int)
alerts = []
```

| Variable | Type | Purpose |
|----------|------|---------|
| `port_hits` | `defaultdict(set)` | Maps source IPs → unique destination ports accessed |
| `icmp_count` | `defaultdict(int)` | Maps source IPs → count of ICMP packets sent |
| `alerts` | `list` | Stores all detected threats with timestamps |

**Example:**
```
port_hits = {
    "192.168.1.100": {22, 80, 443, 8080, ...},  # Set of ports
    "10.0.0.50": {443, 8443, ...}
}

icmp_count = {
    "203.0.113.5": 25,     # Sent 25 ICMP packets
    "198.51.100.3": 5
}

alerts = [
    "[2026-04-23 14:30:45] ⚠️ Port Scan Detected from 192.168.1.100",
    "[2026-04-23 14:31:20] ⚠️ ICMP Flood Detected from 203.0.113.5"
]
```

---

## 🔢 Sequential File Numbering

```python
def get_next_file_number():
    """Find the next available file number for sequential naming"""
    desktop_path = os.path.expanduser("~/Desktop")
    existing_files = os.listdir(desktop_path)
    
    max_num = -1
    for file in existing_files:
        if file.startswith("project") and file.endswith(".pcap"):
            try:
                num_str = file.replace("project", "").replace(".pcap", "")
                num = int(num_str)
                max_num = max(max_num, num)
            except ValueError:
                continue
    
    return max_num + 1
```

**Step-by-step:**
1. **Get Desktop path** - `~/Desktop` expands to `C:\Users\{username}\Desktop`
2. **List all files** - `os.listdir()` gets all files on the desktop
3. **Find existing captures** - Loop through files looking for `projectN.pcap` pattern
4. **Extract numbers** - Remove "project" prefix and ".pcap" suffix to get the number
5. **Track maximum** - Keep track of the highest number found
6. **Return next number** - Return `max_num + 1`

**Example:**
```
If Desktop has: project0.pcap, project1.pcap, project2.pcap
→ max_num = 2
→ Returns 3 (next run uses project3.pcap)
```

---

## 🚨 Alert Logging Function

```python
def log_alert(message):
    """Log alert to console and alerts list"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = f"[{timestamp}] {message}"
    print(alert_msg)
    alerts.append(alert_msg)
```

**What it does:**
1. Gets current timestamp (e.g., "2026-04-23 14:30:45")
2. Formats message with timestamp prefix
3. **Prints** to console (real-time feedback)
4. **Appends** to `alerts` list (for report generation later)

**Output example:**
```
[2026-04-23 14:30:45] ⚠️ Port Scan Detected from 192.168.1.100
```

---

## 🔍 Port Scan Detection

```python
def detect_port_scan(packet):
    if packet.haslayer("TCP"):
        src = packet["IP"].src
        port = packet["TCP"].dport
        
        port_hits[src].add(port)
        
        if len(port_hits[src]) > 10:
            log_alert(f"⚠️ Port Scan Detected from {src}")
```

**Detection Logic:**
1. **Check for TCP** - Only analyze TCP packets
2. **Extract source IP** - Get the source IP address
3. **Extract destination port** - Get the destination port being accessed
4. **Add to set** - Add this port to the set for this source IP
5. **Check threshold** - If source IP has accessed >10 unique ports:
   - **Alert!** - Port scan detected (attacker probing for open services)

**Example scenario:**
```
Packet 1: 192.168.1.100 → port 22 (SSH)      → port_hits["192.168.1.100"] = {22}
Packet 2: 192.168.1.100 → port 80 (HTTP)     → port_hits["192.168.1.100"] = {22, 80}
Packet 3: 192.168.1.100 → port 443 (HTTPS)   → port_hits["192.168.1.100"] = {22, 80, 443}
...
After 11 unique ports: ⚠️ Alert triggered!
```

---

## 💥 ICMP Flood Detection

```python
def detect_icmp(packet):
    if packet.haslayer("ICMP"):
        src = packet["IP"].src
        icmp_count[src] += 1
        
        if icmp_count[src] > 20:
            log_alert(f"⚠️ ICMP Flood Detected from {src}")
```

**Detection Logic:**
1. **Check for ICMP** - Only analyze ICMP packets (ping requests)
2. **Extract source IP** - Get the attacker's IP
3. **Increment counter** - Add 1 to the ICMP count for this IP
4. **Check threshold** - If source IP sent >20 ICMP packets:
   - **Alert!** - ICMP flood detected (attacker sending too many pings)

**Example scenario:**
```
Packets from 203.0.113.5: 1, 2, 3, 4, 5 ... 20 ICMP packets → No alert
21st ICMP packet from 203.0.113.5 → ⚠️ Alert triggered!
```

---

## 📦 Packet Processing Function

```python
def process_packet(packet):
    print(packet.summary())
    
    detect_port_scan(packet)
    detect_icmp(packet)
    
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

    if packet.haslayer("TCP"):
        protocol = "TCP"
        print(f"Protocol: {protocol}")
    elif packet.haslayer("UDP"):
        protocol = "UDP"
        print(f"Protocol: {protocol}")
    elif packet.haslayer("ICMP"):
        protocol = "ICMP"
        print(f"Protocol: {protocol}")
```

**Execution flow for each captured packet:**
1. **Print summary** - Display raw packet info from Scapy
2. **Run detections** - Check for port scans and ICMP floods
3. **Extract IP layer** - If packet has IP header:
   - Get source and destination IPs
   - Print them
4. **Identify protocol** - Check TCP/UDP/ICMP layers and print protocol type

**Sample console output:**
```
Ether / IP / TCP 192.168.1.100 > 8.8.8.8 S
Source IP: 192.168.1.100, Destination IP: 8.8.8.8
Protocol: TCP
```

---

## 🎯 Packet Capture

```python
packets = sniff(prn=process_packet, store=1, count=100)
```

**Parameters:**
| Parameter | Value | Meaning |
|-----------|-------|---------|
| `prn` | `process_packet` | Function to call for each packet |
| `store` | `1` | Store packets in memory (True/1) |
| `count` | `100` | Stop after capturing 100 packets |

**What happens:**
- Starts listening on all network interfaces
- For each packet: calls `process_packet()` function
- Stores packets in list for later saving
- Stops automatically after 100 packets captured

---

## 💾 File Saving - Sequential Numbering

```python
file_num = get_next_file_number()

desktop_path = os.path.expanduser(f"~/Desktop/project{file_num}.pcap")
wrpcap(desktop_path, packets)
print(f"\n✅ Capture saved to: {desktop_path}")
```

**Process:**
1. **Get next number** - Calls function to find highest existing number + 1
2. **Create file path** - Uses f-string to insert number: `project0.pcap`, `project1.pcap`, etc.
3. **Save packets** - `wrpcap()` writes all captured packets to `.pcap` file
4. **Confirm** - Print success message with file location

**Example outputs:**
```
Run 1: ~/Desktop/project0.pcap
Run 2: ~/Desktop/project1.pcap
Run 3: ~/Desktop/project2.pcap
```

---

## 📄 Report Generation

```python
report_path = os.path.expanduser(f"~/Desktop/project{file_num}_report.txt")
with open(report_path, 'w') as f:
    # Write header
    f.write("=" * 60 + "\n")
    f.write("NETWORK SECURITY REPORT\n")
    f.write("=" * 60 + "\n")
    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"Packets Captured: {len(packets)}\n")
    
    # Write alerts section
    if alerts:
        f.write(f"ALERTS DETECTED: {len(alerts)}\n")
        for alert in alerts:
            f.write(f"{alert}\n")
    else:
        f.write("No threats detected.\n")
    
    # Write port scan summary
    f.write("PORT SCAN SUMMARY\n")
    if port_hits:
        for src, ports in port_hits.items():
            f.write(f"Source IP: {src} - {len(ports)} unique ports\n")
    else:
        f.write("No port scan activity detected.\n")
    
    # Write ICMP activity summary
    f.write("ICMP ACTIVITY SUMMARY\n")
    if icmp_count:
        for src, count in icmp_count.items():
            f.write(f"Source IP: {src} - {count} ICMP packets\n")
    else:
        f.write("No ICMP activity detected.\n")
```

**Report structure:**
1. **Header** - Title, timestamp, packet count
2. **Alerts Section** - All detected threats with timestamps
3. **Port Scan Summary** - Which IPs scanned how many ports
4. **ICMP Activity Summary** - Which IPs sent how many ICMP packets

**Sample report content:**
```
============================================================
NETWORK SECURITY REPORT
============================================================
Generated: 2026-04-23 14:30:45
Packets Captured: 100
============================================================

ALERTS DETECTED: 2
------------------------------------------------------------
[2026-04-23 14:30:45] ⚠️ Port Scan Detected from 192.168.1.100
[2026-04-23 14:31:20] ⚠️ ICMP Flood Detected from 203.0.113.5

============================================================
PORT SCAN SUMMARY
------------------------------------------------------------
Source IP: 192.168.1.100 - 15 unique ports

============================================================
ICMP ACTIVITY SUMMARY
------------------------------------------------------------
Source IP: 203.0.113.5 - 25 ICMP packets
```

---

## 📊 Final Summary Output

```python
print(f"✅ Report saved to: {report_path}")
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Total Alerts: {len(alerts)}")
print(f"Capture file: project{file_num}.pcap")
print(f"Report file: project{file_num}_report.txt")
```

**Displays:**
- Report file location
- Total number of alerts
- Capture file name
- Report file name

**Example output:**
```
✅ Report saved to: C:\Users\renuk\Desktop\project2_report.txt

============================================================
SUMMARY
============================================================
Total Alerts: 2
Capture file: project2.pcap
Report file: project2_report.txt
```

---

## 🔄 Complete Execution Flow

```
1. Script starts
   ↓
2. Check if running as admin
   ├─ NO → Elevate to admin and restart script
   └─ YES → Continue
   ↓
3. Capture 100 network packets
   ├─ For each packet:
   │  ├─ Print packet summary
   │  ├─ Check for port scans
   │  ├─ Check for ICMP floods
   │  ├─ Print IP addresses and protocol
   │  └─ Store packet in memory
   ↓
4. Find next sequential file number
   ↓
5. Save captured packets to projectN.pcap
   ↓
6. Generate detailed report projectN_report.txt
   ├─ Document all threats found
   ├─ Summarize port scan activity
   └─ Summarize ICMP activity
   ↓
7. Print completion summary
   ↓
8. Exit
```

---

## 🎯 Key Features Summary

| Feature | How It Works |
|---------|------------|
| **Admin Auto-Elevation** | Detects non-admin context, UAC prompts, restarts as admin |
| **Real-time Monitoring** | Continuously analyzes packets as they arrive |
| **Port Scan Detection** | Alerts when single IP connects to >10 ports |
| **ICMP Flood Detection** | Alerts when single IP sends >20 ICMP packets |
| **Timestamped Alerts** | All threats logged with exact time detected |
| **Sequential Files** | Automatically increments file numbers (project0, project1, etc.) |
| **Comprehensive Reports** | Text file with alerts, summaries, and statistics |
| **Portable** | Works on any Windows PC with Python and Scapy installed |

---

## 🚀 How to Use

1. **Copy** the script to any folder
2. **Open** in VS Code
3. **Click** "Run Python File"
4. **Approve** the UAC admin prompt
5. **Wait** for packet capture to complete (100 packets)
6. **Check Desktop** for:
   - `projectN.pcap` - Packet capture file
   - `projectN_report.txt` - Security report

---

## ⚠️ Important Notes

- **Requires:** Python 3.x, Scapy library, Windows OS
- **Must run as admin** to capture live packets
- **Captures 100 packets** by default (can be modified at line starting with `packets = sniff...`)
- **Desktop files** - All outputs saved to `~/Desktop/`
- **Thresholds:**
  - Port Scan Alert: >10 unique ports from same IP
  - ICMP Flood Alert: >20 ICMP packets from same IP
  - (These can be adjusted by changing numbers in detection functions)

