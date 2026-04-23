from scapy.all import sniff, wrpcap
import os
from collections import defaultdict
from datetime import datetime
import ctypes
import sys

# Auto-elevate to admin if not already running as admin
def is_admin():
    try:
        return ctypes.windll.shell.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # Re-run the script with admin privileges
    ctypes.windll.shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=' '.join(sys.argv))
    sys.exit()

port_hits = defaultdict(set)
icmp_count = defaultdict(int)
alerts = []

def get_next_file_number():
    """Find the next available file number for sequential naming"""
    desktop_path = os.path.expanduser("~/Desktop")
    existing_files = os.listdir(desktop_path)
    
    max_num = -1
    for file in existing_files:
        if file.startswith("project") and file.endswith(".pcap"):
            try:
                # Extract number from project0.pcap, project1.pcap, etc
                num_str = file.replace("project", "").replace(".pcap", "")
                num = int(num_str)
                max_num = max(max_num, num)
            except ValueError:
                continue
    
    return max_num + 1

def log_alert(message):
    """Log alert to console and alerts list"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = f"[{timestamp}] {message}"
    print(alert_msg)
    alerts.append(alert_msg)

def detect_port_scan(packet):
    if packet.haslayer("TCP"):
        src = packet["IP"].src
        port = packet["TCP"].dport
        
        port_hits[src].add(port)
        
        if len(port_hits[src]) > 10:
            log_alert(f"⚠️ Port Scan Detected from {src}")

def detect_icmp(packet):
    if packet.haslayer("ICMP"):
        src = packet["IP"].src
        icmp_count[src] += 1
        
        if icmp_count[src] > 20:
            log_alert(f"⚠️ ICMP Flood Detected from {src}")

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

# Capture 100 packets
packets = sniff(prn=process_packet, store=1, count=100)

# Get the next file number
file_num = get_next_file_number()

# Save capture file to desktop
desktop_path = os.path.expanduser(f"~/Desktop/project{file_num}.pcap")
wrpcap(desktop_path, packets)
print(f"\n✅ Capture saved to: {desktop_path}")

# Generate and save report
report_path = os.path.expanduser(f"~/Desktop/project{file_num}_report.txt")
with open(report_path, 'w') as f:
    f.write("=" * 60 + "\n")
    f.write("NETWORK SECURITY REPORT\n")
    f.write("=" * 60 + "\n")
    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"Packets Captured: {len(packets)}\n")
    f.write("=" * 60 + "\n\n")
    
    if alerts:
        f.write(f"ALERTS DETECTED: {len(alerts)}\n")
        f.write("-" * 60 + "\n")
        for alert in alerts:
            f.write(f"{alert}\n")
    else:
        f.write("No threats detected.\n")
    
    f.write("\n" + "=" * 60 + "\n")
    f.write("PORT SCAN SUMMARY\n")
    f.write("-" * 60 + "\n")
    if port_hits:
        for src, ports in port_hits.items():
            f.write(f"Source IP: {src} - {len(ports)} unique ports\n")
    else:
        f.write("No port scan activity detected.\n")
    
    f.write("\n" + "=" * 60 + "\n")
    f.write("ICMP ACTIVITY SUMMARY\n")
    f.write("-" * 60 + "\n")
    if icmp_count:
        for src, count in icmp_count.items():
            f.write(f"Source IP: {src} - {count} ICMP packets\n")
    else:
        f.write("No ICMP activity detected.\n")

print(f"✅ Report saved to: {report_path}")
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Total Alerts: {len(alerts)}")
print(f"Capture file: project{file_num}.pcap")
print(f"Report file: project{file_num}_report.txt")