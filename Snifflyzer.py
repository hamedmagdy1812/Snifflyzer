#!/usr/bin/env python3
"""
Snifflyzer - A lightweight network sniffer and analyzer for basic threat detection
"""

import argparse
import os
import time
import signal
import sys
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, DNSQR, DNSRR, rdpcap, wrpcap
    import matplotlib.pyplot as plt
except ImportError:
    print("Required packages not installed. Install with:")
    print("pip install scapy matplotlib")
    sys.exit(1)

# Global variables for analysis
packet_stats = Counter()
ip_connections = defaultdict(Counter)
dns_queries = {}
arp_cache = {}
login_attempts = defaultdict(Counter)
suspicious_activities = []
total_packets = 0
severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

# For CTRL+C handling
sniff_active = True


def log_threat(source, threat_type, details, severity="MEDIUM"):
    """Log a detected threat with timestamp and severity level"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    suspicious_activities.append({
        "timestamp": timestamp,
        "source": source,
        "threat_type": threat_type,
        "details": details,
        "severity": severity
    })
    severity_counts[severity] += 1
    

def analyze_arp(packet):
    """Detect potential ARP spoofing attacks"""
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 2:  # is-at (response)
            ip_src = arp.psrc
            mac_src = arp.hwsrc
            
            # Check if this IP was previously seen with a different MAC
            if ip_src in arp_cache and arp_cache[ip_src] != mac_src:
                log_threat(
                    ip_src,
                    "ARP SPOOFING",
                    f"IP {ip_src} changed MAC from {arp_cache[ip_src]} to {mac_src}",
                    "HIGH"
                )
                print(f"\033[91m[HIGH] Potential ARP spoofing: {ip_src} MAC changed to {mac_src}\033[0m")
            
            # Update our ARP cache
            arp_cache[ip_src] = mac_src


def analyze_dns(packet):
    """Detect potential DNS poisoning and track DNS queries"""
    if packet.haslayer(DNS):
        # Track DNS queries
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            dns_queries[qname] = dns_queries.get(qname, 0) + 1
            
        # Check for DNS responses
        if packet.haslayer(DNSRR):
            qname = packet[DNSRR].rrname.decode('utf-8', errors='ignore').rstrip('.')
            rdata = packet[DNSRR].rdata
            if isinstance(rdata, bytes):
                try:
                    rdata = rdata.decode('utf-8', errors='ignore')
                except:
                    rdata = str(rdata)
            
            # Check for potentially suspicious DNS answers
            if qname in ["google.com", "facebook.com", "amazon.com", "microsoft.com"] and \
               packet.haslayer(IP) and packet[IP].src != "8.8.8.8" and packet[IP].src != "1.1.1.1":
                log_threat(
                    packet[IP].src,
                    "DNS MANIPULATION",
                    f"Suspicious DNS response for {qname} -> {rdata}",
                    "HIGH"
                )
                print(f"\033[91m[HIGH] Potential DNS poisoning: {qname} -> {rdata}\033[0m")


def analyze_tcp(packet):
    """Analyze TCP packets for suspicious login attempts and unusual behavior"""
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        
        # Update connection counters
        ip_connections[src_ip][dst_ip] += 1
        
        # Check for potential SSH/Telnet/FTP/RDP brute force
        if dst_port in [22, 23, 21, 3389]:
            service = {22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP"}[dst_port]
            login_attempts[f"{src_ip}->{dst_ip}:{service}"] += 1
            attempt_count = login_attempts[f"{src_ip}->{dst_ip}:{service}"]
            
            if attempt_count == 10:
                log_threat(
                    src_ip, 
                    f"{service} BRUTE FORCE", 
                    f"Multiple {service} connection attempts to {dst_ip}",
                    "MEDIUM"
                )
                print(f"\033[93m[MEDIUM] Potential {service} brute force from {src_ip} to {dst_ip}\033[0m")
            elif attempt_count == 30:
                log_threat(
                    src_ip, 
                    f"{service} BRUTE FORCE", 
                    f"Excessive {service} connection attempts to {dst_ip}",
                    "HIGH"
                )
                print(f"\033[91m[HIGH] Excessive {service} connection attempts from {src_ip} to {dst_ip}\033[0m")


def packet_callback(packet):
    """Process each packet captured"""
    global total_packets
    total_packets += 1
    
    # Update protocol counter
    if packet.haslayer(TCP):
        packet_stats["TCP"] += 1
    elif packet.haslayer(UDP):
        packet_stats["UDP"] += 1
    elif packet.haslayer(ARP):
        packet_stats["ARP"] += 1
    elif packet.haslayer(DNS):
        packet_stats["DNS"] += 1
    else:
        packet_stats["Other"] += 1
    
    # Run analysis modules
    if packet.haslayer(ARP):
        analyze_arp(packet)
    
    if packet.haslayer(DNS):
        analyze_dns(packet)
    
    if packet.haslayer(IP) and packet.haslayer(TCP):
        analyze_tcp(packet)
    
    # Print basic packet info every 100 packets
    if total_packets % 100 == 0:
        sys.stdout.write(f"\rPackets captured: {total_packets} (TCP: {packet_stats['TCP']}, UDP: {packet_stats['UDP']}, DNS: {packet_stats['DNS']}, ARP: {packet_stats['ARP']}, Other: {packet_stats['Other']})")
        sys.stdout.flush()


def detect_unusual_traffic():
    """Detect unusual traffic patterns from collected statistics"""
    # Check for IPs with too many connections
    for src_ip, destinations in ip_connections.items():
        if len(destinations) > 20:
            log_threat(
                src_ip,
                "PORT SCANNING",
                f"Connected to {len(destinations)} different IPs",
                "MEDIUM"
            )
            print(f"\033[93m[MEDIUM] Potential port scanning from {src_ip} ({len(destinations)} destinations)\033[0m")


def generate_visualizations(output_dir):
    """Generate visualizations of the collected data"""
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate protocol distribution pie chart
    plt.figure(figsize=(10, 6))
    labels = list(packet_stats.keys())
    sizes = list(packet_stats.values())
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title('Protocol Distribution')
    plt.savefig(os.path.join(output_dir, 'protocol_distribution.png'))
    
    # Generate threat severity distribution
    plt.figure(figsize=(10, 6))
    labels = list(severity_counts.keys())
    sizes = list(severity_counts.values())
    plt.bar(labels, sizes, color=['green', 'orange', 'red'])
    plt.title('Threat Severity Distribution')
    plt.savefig(os.path.join(output_dir, 'threat_severity.png'))


def print_summary_report():
    """Print a summary report of the sniffing session"""
    print("\n\n" + "=" * 50)
    print("SNIFFLYZER SUMMARY REPORT")
    print("=" * 50)
    print(f"Total packets captured: {total_packets}")
    print(f"Session duration: {session_duration:.2f} seconds")
    print("\nProtocol Distribution:")
    for proto, count in packet_stats.most_common():
        print(f"  {proto}: {count} ({count/max(total_packets, 1)*100:.1f}%)")
    
    print("\nTop DNS Queries:")
    for domain, count in sorted(dns_queries.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {domain}: {count}")
    
    print("\nDetected Threats:")
    if not suspicious_activities:
        print("  No threats detected")
    else:
        for level in ["HIGH", "MEDIUM", "LOW"]:
            level_threats = [t for t in suspicious_activities if t["severity"] == level]
            if level_threats:
                print(f"\n  {level} Severity Threats ({len(level_threats)}):")
                for threat in level_threats:
                    print(f"    [{threat['timestamp']}] {threat['threat_type']} from {threat['source']}: {threat['details']}")


def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully exit the sniffer"""
    global sniff_active
    print("\n\nStopping packet capture...")
    sniff_active = False


def main():
    """Main function to set up and run the sniffer"""
    parser = argparse.ArgumentParser(description='Snifflyzer - Network Sniffer & Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff on')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 for unlimited)')
    parser.add_argument('-t', '--timeout', type=int, default=0, help='Timeout in seconds (0 for no timeout)')
    parser.add_argument('-o', '--output', default='snifflyzer_output', help='Output directory for reports and visualizations')
    parser.add_argument('-f', '--filter', default='', help='BPF filter to apply (e.g., "tcp port 80")')
    parser.add_argument('-p', '--pcap', help='Save captured packets to PCAP file')
    parser.add_argument('-r', '--read', help='Read packets from PCAP file instead of sniffing')
    
    args = parser.parse_args()
    
    global session_duration
    start_time = time.time()
    
    print("🔍 Snifflyzer - Network Sniffer & Analyzer 🔍")
    print("=" * 50)
    
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start sniffing or reading from PCAP
    if args.read:
        print(f"Reading packets from {args.read}...")
        packets = rdpcap(args.read)
        for packet in packets:
            packet_callback(packet)
        detect_unusual_traffic()
    else:
        # Print sniffing parameters
        print(f"Starting capture with parameters:")
        print(f"  Interface: {args.interface or 'default'}")
        print(f"  Count: {'unlimited' if args.count == 0 else args.count}")
        print(f"  Timeout: {'none' if args.timeout == 0 else f'{args.timeout}s'}")
        print(f"  Filter: {args.filter or 'none'}")
        print(f"  PCAP output: {args.pcap or 'none'}")
        print("\nPress Ctrl+C to stop capture\n")
        
        # Start sniffing
        try:
            packets = sniff(
                iface=args.interface,
                count=args.count if args.count > 0 else None,
                timeout=args.timeout if args.timeout > 0 else None,
                filter=args.filter if args.filter else None,
                prn=packet_callback,
                store=bool(args.pcap),
                stop_filter=lambda p: not sniff_active
            )
            
            # Save PCAP if requested
            if args.pcap and packets:
                wrpcap(args.pcap, packets)
                print(f"\nSaved {len(packets)} packets to {args.pcap}")
                
        except Exception as e:
            print(f"\nError during packet capture: {e}")
    
    # Calculate session duration
    session_duration = time.time() - start_time
    
    # Run final analysis
    detect_unusual_traffic()
    
    # Print summary report
    print_summary_report()
    
    # Generate visualizations
    if args.output:
        try:
            generate_visualizations(args.output)
            print(f"\nVisualizations saved to {args.output} directory")
        except Exception as e:
            print(f"\nError generating visualizations: {e}")


if __name__ == "__main__":
    main()