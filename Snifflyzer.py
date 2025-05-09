#!/usr/bin/env python3
"""
Snifflyzer - A lightweight network sniffer and analyzer for basic threat detection
with user-friendly interface
"""

import argparse
import os
import time
import signal
import sys
import platform
import subprocess
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, DNSQR, DNSRR, rdpcap, wrpcap, conf
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

# Terminal colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clear_screen():
    """Clear the terminal screen based on OS"""
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def print_banner():
    """Print the Snifflyzer banner"""
    banner = f"""
{Colors.BLUE}███████╗███╗   ██╗██╗███████╗███████╗██╗  ██╗   ██╗███████╗███████╗██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔════╝██║  ╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  ██║   ╚████╔╝ ███████╗█████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██║    ╚██╔╝  ╚════██║██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║   ███████║███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝{Colors.ENDC}
                                                                        
{Colors.GREEN}🔍 Network Sniffer & Analyzer - Detect threats in real-time 🔍{Colors.ENDC}
"""
    print(banner)

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
    
    # Color code by severity
    color = Colors.YELLOW
    if severity == "HIGH":
        color = Colors.RED
    elif severity == "LOW":
        color = Colors.GREEN
        
    print(f"\n{color}[{severity}] {threat_type}: {details} (from {source}){Colors.ENDC}")

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
            elif attempt_count == 30:
                log_threat(
                    src_ip, 
                    f"{service} BRUTE FORCE", 
                    f"Excessive {service} connection attempts to {dst_ip}",
                    "HIGH"
                )

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
        sys.stdout.write(f"\r{Colors.BLUE}Packets captured: {total_packets} (TCP: {packet_stats['TCP']}, UDP: {packet_stats['UDP']}, DNS: {packet_stats['DNS']}, ARP: {packet_stats['ARP']}, Other: {packet_stats['Other']}){Colors.ENDC}")
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

def generate_visualizations(output_dir):
    """Generate visualizations of the collected data"""
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print(f"\n{Colors.BLUE}Generating visualizations in {output_dir}...{Colors.ENDC}")
    
    # Generate protocol distribution pie chart
    plt.figure(figsize=(10, 6))
    labels = list(packet_stats.keys())
    sizes = list(packet_stats.values())
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title('Protocol Distribution')
    chart_path = os.path.join(output_dir, 'protocol_distribution.png')
    plt.savefig(chart_path)
    print(f"{Colors.GREEN}✓ Saved protocol distribution chart to {chart_path}{Colors.ENDC}")
    
    # Generate threat severity distribution
    plt.figure(figsize=(10, 6))
    labels = list(severity_counts.keys())
    sizes = list(severity_counts.values())
    plt.bar(labels, sizes, color=['green', 'orange', 'red'])
    plt.title('Threat Severity Distribution')
    threat_path = os.path.join(output_dir, 'threat_severity.png')
    plt.savefig(threat_path)
    print(f"{Colors.GREEN}✓ Saved threat severity chart to {threat_path}{Colors.ENDC}")

def print_summary_report():
    """Print a summary report of the sniffing session"""
    print("\n\n" + "=" * 60)
    print(f"{Colors.BOLD}{Colors.BLUE}SNIFFLYZER SUMMARY REPORT{Colors.ENDC}")
    print("=" * 60)
    print(f"Total packets captured: {total_packets}")
    print(f"Session duration: {session_duration:.2f} seconds")
    
    print(f"\n{Colors.BOLD}Protocol Distribution:{Colors.ENDC}")
    for proto, count in packet_stats.most_common():
        print(f"  {proto}: {count} ({count/max(total_packets, 1)*100:.1f}%)")
    
    print(f"\n{Colors.BOLD}Top DNS Queries:{Colors.ENDC}")
    for domain, count in sorted(dns_queries.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {domain}: {count}")
    
    print(f"\n{Colors.BOLD}Detected Threats:{Colors.ENDC}")
    if not suspicious_activities:
        print(f"  {Colors.GREEN}No threats detected{Colors.ENDC}")
    else:
        for level, color in [("HIGH", Colors.RED), ("MEDIUM", Colors.YELLOW), ("LOW", Colors.GREEN)]:
            level_threats = [t for t in suspicious_activities if t["severity"] == level]
            if level_threats:
                print(f"\n  {color}{level} Severity Threats ({len(level_threats)}):{Colors.ENDC}")
                for threat in level_threats:
                    print(f"    [{threat['timestamp']}] {threat['threat_type']} from {threat['source']}: {threat['details']}")

def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully exit the sniffer"""
    global sniff_active
    print(f"\n\n{Colors.YELLOW}Stopping packet capture...{Colors.ENDC}")
    sniff_active = False

def get_network_interfaces():
    """Get a list of available network interfaces"""
    interfaces = []
    
    try:
        # Use scapy's conf.ifaces
        for iface_name in conf.ifaces:
            interfaces.append(iface_name)
    except:
        # Fallback methods
        if platform.system() == "Windows":
            # Windows fallback
            try:
                from scapy.arch.windows import get_windows_if_list
                for iface in get_windows_if_list():
                    interfaces.append(iface.get('name', 'Unknown'))
            except:
                interfaces = ["Ethernet", "Wi-Fi"]  # Default fallback
        else:
            # Linux/Mac fallback
            try:
                output = subprocess.check_output(["ifconfig"]).decode('utf-8')
                interfaces = [line.split(':')[0] for line in output.split('\n') if ':' in line]
            except:
                try:
                    output = subprocess.check_output(["ip", "link", "show"]).decode('utf-8')
                    interfaces = [line.split(':')[1].strip() for line in output.split('\n') if ':' in line and not line.startswith(' ')]
                except:
                    interfaces = ["eth0", "wlan0"]  # Default fallback
    
    return list(set(interfaces))  # Remove duplicates

def interactive_menu():
    """Interactive menu for user to select options"""
    clear_screen()
    print_banner()
    
    print("\n" + "=" * 60)
    print(f"{Colors.BOLD}SETUP YOUR CAPTURE SESSION{Colors.ENDC}")
    print("=" * 60)
    
    # Get available interfaces
    interfaces = get_network_interfaces()
    
    # Option 1: Select interface
    print(f"\n{Colors.BOLD}[1] Select Network Interface:{Colors.ENDC}")
    for i, iface in enumerate(interfaces):
        print(f"    {i+1}. {iface}")
    print(f"    {len(interfaces)+1}. Any interface (default)")
    
    while True:
        try:
            iface_choice = input(f"\n{Colors.GREEN}Choose interface [1-{len(interfaces)+1}]: {Colors.ENDC}")
            if not iface_choice:
                selected_iface = None
                break
            
            iface_idx = int(iface_choice) - 1
            if 0 <= iface_idx < len(interfaces):
                selected_iface = interfaces[iface_idx]
                break
            elif iface_idx == len(interfaces):
                selected_iface = None
                break
            else:
                print(f"{Colors.RED}Invalid choice. Please try again.{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.RED}Please enter a number.{Colors.ENDC}")
    
    # Option 2: Capture limit
    print(f"\n{Colors.BOLD}[2] Capture Limit:{Colors.ENDC}")
    print("    How many packets do you want to capture?")
    print("    (Enter 0 for unlimited)")
    
    while True:
        try:
            count = input(f"\n{Colors.GREEN}Enter packet count [0]: {Colors.ENDC}")
            if not count:
                count = 0
                break
            count = int(count)
            if count >= 0:
                break
            else:
                print(f"{Colors.RED}Please enter a non-negative number.{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.RED}Please enter a valid number.{Colors.ENDC}")
    
    # Option 3: Timeout
    print(f"\n{Colors.BOLD}[3] Capture Duration:{Colors.ENDC}")
    print("    How long do you want to capture (in seconds)?")
    print("    (Enter 0 for no timeout)")
    
    while True:
        try:
            timeout = input(f"\n{Colors.GREEN}Enter timeout in seconds [0]: {Colors.ENDC}")
            if not timeout:
                timeout = 0
                break
            timeout = int(timeout)
            if timeout >= 0:
                break
            else:
                print(f"{Colors.RED}Please enter a non-negative number.{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.RED}Please enter a valid number.{Colors.ENDC}")
    
    # Option 4: BPF Filter
    print(f"\n{Colors.BOLD}[4] Packet Filter:{Colors.ENDC}")
    print("    Enter a BPF filter expression (optional)")
    print("    Examples:")
    print("      - tcp port 80          (HTTP traffic)")
    print("      - udp port 53          (DNS traffic)")
    print("      - tcp port 22          (SSH traffic)")
    print("      - host 192.168.1.1     (Traffic to/from this IP)")
    
    filter_expr = input(f"\n{Colors.GREEN}Enter filter [none]: {Colors.ENDC}")
    if not filter_expr:
        filter_expr = None
    
    # Option 5: Save PCAP
    print(f"\n{Colors.BOLD}[5] Save PCAP File:{Colors.ENDC}")
    print("    Do you want to save captured packets to a PCAP file?")
    
    save_pcap = input(f"\n{Colors.GREEN}Save PCAP? [y/N]: {Colors.ENDC}").lower()
    if save_pcap == 'y' or save_pcap == 'yes':
        pcap_filename = input(f"{Colors.GREEN}Enter filename [snifflyzer.pcap]: {Colors.ENDC}")
        if not pcap_filename:
            pcap_filename = "snifflyzer.pcap"
    else:
        pcap_filename = None
    
    # Option 6: Output directory
    print(f"\n{Colors.BOLD}[6] Output Directory:{Colors.ENDC}")
    print("    Where should reports and visualizations be saved?")
    
    output_dir = input(f"\n{Colors.GREEN}Enter directory [snifflyzer_output]: {Colors.ENDC}")
    if not output_dir:
        output_dir = "snifflyzer_output"
    
    # Confirm settings
    clear_screen()
    print_banner()
    print("\n" + "=" * 60)
    print(f"{Colors.BOLD}CAPTURE SETTINGS{Colors.ENDC}")
    print("=" * 60)
    print(f"Interface: {selected_iface or 'Any interface'}")
    print(f"Packet limit: {'Unlimited' if count == 0 else count}")
    print(f"Duration: {'No timeout' if timeout == 0 else f'{timeout} seconds'}")
    print(f"Filter: {filter_expr or 'None'}")
    print(f"PCAP file: {pcap_filename or 'Not saving'}")
    print(f"Output directory: {output_dir}")
    
    confirm = input(f"\n{Colors.GREEN}Start capture with these settings? [Y/n]: {Colors.ENDC}").lower()
    if confirm == 'n' or confirm == 'no':
        return interactive_menu()
    
    return {
        'interface': selected_iface,
        'count': count,
        'timeout': timeout,
        'filter': filter_expr,
        'pcap': pcap_filename,
        'output': output_dir
    }

def read_pcap_menu():
    """Menu for reading from existing PCAP files"""
    clear_screen()
    print_banner()
    
    print("\n" + "=" * 60)
    print(f"{Colors.BOLD}READ FROM PCAP FILE{Colors.ENDC}")
    print("=" * 60)
    
    # Get PCAP filename
    pcap_file = input(f"\n{Colors.GREEN}Enter PCAP filename: {Colors.ENDC}")
    if not pcap_file:
        print(f"{Colors.RED}No filename entered. Returning to main menu.{Colors.ENDC}")
        time.sleep(2)
        return main_menu()
    
    if not os.path.exists(pcap_file):
        print(f"{Colors.RED}File not found: {pcap_file}. Returning to main menu.{Colors.ENDC}")
        time.sleep(2)
        return main_menu()
    
    # Output directory
    output_dir = input(f"\n{Colors.GREEN}Enter output directory [snifflyzer_output]: {Colors.ENDC}")
    if not output_dir:
        output_dir = "snifflyzer_output"
    
    return {
        'read': pcap_file,
        'output': output_dir
    }

def main_menu():
    """Main menu for the application"""
    clear_screen()
    print_banner()
    
    print("\n" + "=" * 60)
    print(f"{Colors.BOLD}MAIN MENU{Colors.ENDC}")
    print("=" * 60)
    print(f"1. Start live packet capture")
    print(f"2. Analyze existing PCAP file")
    print(f"3. Exit")
    
    choice = input(f"\n{Colors.GREEN}Choose an option [1-3]: {Colors.ENDC}")
    
    if choice == '1':
        return interactive_menu()
    elif choice == '2':
        return read_pcap_menu()
    elif choice == '3':
        print(f"\n{Colors.BLUE}Thank you for using Snifflyzer! Goodbye.{Colors.ENDC}")
        sys.exit(0)
    else:
        print(f"{Colors.RED}Invalid choice. Please try again.{Colors.ENDC}")
        time.sleep(1)
        return main_menu()

def main():
    """Main function to set up and run the sniffer"""
    global session_duration
    
    # Show menu and get options
    options = main_menu()
    
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start time for session duration
    start_time = time.time()
    
    # Start sniffing or reading from PCAP
    if 'read' in options:
        clear_screen()
        print_banner()
        print(f"\n{Colors.BLUE}Reading packets from {options['read']}...{Colors.ENDC}")
        
        try:
            packets = rdpcap(options['read'])
            total_packets_to_read = len(packets)
            
            print(f"Found {total_packets_to_read} packets in file")
            
            # Process each packet
            for i, packet in enumerate(packets):
                packet_callback(packet)
                if i % 100 == 0:
                    progress = (i / total_packets_to_read) * 100
                    sys.stdout.write(f"\r{Colors.BLUE}Progress: {progress:.1f}% ({i}/{total_packets_to_read} packets){Colors.ENDC}")
                    sys.stdout.flush()
            
            detect_unusual_traffic()
            print(f"\n\n{Colors.GREEN}✓ Analysis complete!{Colors.ENDC}")
            
        except Exception as e:
            print(f"\n{Colors.RED}Error reading PCAP file: {e}{Colors.ENDC}")
            sys.exit(1)
    else:
        # Live capture
        clear_screen()
        print_banner()
        
        # Print sniffing parameters
        print(f"\n{Colors.BOLD}STARTING CAPTURE{Colors.ENDC}")
        print(f"  Interface: {options.get('interface') or 'default'}")
        print(f"  Count: {'unlimited' if options.get('count', 0) == 0 else options.get('count')}")
        timeout_val = 'none' if options.get('timeout', 0) == 0 else f"{options.get('timeout')}s"
        print(f"  Timeout: {timeout_val}")
        print(f"  Filter: {options.get('filter') or 'none'}")
        print(f"  PCAP output: {options.get('pcap') or 'none'}")
        print(f"\n{Colors.YELLOW}Press Ctrl+C to stop capture{Colors.ENDC}\n")
        
        # Start sniffing
        try:
            packets = sniff(
                iface=options.get('interface'),
                count=options.get('count') if options.get('count', 0) > 0 else None,
                timeout=options.get('timeout') if options.get('timeout', 0) > 0 else None,
                filter=options.get('filter'),
                prn=packet_callback,
                store=bool(options.get('pcap')),
                stop_filter=lambda p: not sniff_active
            )
            
            # Save PCAP if requested
            if options.get('pcap') and packets:
                wrpcap(options.get('pcap'), packets)
                print(f"\n{Colors.GREEN}✓ Saved {len(packets)} packets to {options.get('pcap')}{Colors.ENDC}")
                
        except Exception as e:
            print(f"\n{Colors.RED}Error during packet capture: {e}{Colors.ENDC}")
            sys.exit(1)
    
    # Calculate session duration
    session_duration = time.time() - start_time
    
    # Run final analysis
    detect_unusual_traffic()
    
    # Print summary report
    print_summary_report()
    
    # Generate visualizations
    if options.get('output'):
        try:
            generate_visualizations(options.get('output'))
        except Exception as e:
            print(f"\n{Colors.RED}Error generating visualizations: {e}{Colors.ENDC}")
    
    print(f"\n{Colors.GREEN}Session completed. Thank you for using Snifflyzer!{Colors.ENDC}")
    
    # Ask if user wants to return to main menu
    restart = input(f"\n{Colors.GREEN}Return to main menu? [Y/n]: {Colors.ENDC}").lower()
    if restart != 'n' and restart != 'no':
        # Reset global variables
        global packet_stats, ip_connections, dns_queries, arp_cache, login_attempts, suspicious_activities, total_packets, severity_counts
        packet_stats = Counter()
        ip_connections = defaultdict(Counter)
        dns_queries = {}
        arp_cache = {}
        login_attempts = defaultdict(Counter)
        suspicious_activities = []
        total_packets = 0
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        
        # Return to main menu
        main()


if __name__ == "__main__":
    main()