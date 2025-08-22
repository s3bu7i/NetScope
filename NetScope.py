#!/usr/bin/env python3
"""
NetScope Ultimate - Advanced Network Analysis & Monitoring Suite
A comprehensive unified network diagnostics, monitoring, and analysis tool
Combines all features from both NetScope versions plus new unique functions
"""

import os
import sys
import socket
import subprocess
import platform
import time
import threading
import json
import re
from datetime import datetime
from collections import defaultdict
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import hashlib
import random

try:
    import psutil
    import requests
except ImportError:
    print("Installing required dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "requests"])
    import psutil
    import requests


class Colors:
    """ANSI color codes for enhanced terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    WHITE = '\033[37m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'


class NetworkSecurityAnalyzer:
    """Advanced security analysis functions"""
    
    def __init__(self):
        self.security_alerts = []
        self.suspicious_ports = [1337, 31337, 12345, 54321, 6666, 6667]
        self.common_backdoor_ports = [2222, 4444, 5555, 7777, 8888, 9999]
    
    def check_suspicious_connections(self):
        """Check for suspicious network connections"""
        suspicious = []
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                if conn.raddr.port in self.suspicious_ports:
                    suspicious.append({
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'reason': 'Suspicious port'
                    })
        
        return suspicious
    
    def analyze_network_security(self):
        """Comprehensive network security analysis"""
        security_report = {
            'open_ports': [],
            'suspicious_connections': self.check_suspicious_connections(),
            'network_interfaces': len(psutil.net_if_addrs()),
            'active_connections': len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
        }
        return security_report


class NetworkPerformanceMonitor:
    """Real-time network performance monitoring"""
    
    def __init__(self):
        self.baseline_stats = {}
        self.performance_history = []
    
    def get_interface_speed(self, interface):
        """Calculate interface speed and utilization"""
        stats = psutil.net_io_counters(pernic=True)
        if interface in stats:
            return {
                'bytes_sent': stats[interface].bytes_sent,
                'bytes_recv': stats[interface].bytes_recv,
                'packets_sent': stats[interface].packets_sent,
                'packets_recv': stats[interface].packets_recv,
                'errors': stats[interface].errin + stats[interface].errout,
                'drops': stats[interface].dropin + stats[interface].dropout
            }
        return None
    
    def monitor_bandwidth_usage(self, duration=5):
        """Monitor bandwidth usage over time"""
        initial = psutil.net_io_counters()
        time.sleep(duration)
        final = psutil.net_io_counters()
        
        bytes_sent = final.bytes_sent - initial.bytes_sent
        bytes_recv = final.bytes_recv - initial.bytes_recv
        
        return {
            'upload_speed': bytes_sent / duration,
            'download_speed': bytes_recv / duration,
            'total_speed': (bytes_sent + bytes_recv) / duration
        }


class AdvancedNetworkAnalyzer:
    def __init__(self):
        self.system_info = self.get_system_info()
        self.network_interfaces = {}
        self.traffic_stats = {}
        self.monitoring = False
        self.system = platform.system()
        self.local_ip = None
        self.gateway_ip = None
        self.public_ip = None
        self.security_analyzer = NetworkSecurityAnalyzer()
        self.performance_monitor = NetworkPerformanceMonitor()
        self.scan_history = []

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║  {Colors.BOLD}███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ███████╗             {Colors.ENDC}{Colors.CYAN}║
║  {Colors.BOLD}████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔════╝             {Colors.ENDC}{Colors.CYAN}║
║  {Colors.BOLD}██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██████╗              {Colors.ENDC}{Colors.CYAN}║
║  {Colors.BOLD}██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██╔═══╝              {Colors.ENDC}{Colors.CYAN}║
║  {Colors.BOLD}██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝███████╗             {Colors.ENDC}{Colors.CYAN}║
║  {Colors.BOLD}╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝             {Colors.ENDC}{Colors.CYAN}║
║                                                                          ║
║                    {Colors.BOLD}{Colors.YELLOW}🚀 ULTIMATE NETWORK ANALYSIS SUITE 🚀{Colors.ENDC}{Colors.CYAN}                   ║
║           {Colors.MAGENTA}Advanced Diagnostics • Security Analysis • Performance{Colors.ENDC}{Colors.CYAN}        ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.YELLOW}System: {Colors.ENDC}{self.system_info['system']} | {Colors.YELLOW}Host: {Colors.ENDC}{self.system_info['hostname']}
{Colors.YELLOW}Time: {Colors.ENDC}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {Colors.YELLOW}Version: {Colors.ENDC}Ultimate 3.0
"""
        print(banner)

    def get_system_info(self):
        return {
            'system': platform.system(),
            'hostname': socket.gethostname(),
            'platform': platform.platform(),
            'processor': platform.processor() or 'Unknown',
            'architecture': platform.architecture()[0],
            'python_version': platform.python_version()
        }

    def execute_command(self, command, timeout=30):
        """Execute system command with timeout"""
        try:
            if isinstance(command, str):
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
            else:
                result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1

    def get_local_ip(self):
        """Get local IP address using multiple methods"""
        if self.local_ip:
            return self.local_ip
            
        try:
            # Method 1: Connect to external IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                self.local_ip = s.getsockname()[0]
                return self.local_ip
        except:
            pass
        
        try:
            # Method 2: Use hostname
            self.local_ip = socket.gethostbyname(socket.gethostname())
            if not self.local_ip.startswith('127.'):
                return self.local_ip
        except:
            pass
        
        # Method 3: Parse network interfaces
        try:
            interfaces = psutil.net_if_addrs()
            for interface, addrs in interfaces.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        self.local_ip = addr.address
                        return self.local_ip
        except:
            pass
            
        return "Unable to determine"

    def get_gateway_ip(self):
        """Get default gateway IP using multiple methods"""
        if self.gateway_ip:
            return self.gateway_ip
            
        try:
            if self.system == "Windows":
                output, _, _ = self.execute_command("ipconfig")
                for line in output.split('\n'):
                    if 'Default Gateway' in line:
                        gateway = line.split(':')[-1].strip()
                        if gateway and gateway != "":
                            self.gateway_ip = gateway
                            return gateway
            else:
                # Try ip route first
                output, _, code = self.execute_command("ip route show default")
                if code == 0 and output:
                    parts = output.split()
                    if 'via' in parts:
                        idx = parts.index('via')
                        if idx + 1 < len(parts):
                            self.gateway_ip = parts[idx + 1]
                            return self.gateway_ip
                
                # Fallback to route command
                output, _, _ = self.execute_command("route -n | grep '^0.0.0.0'")
                if output:
                    self.gateway_ip = output.split()[1]
                    return self.gateway_ip
        except:
            pass
        return "Unable to determine"

    def get_public_ip_advanced(self):
        """Get public IP with ISP and location info"""
        if self.public_ip:
            return {'ip': self.public_ip}
            
        services = [
            'http://ipinfo.io/json',
            'https://api.ipify.org?format=json',
            'http://ip-api.com/json/',
            'https://httpbin.org/ip'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if 'ip' in data:
                        self.public_ip = data['ip']
                        return data
                    elif 'query' in data:
                        self.public_ip = data['query']
                        return data
                    elif 'origin' in data:
                        self.public_ip = data['origin']
                        return {'ip': data['origin']}
            except:
                continue
        
        # Fallback using curl
        curl_services = [
            "curl -s ifconfig.me",
            "curl -s icanhazip.com",
            "curl -s ident.me"
        ]
        
        for service in curl_services:
            try:
                output, _, code = self.execute_command(service)
                if code == 0 and output:
                    self.public_ip = output.strip()
                    return {'ip': self.public_ip}
            except:
                continue
                
        return {'ip': 'Unable to determine'}

    def get_network_interfaces_advanced(self):
        """Get comprehensive network interface information"""
        interfaces = {}
        
        try:
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface_name, addresses in net_if_addrs.items():
                if interface_name in net_if_stats:
                    stats = net_if_stats[interface_name]
                    interfaces[interface_name] = {
                        'addresses': [],
                        'is_up': stats.isup,
                        'duplex': stats.duplex,
                        'speed': stats.speed,
                        'mtu': stats.mtu,
                        'flags': []
                    }
                    
                    # Add flags
                    if stats.isup:
                        interfaces[interface_name]['flags'].append('UP')
                    if stats.duplex == 2:
                        interfaces[interface_name]['flags'].append('FULL_DUPLEX')
                    elif stats.duplex == 1:
                        interfaces[interface_name]['flags'].append('HALF_DUPLEX')
                    
                    for addr in addresses:
                        addr_info = {
                            'family': str(addr.family),
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast,
                            'ptp': addr.ptp
                        }
                        interfaces[interface_name]['addresses'].append(addr_info)
        except Exception as e:
            print(f"Error getting interfaces: {e}")
        
        self.network_interfaces = interfaces
        return interfaces

    def get_dns_servers_advanced(self):
        """Get DNS servers with additional info"""
        dns_servers = []
        try:
            if self.system == "Windows":
                # Get from nslookup
                output, _, _ = self.execute_command('nslookup google.com')
                lines = output.split('\n')
                for line in lines:
                    if 'Server:' in line:
                        dns_ip = line.split(':')[-1].strip()
                        if dns_ip and dns_ip not in ['127.0.0.1', 'localhost']:
                            dns_servers.append(dns_ip)
                
                # Get from ipconfig
                output, _, _ = self.execute_command('ipconfig /all')
                for line in output.split('\n'):
                    if 'DNS Servers' in line:
                        dns_ip = line.split(':')[-1].strip()
                        if dns_ip and dns_ip not in dns_servers:
                            dns_servers.append(dns_ip)
            else:
                # Linux/Unix
                try:
                    with open('/etc/resolv.conf', 'r') as f:
                        for line in f:
                            if line.startswith('nameserver'):
                                dns_servers.append(line.split()[1])
                except:
                    pass
                
                # Try systemd-resolve
                output, _, code = self.execute_command('systemd-resolve --status')
                if code == 0:
                    for line in output.split('\n'):
                        if 'DNS Servers:' in line:
                            dns_ip = line.split(':')[-1].strip()
                            if dns_ip and dns_ip not in dns_servers:
                                dns_servers.append(dns_ip)
        except:
            pass
        
        return dns_servers if dns_servers else ["Unable to determine"]

    def advanced_network_scan(self, network=None, aggressive=False):
        """Advanced network scanning with service detection"""
        if not network:
            local_ip = self.get_local_ip()
            if local_ip == "Unable to determine":
                return {}
            
            try:
                network_obj = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            except:
                return {}
        else:
            try:
                network_obj = ipaddress.IPv4Network(network, strict=False)
            except:
                return {}
        
        devices = {}
        
        def scan_host_advanced(ip):
            host_info = {'ip': str(ip), 'hostname': 'Unknown', 'services': [], 'os_guess': 'Unknown'}
            
            # Ping test
            if self.system == "Windows":
                cmd = f"ping -n 1 -w 1000 {ip}"
            else:
                cmd = f"ping -c 1 -W 1 {ip}"
            
            _, _, code = self.execute_command(cmd)
            if code != 0:
                return None
            
            # Get hostname
            try:
                host_info['hostname'] = socket.gethostbyaddr(str(ip))[0]
            except:
                pass
            
            # Quick port scan if aggressive
            if aggressive:
                common_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389]
                open_ports = []
                
                for port in common_ports:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(0.5)
                            if sock.connect_ex((str(ip), port)) == 0:
                                open_ports.append(port)
                    except:
                        pass
                
                host_info['open_ports'] = open_ports
                
                # Basic OS detection based on open ports
                if 3389 in open_ports or 135 in open_ports:
                    host_info['os_guess'] = 'Windows'
                elif 22 in open_ports:
                    host_info['os_guess'] = 'Linux/Unix'
            
            return host_info
        
        print(f"\n{Colors.YELLOW}🔍 Advanced scanning network {network_obj}...{Colors.ENDC}")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            hosts = list(network_obj.hosts())[:100]  # Limit to first 100 IPs
            futures = [executor.submit(scan_host_advanced, ip) for ip in hosts]
            
            for i, future in enumerate(futures):
                try:
                    result = future.result(timeout=5)
                    if result:
                        devices[result['ip']] = result
                except:
                    pass
                
                if i % 10 == 0:
                    print(f"\r{Colors.CYAN}Progress: {i+1}/{len(futures)} hosts scanned{Colors.ENDC}", end="")
        
        print(f"\r{Colors.GREEN}✅ Advanced network scan complete! Found {len(devices)} devices{Colors.ENDC}\n")
        
        # Store scan results
        self.scan_history.append({
            'timestamp': datetime.now().isoformat(),
            'network': str(network_obj),
            'devices_found': len(devices),
            'devices': devices
        })
        
        return devices

    def port_scanner_advanced(self, target, port_range="common", timeout=1):
        """Advanced port scanner with service detection"""
        if port_range == "common":
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
        elif port_range == "extended":
            ports = list(range(1, 1001))
        elif isinstance(port_range, list):
            ports = port_range
        else:
            ports = [21, 22, 23, 25, 53, 80, 443]
        
        open_ports = []
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt'
        }
        
        def scan_port_advanced(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        service = services.get(port, 'Unknown')
                        
                        # Try to grab banner
                        banner = ""
                        try:
                            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                            banner = sock.recv(1024).decode('utf-8', errors='ignore')[:100]
                        except:
                            pass
                        
                        return {
                            'port': port,
                            'service': service,
                            'banner': banner.strip() if banner else 'No banner'
                        }
            except:
                pass
            return None
        
        print(f"\n{Colors.YELLOW}🔍 Scanning {len(ports)} ports on {target}...{Colors.ENDC}")
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port_advanced, port) for port in ports]
            
            for i, future in enumerate(futures):
                try:
                    result = future.result(timeout=3)
                    if result:
                        open_ports.append(result)
                except:
                    pass
                
                if i % 50 == 0:
                    print(f"\r{Colors.CYAN}Progress: {i+1}/{len(ports)} ports scanned{Colors.ENDC}", end="")
        
        print(f"\r{Colors.GREEN}✅ Port scan complete! Found {len(open_ports)} open ports{Colors.ENDC}\n")
        return open_ports

    def network_performance_analysis(self):
        """Comprehensive network performance analysis"""
        print(f"\n{Colors.HEADER}📊 NETWORK PERFORMANCE ANALYSIS{Colors.ENDC}")
        print("=" * 70)
        
        # Bandwidth monitoring
        print(f"\n{Colors.YELLOW}📈 Bandwidth Analysis (5 second sample):{Colors.ENDC}")
        bandwidth = self.performance_monitor.monitor_bandwidth_usage(5)
        
        print(f"   Upload Speed:   {Colors.GREEN}{self.format_bytes(bandwidth['upload_speed'])}/s{Colors.ENDC}")
        print(f"   Download Speed: {Colors.GREEN}{self.format_bytes(bandwidth['download_speed'])}/s{Colors.ENDC}")
        print(f"   Total Speed:    {Colors.GREEN}{self.format_bytes(bandwidth['total_speed'])}/s{Colors.ENDC}")
        
        # Interface statistics
        print(f"\n{Colors.YELLOW}🔌 Interface Performance:{Colors.ENDC}")
        net_stats = psutil.net_io_counters(pernic=True)
        
        for interface, stats in net_stats.items():
            if stats.bytes_sent > 0 or stats.bytes_recv > 0:
                error_rate = (stats.errin + stats.errout) / max(1, stats.packets_sent + stats.packets_recv) * 100
                print(f"\n   {Colors.CYAN}{interface}:{Colors.ENDC}")
                print(f"     Sent:     {Colors.GREEN}{self.format_bytes(stats.bytes_sent)}{Colors.ENDC} ({stats.packets_sent:,} packets)")
                print(f"     Received: {Colors.GREEN}{self.format_bytes(stats.bytes_recv)}{Colors.ENDC} ({stats.packets_recv:,} packets)")
                if error_rate > 1:
                    print(f"     Errors:   {Colors.RED}{error_rate:.2f}%{Colors.ENDC}")
                else:
                    print(f"     Errors:   {Colors.GREEN}{error_rate:.2f}%{Colors.ENDC}")
        
        # Latency testing
        print(f"\n{Colors.YELLOW}⚡ Latency Testing:{Colors.ENDC}")
        test_hosts = [
            ('Google DNS', '8.8.8.8'),
            ('Cloudflare DNS', '1.1.1.1'),
            ('Gateway', self.get_gateway_ip())
        ]
        
        for name, host in test_hosts:
            if host != "Unable to determine":
                latency = self.ping_latency(host)
                if latency:
                    if latency < 50:
                        color = Colors.GREEN
                    elif latency < 100:
                        color = Colors.YELLOW
                    else:
                        color = Colors.RED
                    print(f"   {name:<15}: {color}{latency:.2f}ms{Colors.ENDC}")
                else:
                    print(f"   {name:<15}: {Colors.RED}Failed{Colors.ENDC}")

    def ping_latency(self, host, count=3):
        """Measure ping latency"""
        try:
            if self.system == "Windows":
                cmd = f"ping -n {count} {host}"
            else:
                cmd = f"ping -c {count} {host}"
            
            output, _, code = self.execute_command(cmd)
            if code == 0:
                # Extract average time
                if self.system == "Windows":
                    matches = re.findall(r'time=(\d+)ms', output)
                else:
                    matches = re.findall(r'time=(\d+\.?\d*) ms', output)
                
                if matches:
                    times = [float(t) for t in matches]
                    return sum(times) / len(times)
        except:
            pass
        return None

    def network_security_audit(self):
        """Comprehensive network security audit"""
        print(f"\n{Colors.HEADER}🔒 NETWORK SECURITY AUDIT{Colors.ENDC}")
        print("=" * 70)
        
        # Security analysis
        security_report = self.security_analyzer.analyze_network_security()
        
        print(f"\n{Colors.YELLOW}🛡️ Security Overview:{Colors.ENDC}")
        print(f"   Active Connections:     {Colors.GREEN}{security_report['active_connections']}{Colors.ENDC}")
        print(f"   Network Interfaces:     {Colors.GREEN}{security_report['network_interfaces']}{Colors.ENDC}")
        
        # Suspicious connections
        if security_report['suspicious_connections']:
            print(f"\n{Colors.RED}⚠️ Suspicious Connections Found:{Colors.ENDC}")
            for conn in security_report['suspicious_connections']:
                print(f"   {Colors.RED}•{Colors.ENDC} {conn['local']} → {conn['remote']} ({conn['reason']})")
        else:
            print(f"\n{Colors.GREEN}✅ No suspicious connections detected{Colors.ENDC}")
        
        # Port analysis on local system
        print(f"\n{Colors.YELLOW}🔍 Local Open Ports:{Colors.ENDC}")
        listening_ports = []
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            if conn.status == 'LISTEN':
                listening_ports.append({
                    'port': conn.laddr.port,
                    'address': conn.laddr.ip,
                    'pid': conn.pid
                })
        
        # Group by port
        port_groups = defaultdict(list)
        for port_info in listening_ports:
            port_groups[port_info['port']].append(port_info)
        
        for port, infos in sorted(port_groups.items()):
            service_name = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                80: 'HTTP', 110: 'POP3', 135: 'RPC', 143: 'IMAP', 443: 'HTTPS',
                993: 'IMAPS', 995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL',
                3306: 'MySQL'
            }.get(port, 'Unknown')
            
            addresses = [info['address'] for info in infos]
            if '0.0.0.0' in addresses or '::' in addresses:
                risk_color = Colors.YELLOW if port in [80, 443, 22] else Colors.RED
            else:
                risk_color = Colors.GREEN
            
            print(f"   {risk_color}Port {port:<6}{Colors.ENDC} ({service_name}) - {', '.join(set(addresses))}")

    def network_topology_discovery(self):
        """Discover and map network topology"""
        print(f"\n{Colors.HEADER}🗺️ NETWORK TOPOLOGY DISCOVERY{Colors.ENDC}")
        print("=" * 70)
        
        # Get routing table
        print(f"\n{Colors.YELLOW}🛣️ Routing Table:{Colors.ENDC}")
        try:
            if self.system == "Windows":
                output, _, _ = self.execute_command("route print")
            else:
                output, _, _ = self.execute_command("ip route")
            
            routes = output.split('\n')[:15]  # Show first 15 routes
            for route in routes:
                if route.strip():
                    print(f"   {Colors.GREEN}{route}{Colors.ENDC}")
        except:
            print(f"   {Colors.RED}Unable to retrieve routing table{Colors.ENDC}")
        
        # ARP table
        print(f"\n{Colors.YELLOW}📋 ARP Table (IP-MAC mappings):{Colors.ENDC}")
        arp_entries = self.get_arp_table()
        
        if arp_entries:
            for ip, mac in list(arp_entries.items())[:10]:
                print(f"   {Colors.CYAN}{ip:<18}{Colors.ENDC} → {Colors.GREEN}{mac}{Colors.ENDC}")
        else:
            print(f"   {Colors.RED}Unable to retrieve ARP table{Colors.ENDC}")
        
        # Traceroute to external host
        print(f"\n{Colors.YELLOW}🌐 Network Path to Google (8.8.8.8):{Colors.ENDC}")
        try:
            if self.system == "Windows":
                output, _, _ = self.execute_command("tracert -h 8 8.8.8.8")
            else:
                output, _, _ = self.execute_command("traceroute -m 8 8.8.8.8")
            
            hops = output.split('\n')[:8]  # Show first 8 hops
            for hop in hops:
                if hop.strip() and not hop.startswith('traceroute'):
                    print(f"   {Colors.GREEN}{hop}{Colors.ENDC}")
        except:
            print(f"   {Colors.RED}Traceroute failed{Colors.ENDC}")

    def get_arp_table(self):
        """Get ARP table entries"""
        arp_entries = {}
        try:
            if self.system == "Windows":
                output, _, _ = self.execute_command("arp -a")
            else:
                output, _, _ = self.execute_command("arp -a")
            
            for line in output.split('\n'):
                if '.' in line and (':' in line or '-' in line):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0].replace('(', '').replace(')', '')
                        mac = parts[1] if len(parts) > 1 else "Unknown"
                        if self.is_valid_ip(ip):
                            arp_entries[ip] = mac
        except:
            pass
        return arp_entries

    def is_valid_ip(self, ip):
        """Check if string is valid IP address"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except:
            return False

    def wifi_analyzer(self):
        """Analyze WiFi networks (Windows/Linux)"""
        print(f"\n{Colors.HEADER}📶 WIFI NETWORK ANALYZER{Colors.ENDC}")
        print("=" * 70)
        
        try:
            if self.system == "Windows":
                # Get available WiFi networks
                output, _, code = self.execute_command("netsh wlan show profiles")
                if code == 0:
                    print(f"\n{Colors.YELLOW}📡 Available WiFi Profiles:{Colors.ENDC}")
                    profiles = []
                    for line in output.split('\n'):
                        if 'All User Profile' in line:
                            profile = line.split(':')[1].strip()
                            profiles.append(profile)
                            print(f"   {Colors.GREEN}• {profile}{Colors.ENDC}")
                    
                    # Get detailed info for current connection
                    output2, _, _ = self.execute_command("netsh wlan show interfaces")
                    if output2:
                        print(f"\n{Colors.YELLOW}📶 Current WiFi Connection:{Colors.ENDC}")
                        for line in output2.split('\n'):
                            line = line.strip()
                            if any(keyword in line for keyword in ['SSID', 'Signal', 'Channel', 'Authentication']):
                                print(f"   {Colors.CYAN}{line}{Colors.ENDC}")
                else:
                    print(f"   {Colors.RED}Unable to retrieve WiFi information{Colors.ENDC}")
            else:
                # Linux WiFi analysis
                output, _, code = self.execute_command("iwconfig")
                if code == 0:
                    print(f"\n{Colors.YELLOW}📡 Wireless Interfaces:{Colors.ENDC}")
                    for line in output.split('\n'):
                        if line and not line.startswith(' '):
                            print(f"   {Colors.GREEN}{line}{Colors.ENDC}")
                
                # Try to scan for networks
                output, _, code = self.execute_command("iwlist scan 2>/dev/null | grep ESSID")
                if code == 0 and output:
                    print(f"\n{Colors.YELLOW}📶 Available Networks:{Colors.ENDC}")
                    for line in output.split('\n')[:10]:  # Show first 10
                        if 'ESSID' in line:
                            ssid = line.split('ESSID:')[1].strip().replace('"', '')
                            if ssid:
                                print(f"   {Colors.GREEN}• {ssid}{Colors.ENDC}")
        except:
            print(f"   {Colors.RED}WiFi analysis not available on this system{Colors.ENDC}")

    def dns_analysis(self):
        """Advanced DNS analysis"""
        print(f"\n{Colors.HEADER}🔍 DNS ANALYSIS{Colors.ENDC}")
        print("=" * 70)
        
        # Get DNS servers
        dns_servers = self.get_dns_servers_advanced()
        print(f"\n{Colors.YELLOW}🌐 DNS Servers:{Colors.ENDC}")
        for i, dns in enumerate(dns_servers, 1):
            print(f"   {i}. {Colors.GREEN}{dns}{Colors.ENDC}")
        
        # DNS resolution testing
        print(f"\n{Colors.YELLOW}⚡ DNS Resolution Performance:{Colors.ENDC}")
        test_domains = ['google.com', 'github.com', 'stackoverflow.com', 'wikipedia.org']
        
        for domain in test_domains:
            start_time = time.time()
            try:
                ip = socket.gethostbyname(domain)
                resolve_time = (time.time() - start_time) * 1000
                print(f"   {domain:<20}: {Colors.GREEN}{ip:<15}{Colors.ENDC} ({resolve_time:.2f}ms)")
            except:
                print(f"   {domain:<20}: {Colors.RED}Resolution failed{Colors.ENDC}")
        
        # Reverse DNS testing
        print(f"\n{Colors.YELLOW}🔄 Reverse DNS Testing:{Colors.ENDC}")
        test_ips = ['8.8.8.8', '1.1.1.1', self.get_gateway_ip()]
        
        for ip in test_ips:
            if ip != "Unable to determine":
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    print(f"   {ip:<15}: {Colors.GREEN}{hostname}{Colors.ENDC}")
                except:
                    print(f"   {ip:<15}: {Colors.RED}No reverse record{Colors.ENDC}")

    def format_bytes(self, bytes_val):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"

    def export_results(self):
        """Export scan results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"netscope_results_{timestamp}.json"
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'system_info': self.system_info,
            'network_info': {
                'local_ip': self.get_local_ip(),
                'gateway_ip': self.get_gateway_ip(),
                'public_ip_info': self.get_public_ip_advanced(),
                'dns_servers': self.get_dns_servers_advanced()
            },
            'interfaces': self.get_network_interfaces_advanced(),
            'scan_history': self.scan_history,
            'traffic_stats': psutil.net_io_counters()._asdict()
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            print(f"\n{Colors.GREEN}✅ Results exported to {filename}{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.RED}❌ Export failed: {e}{Colors.ENDC}")

    def show_main_menu(self):
        """Display enhanced main menu"""
        menu = f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════════════════╗
║                              MAIN MENU                                  ║
╠══════════════════════════════════════════════════════════════════════════╣{Colors.ENDC}
{Colors.CYAN}║  1. 🌐  Network Overview & Basic Info                                   ║
║  2. 🔌  Advanced Interface Analysis                                     ║
║  3. 🔍  Network Device Discovery                                        ║
║  4. 🔐  Advanced Port Scanner                                           ║
║  5. 📊  Network Performance Analysis                                    ║
║  6. 🛡️   Network Security Audit                                         ║
║  7. 🗺️   Network Topology Discovery                                     ║
║  8. 📶  WiFi Network Analyzer                                           ║
║  9. 🔍  DNS Analysis & Testing                                          ║
║ 10. 📈  Real-time Traffic Monitor                                       ║
║ 11. 🎯  Custom Network Tools                                            ║
║ 12. 📄  Export Results                                                   ║
║ 13. 📊  System Information                                              ║
║ 14. ❓  Help & Documentation                                            ║
║ 15. 🚪  Exit                                                            ║{Colors.ENDC}
{Colors.HEADER}╚══════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
        return menu

    def network_overview(self):
        """Comprehensive network overview"""
        print(f"\n{Colors.HEADER}🌐 COMPREHENSIVE NETWORK OVERVIEW{Colors.ENDC}")
        print("=" * 70)
        
        # Basic network info
        local_ip = self.get_local_ip()
        gateway_ip = self.get_gateway_ip()
        public_info = self.get_public_ip_advanced()
        dns_servers = self.get_dns_servers_advanced()
        
        print(f"\n{Colors.YELLOW}🔗 Network Configuration:{Colors.ENDC}")
        print(f"   Local IP:       {Colors.GREEN}{local_ip}{Colors.ENDC}")
        print(f"   Gateway:        {Colors.GREEN}{gateway_ip}{Colors.ENDC}")
        print(f"   Public IP:      {Colors.GREEN}{public_info.get('ip', 'Unknown')}{Colors.ENDC}")
        
        if 'org' in public_info:
            print(f"   ISP:            {Colors.GREEN}{public_info['org']}{Colors.ENDC}")
        if 'city' in public_info:
            print(f"   Location:       {Colors.GREEN}{public_info['city']}, {public_info.get('region', '')}{Colors.ENDC}")
        
        print(f"\n{Colors.YELLOW}🌐 DNS Configuration:{Colors.ENDC}")
        for i, dns in enumerate(dns_servers[:3], 1):
            print(f"   DNS {i}:          {Colors.GREEN}{dns}{Colors.ENDC}")
        
        # Quick connectivity test
        print(f"\n{Colors.YELLOW}⚡ Connectivity Test:{Colors.ENDC}")
        test_hosts = [('Google', '8.8.8.8'), ('Cloudflare', '1.1.1.1')]
        
        for name, host in test_hosts:
            latency = self.ping_latency(host, 1)
            if latency:
                print(f"   {name:<12}:   {Colors.GREEN}{latency:.1f}ms{Colors.ENDC}")
            else:
                print(f"   {name:<12}:   {Colors.RED}Failed{Colors.ENDC}")

    def advanced_interface_analysis(self):
        """Advanced network interface analysis"""
        print(f"\n{Colors.HEADER}🔌 ADVANCED INTERFACE ANALYSIS{Colors.ENDC}")
        print("=" * 70)
        
        interfaces = self.get_network_interfaces_advanced()
        net_stats = psutil.net_io_counters(pernic=True)
        
        for name, info in interfaces.items():
            if info['is_up']:
                print(f"\n{Colors.YELLOW}📡 Interface: {name}{Colors.ENDC}")
                print(f"   Status:         {Colors.GREEN}UP{Colors.ENDC}")
                print(f"   MTU:            {Colors.GREEN}{info['mtu']}{Colors.ENDC}")
                
                if info['speed'] > 0:
                    print(f"   Speed:          {Colors.GREEN}{info['speed']} Mbps{Colors.ENDC}")
                
                print(f"   Flags:          {Colors.GREEN}{', '.join(info['flags'])}{Colors.ENDC}")
                
                # IP addresses
                for addr in info['addresses']:
                    family = addr['family']
                    if 'AF_INET' in family:
                        print(f"   IPv4:           {Colors.GREEN}{addr['address']}{Colors.ENDC}")
                        if addr['netmask']:
                            print(f"   Netmask:        {Colors.GREEN}{addr['netmask']}{Colors.ENDC}")
                        if addr['broadcast']:
                            print(f"   Broadcast:      {Colors.GREEN}{addr['broadcast']}{Colors.ENDC}")
                    elif 'AF_PACKET' in family or 'AF_LINK' in family:
                        print(f"   MAC Address:    {Colors.GREEN}{addr['address']}{Colors.ENDC}")
                
                # Traffic statistics
                if name in net_stats:
                    stats = net_stats[name]
                    if stats.bytes_sent > 0 or stats.bytes_recv > 0:
                        print(f"   Bytes Sent:     {Colors.GREEN}{self.format_bytes(stats.bytes_sent)}{Colors.ENDC}")
                        print(f"   Bytes Received: {Colors.GREEN}{self.format_bytes(stats.bytes_recv)}{Colors.ENDC}")
                        print(f"   Packets Sent:   {Colors.GREEN}{stats.packets_sent:,}{Colors.ENDC}")
                        print(f"   Packets Recv:   {Colors.GREEN}{stats.packets_recv:,}{Colors.ENDC}")
                        
                        if stats.errin + stats.errout > 0:
                            print(f"   Errors:         {Colors.RED}{stats.errin + stats.errout}{Colors.ENDC}")

    def custom_network_tools(self):
        """Custom network diagnostic tools"""
        while True:
            print(f"\n{Colors.HEADER}🎯 CUSTOM NETWORK TOOLS{Colors.ENDC}")
            print("=" * 70)
            
            print(f"\n{Colors.CYAN}1.{Colors.ENDC} Custom Ping Test")
            print(f"{Colors.CYAN}2.{Colors.ENDC} Custom Port Range Scanner")
            print(f"{Colors.CYAN}3.{Colors.ENDC} Network Latency Matrix")
            print(f"{Colors.CYAN}4.{Colors.ENDC} Bandwidth Speed Test")
            print(f"{Colors.CYAN}5.{Colors.ENDC} Custom Traceroute")
            print(f"{Colors.CYAN}6.{Colors.ENDC} Network Connectivity Monitor")
            print(f"{Colors.CYAN}0.{Colors.ENDC} Back to Main Menu")
            
            choice = input(f"\n{Colors.YELLOW}Select tool [0-6]: {Colors.ENDC}")
            
            if choice == '1':
                self.custom_ping_test()
            elif choice == '2':
                self.custom_port_scanner()
            elif choice == '3':
                self.network_latency_matrix()
            elif choice == '4':
                self.bandwidth_speed_test()
            elif choice == '5':
                self.custom_traceroute()
            elif choice == '6':
                self.connectivity_monitor()
            elif choice == '0':
                break
            
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.ENDC}")

    def custom_ping_test(self):
        """Custom ping test with user parameters"""
        target = input(f"\n{Colors.YELLOW}Enter target (IP/hostname): {Colors.ENDC}")
        if not target:
            return
        
        try:
            count = int(input(f"{Colors.YELLOW}Number of pings [4]: {Colors.ENDC}") or "4")
            timeout = int(input(f"{Colors.YELLOW}Timeout in seconds [5]: {Colors.ENDC}") or "5")
        except:
            count, timeout = 4, 5
        
        print(f"\n{Colors.GREEN}Pinging {target} with {count} packets...{Colors.ENDC}\n")
        
        if self.system == "Windows":
            cmd = f"ping -n {count} -w {timeout*1000} {target}"
        else:
            cmd = f"ping -c {count} -W {timeout} {target}"
        
        output, _, code = self.execute_command(cmd)
        
        if code == 0:
            print(f"{Colors.GREEN}{output}{Colors.ENDC}")
        else:
            print(f"{Colors.RED}Ping failed or timed out{Colors.ENDC}")

    def custom_port_scanner(self):
        """Custom port range scanner"""
        target = input(f"\n{Colors.YELLOW}Enter target IP: {Colors.ENDC}")
        if not target:
            return
        
        print(f"\n{Colors.CYAN}Port Range Options:{Colors.ENDC}")
        print(f"1. Common ports (21,22,23,25,53,80,443,etc.)")
        print(f"2. Well-known ports (1-1023)")
        print(f"3. Custom range")
        
        choice = input(f"\n{Colors.YELLOW}Select option [1]: {Colors.ENDC}") or "1"
        
        if choice == "1":
            ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5432, 3306]
        elif choice == "2":
            ports = list(range(1, 1024))
        elif choice == "3":
            try:
                start = int(input(f"{Colors.YELLOW}Start port: {Colors.ENDC}"))
                end = int(input(f"{Colors.YELLOW}End port: {Colors.ENDC}"))
                ports = list(range(start, end + 1))
            except:
                print(f"{Colors.RED}Invalid port range{Colors.ENDC}")
                return
        else:
            ports = [21, 22, 23, 25, 53, 80, 443]
        
        open_ports = self.port_scanner_advanced(target, ports)
        
        if open_ports:
            print(f"\n{Colors.GREEN}Open ports on {target}:{Colors.ENDC}")
            for port_info in open_ports:
                print(f"   {Colors.CYAN}Port {port_info['port']:<6}{Colors.ENDC} - {Colors.GREEN}{port_info['service']}{Colors.ENDC}")
                if port_info['banner'] != 'No banner':
                    print(f"     Banner: {Colors.YELLOW}{port_info['banner'][:60]}...{Colors.ENDC}")
        else:
            print(f"{Colors.RED}No open ports found{Colors.ENDC}")

    def network_latency_matrix(self):
        """Test latency to multiple hosts"""
        hosts = [
            ('Google DNS', '8.8.8.8'),
            ('Cloudflare DNS', '1.1.1.1'),
            ('OpenDNS', '208.67.222.222'),
            ('Quad9 DNS', '9.9.9.9'),
            ('Gateway', self.get_gateway_ip())
        ]
        
        print(f"\n{Colors.HEADER}🌐 NETWORK LATENCY MATRIX{Colors.ENDC}")
        print("=" * 50)
        
        print(f"\n{Colors.CYAN}{'Host':<20} {'IP':<15} {'Latency':<10} {'Status'}{Colors.ENDC}")
        print("-" * 50)
        
        for name, ip in hosts:
            if ip != "Unable to determine":
                latency = self.ping_latency(ip, 3)
                if latency:
                    if latency < 50:
                        status = f"{Colors.GREEN}Excellent{Colors.ENDC}"
                        lat_color = Colors.GREEN
                    elif latency < 100:
                        status = f"{Colors.YELLOW}Good{Colors.ENDC}"
                        lat_color = Colors.YELLOW
                    else:
                        status = f"{Colors.RED}Poor{Colors.ENDC}"
                        lat_color = Colors.RED
                    
                    print(f"{name:<20} {ip:<15} {lat_color}{latency:.1f}ms{Colors.ENDC:<10} {status}")
                else:
                    print(f"{name:<20} {ip:<15} {Colors.RED}Failed{Colors.ENDC:<10} {Colors.RED}Unreachable{Colors.ENDC}")

    def bandwidth_speed_test(self):
        """Simple bandwidth speed test"""
        print(f"\n{Colors.HEADER}📊 BANDWIDTH SPEED TEST{Colors.ENDC}")
        print("=" * 50)
        
        print(f"\n{Colors.YELLOW}Testing download speed...{Colors.ENDC}")
        
        test_urls = [
            'http://speedtest.tele2.net/1MB.zip',
            'http://ipv4.download.thinkbroadband.com/5MB.zip'
        ]
        
        for i, url in enumerate(test_urls, 1):
            try:
                start_time = time.time()
                response = requests.get(url, timeout=10, stream=True)
                
                total_size = 0
                for chunk in response.iter_content(chunk_size=8192):
                    total_size += len(chunk)
                    if time.time() - start_time > 10:  # 10 second timeout
                        break
                
                elapsed = time.time() - start_time
                speed = total_size / elapsed
                
                print(f"   Test {i}: {Colors.GREEN}{self.format_bytes(speed)}/s{Colors.ENDC}")
                break
                
            except Exception as e:
                print(f"   Test {i}: {Colors.RED}Failed ({str(e)[:50]}){Colors.ENDC}")
                continue
        
        # Real-time bandwidth monitoring
        print(f"\n{Colors.YELLOW}Real-time bandwidth monitoring (10 seconds)...{Colors.ENDC}")
        bandwidth = self.performance_monitor.monitor_bandwidth_usage(10)
        
        print(f"\n{Colors.CYAN}Results:{Colors.ENDC}")
        print(f"   Upload:   {Colors.GREEN}{self.format_bytes(bandwidth['upload_speed'])}/s{Colors.ENDC}")
        print(f"   Download: {Colors.GREEN}{self.format_bytes(bandwidth['download_speed'])}/s{Colors.ENDC}")
        print(f"   Total:    {Colors.GREEN}{self.format_bytes(bandwidth['total_speed'])}/s{Colors.ENDC}")

    def custom_traceroute(self):
        """Custom traceroute with options"""
        target = input(f"\n{Colors.YELLOW}Enter target (IP/hostname) [8.8.8.8]: {Colors.ENDC}") or "8.8.8.8"
        
        try:
            max_hops = int(input(f"{Colors.YELLOW}Maximum hops [15]: {Colors.ENDC}") or "15")
        except:
            max_hops = 15
        
        print(f"\n{Colors.GREEN}Tracing route to {target} (max {max_hops} hops)...{Colors.ENDC}\n")
        
        if self.system == "Windows":
            cmd = f"tracert -h {max_hops} {target}"
        else:
            cmd = f"traceroute -m {max_hops} {target}"
        
        output, _, code = self.execute_command(cmd, timeout=60)
        
        if code == 0:
            for line in output.split('\n'):
                if line.strip():
                    print(f"   {Colors.GREEN}{line}{Colors.ENDC}")
        else:
            print(f"{Colors.RED}Traceroute failed{Colors.ENDC}")

    def connectivity_monitor(self):
        """Monitor network connectivity continuously"""
        target = input(f"\n{Colors.YELLOW}Enter target to monitor [8.8.8.8]: {Colors.ENDC}") or "8.8.8.8"
        
        try:
            interval = int(input(f"{Colors.YELLOW}Ping interval in seconds [5]: {Colors.ENDC}") or "5")
        except:
            interval = 5
        
        print(f"\n{Colors.GREEN}Monitoring connectivity to {target} (Ctrl+C to stop)...{Colors.ENDC}\n")
        print(f"{Colors.CYAN}{'Time':<20} {'Status':<15} {'Latency':<15} {'Packet Loss'}{Colors.ENDC}")
        print("-" * 70)
        
        success_count = 0
        total_count = 0
        
        try:
            while True:
                timestamp = datetime.now().strftime("%H:%M:%S")
                latency = self.ping_latency(target, 1)
                total_count += 1
                
                if latency:
                    success_count += 1
                    loss_rate = ((total_count - success_count) / total_count) * 100
                    print(f"{timestamp:<20} {Colors.GREEN}Connected{Colors.ENDC:<24} {Colors.GREEN}{latency:.1f}ms{Colors.ENDC:<24} {loss_rate:.1f}%")
                else:
                    loss_rate = ((total_count - success_count) / total_count) * 100
                    print(f"{timestamp:<20} {Colors.RED}Failed{Colors.ENDC:<24} {Colors.RED}N/A{Colors.ENDC:<24} {loss_rate:.1f}%")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            final_loss = ((total_count - success_count) / total_count) * 100 if total_count > 0 else 0
            print(f"\n{Colors.YELLOW}Monitoring stopped.{Colors.ENDC}")
            print(f"Total packets: {total_count}, Success: {success_count}, Loss: {final_loss:.1f}%")

    def real_time_traffic_monitor(self):
        """Real-time traffic monitoring with live updates"""
        print(f"\n{Colors.HEADER}📈 REAL-TIME TRAFFIC MONITOR{Colors.ENDC}")
        print("=" * 70)
        
        try:
            duration = int(input(f"\n{Colors.YELLOW}Monitor duration in seconds [30]: {Colors.ENDC}") or "30")
            refresh_rate = float(input(f"{Colors.YELLOW}Refresh rate in seconds [2]: {Colors.ENDC}") or "2")
        except:
            duration, refresh_rate = 30, 2
        
        print(f"\n{Colors.GREEN}Monitoring network traffic for {duration} seconds...{Colors.ENDC}")
        print(f"{Colors.CYAN}Press Ctrl+C to stop early{Colors.ENDC}\n")
        
        start_time = time.time()
        previous_stats = psutil.net_io_counters(pernic=True)
        
        try:
            while time.time() - start_time < duration:
                time.sleep(refresh_rate)
                current_stats = psutil.net_io_counters(pernic=True)
                
                # Clear screen and show header
                os.system('cls' if self.system == 'Windows' else 'clear')
                print(f"{Colors.HEADER}📈 REAL-TIME TRAFFIC MONITOR{Colors.ENDC}")
                print("=" * 70)
                print(f"Time elapsed: {int(time.time() - start_time)}s / {duration}s")
                print()
                
                print(f"{Colors.CYAN}{'Interface':<15} {'Upload':<12} {'Download':<12} {'Total':<12}{Colors.ENDC}")
                print("-" * 55)
                
                for interface in current_stats:
                    if interface in previous_stats:
                        prev = previous_stats[interface]
                        curr = current_stats[interface]
                        
                        upload_rate = (curr.bytes_sent - prev.bytes_sent) / refresh_rate
                        download_rate = (curr.bytes_recv - prev.bytes_recv) / refresh_rate
                        total_rate = upload_rate + download_rate
                        
                        if total_rate > 1024:  # Show only active interfaces
                            print(f"{interface:<15} {self.format_bytes(upload_rate)+'/s':<12} "
                                  f"{self.format_bytes(download_rate)+'/s':<12} "
                                  f"{self.format_bytes(total_rate)+'/s':<12}")
                
                previous_stats = current_stats
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Monitoring stopped by user{Colors.ENDC}")

    def show_system_info(self):
        """Show comprehensive system information"""
        print(f"\n{Colors.HEADER}💻 COMPREHENSIVE SYSTEM INFORMATION{Colors.ENDC}")
        print("=" * 70)
        
        # System details
        print(f"\n{Colors.YELLOW}🖥️ System Details:{Colors.ENDC}")
        print(f"   OS:               {Colors.GREEN}{self.system_info['system']}{Colors.ENDC}")
        print(f"   Platform:         {Colors.GREEN}{self.system_info['platform']}{Colors.ENDC}")
        print(f"   Hostname:         {Colors.GREEN}{self.system_info['hostname']}{Colors.ENDC}")
        print(f"   Architecture:     {Colors.GREEN}{self.system_info['architecture']}{Colors.ENDC}")
        print(f"   Python Version:   {Colors.GREEN}{self.system_info['python_version']}{Colors.ENDC}")
        
        # Hardware info
        print(f"\n{Colors.YELLOW}🔧 Hardware Information:{Colors.ENDC}")
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        memory = psutil.virtual_memory()
        
        print(f"   CPU Cores:        {Colors.GREEN}{cpu_count}{Colors.ENDC}")
        if cpu_freq:
            print(f"   CPU Frequency:    {Colors.GREEN}{cpu_freq.current:.0f} MHz{Colors.ENDC}")
        print(f"   Total Memory:     {Colors.GREEN}{self.format_bytes(memory.total)}{Colors.ENDC}")
        print(f"   Available Memory: {Colors.GREEN}{self.format_bytes(memory.available)}{Colors.ENDC}")
        print(f"   Memory Usage:     {Colors.GREEN}{memory.percent}%{Colors.ENDC}")
        
        # Disk information
        print(f"\n{Colors.YELLOW}💾 Storage Information:{Colors.ENDC}")
        try:
            disk = psutil.disk_usage('/')
            print(f"   Total Storage:    {Colors.GREEN}{self.format_bytes(disk.total)}{Colors.ENDC}")
            print(f"   Used Storage:     {Colors.GREEN}{self.format_bytes(disk.used)}{Colors.ENDC}")
            print(f"   Free Storage:     {Colors.GREEN}{self.format_bytes(disk.free)}{Colors.ENDC}")
            print(f"   Usage Percentage: {Colors.GREEN}{(disk.used/disk.total)*100:.1f}%{Colors.ENDC}")
        except:
            print(f"   {Colors.RED}Storage information unavailable{Colors.ENDC}")
        
        # Network summary
        print(f"\n{Colors.YELLOW}🌐 Network Summary:{Colors.ENDC}")
        net_stats = psutil.net_io_counters()
        interfaces = psutil.net_if_addrs()
        
        print(f"   Network Interfaces: {Colors.GREEN}{len(interfaces)}{Colors.ENDC}")
        print(f"   Total Bytes Sent:   {Colors.GREEN}{self.format_bytes(net_stats.bytes_sent)}{Colors.ENDC}")
        print(f"   Total Bytes Recv:   {Colors.GREEN}{self.format_bytes(net_stats.bytes_recv)}{Colors.ENDC}")
        print(f"   Total Packets Sent: {Colors.GREEN}{net_stats.packets_sent:,}{Colors.ENDC}")
        print(f"   Total Packets Recv: {Colors.GREEN}{net_stats.packets_recv:,}{Colors.ENDC}")

    def show_help(self):
        """Display comprehensive help information"""
        help_text = f"""
{Colors.HEADER}❓ NETSCOPE ULTIMATE - HELP & DOCUMENTATION{Colors.ENDC}
{"=" * 70}

{Colors.YELLOW}MAIN FEATURES:{Colors.ENDC}

{Colors.CYAN}🌐 Network Overview:{Colors.ENDC}
   - Displays local IP, gateway, public IP, ISP information
   - Shows DNS configuration and basic connectivity tests
   - Quick network health check

{Colors.CYAN}🔌 Advanced Interface Analysis:{Colors.ENDC}
   - Detailed information about network adapters
   - MAC addresses, IP configurations, traffic statistics
   - Interface speed, MTU, and operational status

{Colors.CYAN}🔍 Network Device Discovery:{Colors.ENDC}
   - Scans local network for active devices
   - Hostname resolution and basic OS detection
   - Aggressive scanning option for port detection

{Colors.CYAN}🔐 Advanced Port Scanner:{Colors.ENDC}
   - Comprehensive port scanning with service detection
   - Banner grabbing and vulnerability assessment
   - Custom port ranges and timing options

{Colors.CYAN}📊 Network Performance Analysis:{Colors.ENDC}
   - Real-time bandwidth monitoring
   - Interface performance metrics
   - Latency testing to multiple hosts

{Colors.CYAN}🛡️ Network Security Audit:{Colors.ENDC}
   - Detects suspicious network connections
   - Analyzes local open ports and services
   - Security risk assessment

{Colors.CYAN}🗺️ Network Topology Discovery:{Colors.ENDC}
   - Routing table analysis
   - ARP table inspection
   - Network path tracing (traceroute)

{Colors.CYAN}📶 WiFi Network Analyzer:{Colors.ENDC}
   - Available wireless networks
   - Current connection details
   - Signal strength and channel information

{Colors.CYAN}🔍 DNS Analysis & Testing:{Colors.ENDC}
   - DNS server configuration
   - Resolution performance testing
   - Reverse DNS lookup capabilities

{Colors.CYAN}📈 Real-time Traffic Monitor:{Colors.ENDC}
   - Live network traffic monitoring
   - Per-interface bandwidth usage
   - Customizable refresh rates

{Colors.CYAN}🎯 Custom Network Tools:{Colors.ENDC}
   - Custom ping tests with parameters
   - Flexible port range scanning
   - Network latency matrix
   - Bandwidth speed testing
   - Continuous connectivity monitoring

{Colors.YELLOW}TIPS FOR BEST RESULTS:{Colors.ENDC}
• Run with administrator/root privileges when possible
• Some features require internet connectivity
• Network scanning may take time depending on network size
• Use Ctrl+C to interrupt long-running operations
• Export results for documentation and analysis

{Colors.YELLOW}SYSTEM REQUIREMENTS:{Colors.ENDC}
• Python 3.6+ with psutil and requests libraries
• Windows, Linux, or macOS operating system
• Network connectivity for external tests

{Colors.YELLOW}SECURITY NOTE:{Colors.ENDC}
This tool is designed for legitimate network administration
and troubleshooting. Always ensure you have proper authorization
before scanning networks you don't own.
"""
        print(help_text)

    def run(self):
        """Main program execution loop"""
        try:
            while True:
                self.clear_screen()
                self.print_banner()
                print(self.show_main_menu())
                
                choice = input(f"\n{Colors.YELLOW}Select option [1-15]: {Colors.ENDC}").strip()
                
                if choice == '1':
                    self.network_overview()
                elif choice == '2':
                    self.advanced_interface_analysis()
                elif choice == '3':
                    print(f"\n{Colors.YELLOW}Choose scan type:{Colors.ENDC}")
                    print(f"1. Quick scan (ping only)")
                    print(f"2. Aggressive scan (with port detection)")
                    scan_type = input(f"\n{Colors.CYAN}Select [1]: {Colors.ENDC}") or "1"
                    aggressive = (scan_type == "2")
                    
                    devices = self.advanced_network_scan(aggressive=aggressive)
                    if devices:
                        print(f"\n{Colors.GREEN}Found {len(devices)} active devices:{Colors.ENDC}\n")
                        for ip, info in devices.items():
                            print(f"   {Colors.CYAN}📱 {ip:<15}{Colors.ENDC} → {Colors.YELLOW}{info['hostname']}{Colors.ENDC}")
                            if aggressive and 'open_ports' in info and info['open_ports']:
                                ports_str = ', '.join(map(str, info['open_ports'][:5]))
                                if len(info['open_ports']) > 5:
                                    ports_str += f" (+{len(info['open_ports'])-5} more)"
                                print(f"      Open ports: {Colors.GREEN}{ports_str}{Colors.ENDC}")
                            if info['os_guess'] != 'Unknown':
                                print(f"      OS Guess: {Colors.MAGENTA}{info['os_guess']}{Colors.ENDC}")
                    else:
                        print(f"{Colors.RED}❌ No devices found or scan failed{Colors.ENDC}")
                
                elif choice == '4':
                    target = input(f"\n{Colors.CYAN}Enter target IP: {Colors.ENDC}")
                    if target:
                        print(f"\n{Colors.YELLOW}Port scan options:{Colors.ENDC}")
                        print(f"1. Common ports (fast)")
                        print(f"2. Extended scan (1-1000)")
                        scan_option = input(f"\n{Colors.CYAN}Select [1]: {Colors.ENDC}") or "1"
                        
                        port_range = "common" if scan_option == "1" else "extended"
                        open_ports = self.port_scanner_advanced(target, port_range)
                        
                        if open_ports:
                            print(f"\n{Colors.GREEN}Open ports on {target}:{Colors.ENDC}")
                            for port_info in open_ports:
                                print(f"   {Colors.CYAN}Port {port_info['port']:<6}{Colors.ENDC} - {Colors.GREEN}{port_info['service']}{Colors.ENDC}")
                                if port_info['banner'] and port_info['banner'] != 'No banner':
                                    print(f"     Banner: {Colors.YELLOW}{port_info['banner'][:60]}{Colors.ENDC}")
                        else:
                            print(f"{Colors.RED}❌ No open ports found{Colors.ENDC}")
                
                elif choice == '5':
                    self.network_performance_analysis()
                elif choice == '6':
                    self.network_security_audit()
                elif choice == '7':
                    self.network_topology_discovery()
                elif choice == '8':
                    self.wifi_analyzer()
                elif choice == '9':
                    self.dns_analysis()
                elif choice == '10':
                    self.real_time_traffic_monitor()
                elif choice == '11':
                    self.custom_network_tools()
                elif choice == '12':
                    self.export_results()
                elif choice == '13':
                    self.show_system_info()
                elif choice == '14':
                    self.show_help()
                elif choice == '15':
                    print(f"\n{Colors.GREEN}🎉 Thank you for using NetScope Ultimate!{Colors.ENDC}")
                    print(f"{Colors.CYAN}Visit us again for your network analysis needs.{Colors.ENDC}")
                    break
                else:
                    print(f"\n{Colors.RED}❌ Invalid option. Please select 1-15.{Colors.ENDC}")
                    time.sleep(2)
                    continue
                
                if choice != '15':
                    input(f"\n{Colors.CYAN}Press Enter to return to main menu...{Colors.ENDC}")
                    
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}⚠️ Program interrupted by user{Colors.ENDC}")
            print(f"{Colors.GREEN}Thank you for using NetScope Ultimate!{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.RED}❌ Fatal error occurred: {str(e)}{Colors.ENDC}")
            print(f"{Colors.YELLOW}Please report this issue if it persists.{Colors.ENDC}")


def main():
    """Main function to initialize and run NetScope Ultimate"""
    try:
        print(f"{Colors.CYAN}Initializing NetScope Ultimate...{Colors.ENDC}")
        
        # Check Python version
        if sys.version_info < (3, 6):
            print(f"{Colors.RED}❌ Python 3.6+ required. Current version: {platform.python_version()}{Colors.ENDC}")
            sys.exit(1)
        
        # Initialize analyzer
        analyzer = AdvancedNetworkAnalyzer()
        
        # Check for admin privileges (optional warning)
        try:
            if analyzer.system == "Windows":
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            else:
                is_admin = (os.geteuid() == 0)
            
            if not is_admin:
                print(f"{Colors.YELLOW}⚠️ Note: Running without admin privileges. Some features may be limited.{Colors.ENDC}")
                time.sleep(2)
        except:
            pass
        
        # Run main program
        analyzer.run()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Program terminated by user. Goodbye!{Colors.ENDC}")
    except ImportError as e:
        print(f"{Colors.RED}❌ Missing required library: {e}{Colors.ENDC}")
        print(f"{Colors.CYAN}Try: pip install psutil requests{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}❌ Fatal error: {str(e)}{Colors.ENDC}")
        print(f"{Colors.YELLOW}Please report this issue with the error details.{Colors.ENDC}")


if __name__ == "__main__":
    main()





    