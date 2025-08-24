# 🚀 NetScope - Advanced Network Analysis & Monitoring Suite

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Status](https://img.shields.io/badge/status-Active-brightgreen.svg)]()

> A comprehensive unified network diagnostics, monitoring, and analysis tool that combines advanced features for network administrators, security professionals, and IT enthusiasts.

![NetScope Banner](internet.ico)

## ✨ Features

### 🌐 Core Network Analysis
- **Network Overview**: Comprehensive network configuration display with ISP information
- **Advanced Interface Analysis**: Detailed network adapter information with traffic statistics
- **Public IP Detection**: Multi-source public IP detection with geolocation data
- **DNS Configuration**: Advanced DNS server analysis and performance testing

### 🔍 Discovery & Scanning
- **Network Device Discovery**: Intelligent host discovery with OS fingerprinting
- **Advanced Port Scanner**: Multi-threaded port scanning with service detection and banner grabbing
- **Network Topology Mapping**: Routing table analysis and network path visualization
- **WiFi Network Analysis**: Wireless network discovery and signal analysis

### 📊 Performance Monitoring
- **Real-time Traffic Monitor**: Live bandwidth monitoring with customizable refresh rates
- **Network Performance Analysis**: Comprehensive latency testing and throughput analysis
- **Interface Speed Testing**: Per-interface performance metrics and utilization
- **Bandwidth Speed Tests**: Download speed testing with multiple providers

### 🛡️ Security Features
- **Network Security Audit**: Suspicious connection detection and risk assessment
- **Port Security Analysis**: Local open port analysis with security recommendations
- **Connection Monitoring**: Real-time monitoring of network connections
- **Threat Detection**: Basic network anomaly detection

### 🎯 Custom Tools
- **Custom Ping Tests**: Configurable ping testing with detailed statistics
- **Port Range Scanner**: Flexible port scanning with custom ranges
- **Latency Matrix**: Multi-host latency comparison
- **Connectivity Monitor**: Continuous connection monitoring with packet loss tracking
- **Custom Traceroute**: Advanced path tracing with hop analysis

## 🚀 Quick Start

### Option 1: Executable (Windows)
1. Download the latest `NetScope.exe` from the [Releases](./dist/NetScope.exe) page
2. Run as Administrator for full functionality
3. No installation required - portable executable

### Option 2: Python Script
1. **Clone the repository:**
   ```bash
   https://github.com/s3bu7i/NetScope.git
   cd NetScope
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Or let the script auto-install:
   ```bash
   python NetScope.py
   ```

3. **Run the tool:**
   ```bash
   # Linux/macOS (recommended with sudo for full features)
   sudo python3 NetScope.py
   
   # Windows (run as Administrator)
   python NetScope.py
   ```

## 📋 Requirements

### System Requirements
- **Operating System**: Windows 7+, Linux, macOS 10.12+
- **Python**: 3.6 or higher (if running from source)
- **Memory**: 64MB RAM minimum
- **Network**: Active network connection for external tests

### Python Dependencies
```
psutil>=5.8.0
requests>=2.25.0
```

## 📖 Usage Guide

### Main Menu Navigation
```
╔══════════════════════════════════════════════════════════════════════════╗
║                              MAIN MENU                                  ║
╠══════════════════════════════════════════════════════════════════════════╣
║  1. 🌐  Network Overview & Basic Info                                   ║
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
╚══════════════════════════════════════════════════════════════════════════╝
```


### Network Overview
```
🌐 COMPREHENSIVE NETWORK OVERVIEW
======================================================================

🔗 Network Configuration:
   Local IP:       192.168.1.100
   Gateway:        192.168.1.1
   Public IP:      203.0.113.42
   ISP:            Example ISP Corporation
   Location:       New York, NY

🌐 DNS Configuration:
   DNS 1:          8.8.8.8
   DNS 2:          1.1.1.1

⚡ Connectivity Test:
   Google      :   12.3ms
   Cloudflare  :   8.7ms
```

### Port Scanner Results
```
🔍 Scanning 20 ports on 192.168.1.1...
✅ Port scan complete! Found 5 open ports

Open ports on 192.168.1.1:
   Port 22     - SSH
     Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
   Port 53     - DNS
   Port 80     - HTTP
     Banner: HTTP/1.1 200 OK Server: nginx/1.18.0
   Port 443    - HTTPS
   Port 8080   - HTTP-Alt
```

## 🔧 Advanced Configuration

### Running with Elevated Privileges

#### Windows
```cmd
# Run Command Prompt as Administrator
python netscope.py
```

#### Linux/macOS
```bash
# Use sudo for full system access
sudo python3 netscope.py
```


## 🚨 Important Notes

### Security Considerations
- **Authorization Required**: Only scan networks you own or have explicit permission to test
- **Network Impact**: Aggressive scans may trigger security alerts
- **Rate Limiting**: Some features implement rate limiting to prevent network overload
- **Privacy**: Tool respects network privacy and doesn't store sensitive data

### Limitations
- Some features require administrator/root privileges
- WiFi analysis availability varies by platform
- External connectivity required for public IP detection
- Performance may vary on different network configurations

