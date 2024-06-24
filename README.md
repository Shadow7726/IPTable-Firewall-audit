
# Firewall Analyzer Tool

![Shadow Logo](logo.png)

## Description

The Firewall Analyzer Tool is a comprehensive Python-based utility designed to assess and analyze your system's firewall configuration, network setup, and potential security vulnerabilities. It provides system administrators and security professionals with valuable insights to quickly evaluate and enhance their network security posture.

## Features

1. **IP Tables Information**: 
   - Displays detailed IPv4 and IPv6 firewall rules
   - Shows rules for different chains (INPUT, OUTPUT, FORWARD)
   - Presents information from various tables (filter, nat, mangle, raw, security)

2. **Firewall Audit**:
   - Performs a security audit of your firewall configuration
   - Checks for adherence to best practices
   - Identifies potential vulnerabilities in the current setup
   - Provides recommendations for improvement

3. **Traceroute and Pivoting Analysis**:
   - Examines network routing configurations
   - Checks for settings that could potentially be exploited for network pivoting attacks
   - Analyzes both IPv4 and IPv6 configurations

4. **User-Friendly Output**:
   - Provides color-coded terminal output for easy reading
   - Generates HTML reports for each analysis for easy viewing and sharing

## Requirements

- Python 3.6+
- Root privileges (sudo access)
- Linux operating system
- Required Python libraries: `colorama`


## Usage

Run the script with root privileges:

```
sudo python3 iptable-firewall_audit.py
```

Follow the on-screen menu to choose the desired analysis option.

## Output

The tool provides:
- Color-coded terminal output for immediate insights
- HTML reports saved in the same directory for detailed review and sharing

## Caution

This tool requires root privileges to access system configurations. Use with caution and only on systems you have permission to analyze.

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check [issues page](https://github.com/Shadow7726/firewall-analyzer/issues) if you want to contribute.

## Author

- GitHub: [@Shadow7726](https://github.com/Shadow7726)

