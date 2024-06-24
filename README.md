
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
sudo python3 firewall_analyzer.py
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

## License

This project is [MIT](https://choosealicense.com/licenses/mit/) licensed.

## Disclaimer

This tool is for educational and professional use only. Always ensure you have proper authorization before running security analysis tools on any system or network.
```

This README.md file includes:

1. **A brief description** of the tool.
2. **An overview of its main features**.
3. **System requirements** and installation instructions.
4. **Usage guidelines**.
5. Information about the **output**.
6. A **caution note** about root privileges.
7. Information on **how to contribute**.
8. **Author information**.
9. **License details**.
10. A **disclaimer** for proper usage.

You can save this as `README.md` in the root directory of your project. Remember to replace `logo.png` with an actual logo file if you have one, or remove that line if you don't. Adjust the GitHub links and other details to match your actual repository structure and preferences.
