import subprocess
import os
import html
import re
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# ASCII Art Logo
logo = """
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ 
"""

# GitHub Link
# https://github.com/Shadow7726

# Initialize colorama
init(autoreset=True)

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"An error occurred: {e}"

def colorize(text, color):
    return f"{color}{text}{Style.RESET_ALL}"

def get_ip_version():
    ipv4_version = run_command("ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}'")
    ipv6_version = run_command("ip -6 addr | grep -oP '(?<=inet6\s)[\da-f:]+'")
    
    versions = []
    if ipv4_version:
        versions.append(f"IPv4: {colorize(ipv4_version.strip(), Fore.GREEN)}")
    if ipv6_version:
        versions.append(f"IPv6: {colorize(ipv6_version.strip(), Fore.GREEN)}")
    
    return ", ".join(versions) if versions else colorize("Unable to determine IP versions", Fore.RED)

def get_ip_info():
    ip_version = get_ip_version()
    
    ipv4_rules = run_command("sudo iptables -S")
    ipv6_rules = run_command("sudo ip6tables -S")
    
    ipv4_input = run_command("sudo iptables -S INPUT")
    ipv4_output = run_command("sudo iptables -S OUTPUT")
    ipv6_input = run_command("sudo ip6tables -S INPUT")
    ipv6_output = run_command("sudo ip6tables -S OUTPUT")
    
    ipv4_list = run_command("sudo iptables --list")
    ipv6_list = run_command("sudo ip6tables --list")
    
    tables = ["filter", "nat", "mangle", "raw", "security"]
    table_rules = []
    for table in tables:
        ipv4_table = run_command(f"sudo iptables -t {table} -L -n -v --line-numbers")
        ipv6_table = run_command(f"sudo ip6tables -t {table} -L -n -v --line-numbers")
        table_rules.append(colorize(f"=== {table.upper()} Table ===", Fore.GREEN))
        table_rules.append(f"IPv4:\n{ipv4_table}")
        table_rules.append(f"IPv6:\n{ipv6_table}\n")
    
    return (f"IP Version: {ip_version}\n\n"
            f"IPv4 Rules:\n{colorize(ipv4_rules, Fore.GREEN)}\n"
            f"IPv6 Rules:\n{colorize(ipv6_rules, Fore.GREEN)}\n"
            f"IPv4 INPUT Rules:\n{colorize(ipv4_input, Fore.GREEN)}\n"
            f"IPv4 OUTPUT Rules:\n{colorize(ipv4_output, Fore.GREEN)}\n"
            f"IPv6 INPUT Rules:\n{colorize(ipv6_input, Fore.GREEN)}\n"
            f"IPv6 OUTPUT Rules:\n{colorize(ipv6_output, Fore.GREEN)}\n"
            f"IPv4 List:\n{ipv4_list}\n"
            f"IPv6 List:\n{ipv6_list}\n"
            f"Table-specific Rules:\n{''.join(table_rules)}")

def audit_firewall():
    tables = ["filter", "nat", "mangle", "raw", "security"]
    audit_results = []
    
    for table in tables:
        ipv4_rules = run_command(f"sudo iptables -t {table} -L -v -n")
        ipv6_rules = run_command(f"sudo ip6tables -t {table} -L -v -n")
        
        audit_results.append(colorize(f"=== {table.upper()} Table ===", Fore.GREEN))
        audit_results.append("IPv4 Rules:")
        audit_results.append(ipv4_rules)
        audit_results.append("IPv6 Rules:")
        audit_results.append(ipv6_rules)
        audit_results.append("\n")
    
    audit_results.append(colorize("Security Audit Results:", Fore.YELLOW))
    
    # Check for default policies
    default_policies = run_command("sudo iptables -L | grep policy")
    audit_results.append(colorize("\n1. Default Policies:", Fore.GREEN))
    audit_results.append(default_policies)
    audit_results.append("Expected: Default policies should be set to DROP for INPUT and FORWARD chains, and ACCEPT for OUTPUT chain.")
    if "policy DROP" in default_policies:
        audit_results.append(colorize("✓ DROP policy detected. Good security practice.", Fore.GREEN))
    else:
        audit_results.append(colorize("⚠ No DROP policy detected. Consider setting default policies to DROP for better security.", Fore.RED))

    # Check for loopback interface rules
    loopback_rules = run_command("sudo iptables -L INPUT | grep lo")
    audit_results.append(colorize("\n2. Loopback Interface Rules:", Fore.GREEN))
    audit_results.append(loopback_rules)
    audit_results.append("Expected: ACCEPT all traffic on the loopback interface (lo).")
    if "ACCEPT     all  --  lo" in loopback_rules:
        audit_results.append(colorize("✓ Loopback interface rule detected. Good configuration.", Fore.GREEN))
    else:
        audit_results.append(colorize("⚠ No specific rule for loopback interface. Consider adding an ACCEPT rule for 'lo'.", Fore.RED))

    # Check for established connection rules
    established_rules = run_command("sudo iptables -L | grep ESTABLISHED")
    audit_results.append(colorize("\n3. Established Connection Rules:", Fore.GREEN))
    audit_results.append(established_rules)
    audit_results.append("Expected: ACCEPT rules for ESTABLISHED,RELATED connections.")
    if "ESTABLISHED" in established_rules:
        audit_results.append(colorize("✓ ESTABLISHED connection rules detected. Good for allowing return traffic.", Fore.GREEN))
    else:
        audit_results.append(colorize("⚠ No specific rules for ESTABLISHED connections. Consider adding for better stateful filtering.", Fore.RED))

    # Check for specific service rules (e.g., SSH)
    ssh_rules = run_command("sudo iptables -L | grep ssh")
    audit_results.append(colorize("\n4. SSH Service Rules:", Fore.GREEN))
    audit_results.append(ssh_rules)
    audit_results.append("Expected: Specific ACCEPT rules for necessary services like SSH, preferably with source IP restrictions.")
    if ssh_rules:
        audit_results.append(colorize("✓ SSH rules detected. Ensure they are restrictive enough.", Fore.GREEN))
    else:
        audit_results.append(colorize("⚠ No specific SSH rules found. If SSH access is needed, consider adding restrictive rules.", Fore.YELLOW))

    # Check for logging rules
    logging_rules = run_command("sudo iptables -L | grep LOG")
    audit_results.append(colorize("\n5. Logging Rules:", Fore.GREEN))
    audit_results.append(logging_rules)
    audit_results.append("Expected: LOG rules for tracking dropped packets or suspicious activities.")
    if logging_rules:
        audit_results.append(colorize("✓ Logging rules detected. Good for monitoring and troubleshooting.", Fore.GREEN))
    else:
        audit_results.append(colorize("⚠ No logging rules found. Consider adding LOG rules for better security insight.", Fore.YELLOW))

    # Check for rate limiting rules
    rate_limit_rules = run_command("sudo iptables -L | grep limit")
    audit_results.append(colorize("\n6. Rate Limiting Rules:", Fore.GREEN))
    audit_results.append(rate_limit_rules)
    audit_results.append("Expected: Rate limiting rules to prevent DoS attacks.")
    if rate_limit_rules:
        audit_results.append(colorize("✓ Rate limiting rules detected. Good for preventing DoS attacks.", Fore.GREEN))
    else:
        audit_results.append(colorize("⚠ No rate limiting rules found. Consider adding to protect against DoS attacks.", Fore.YELLOW))

    # Check for ICMP rules
    icmp_rules = run_command("sudo iptables -L | grep icmp")
    audit_results.append(colorize("\n7. ICMP Rules:", Fore.GREEN))
    audit_results.append(icmp_rules)
    audit_results.append("Expected: Controlled ICMP rules, allowing necessary types while blocking others.")
    if icmp_rules:
        audit_results.append(colorize("✓ ICMP rules detected. Ensure they allow necessary types while blocking others.", Fore.GREEN))
    else:
        audit_results.append(colorize("⚠ No specific ICMP rules found. Consider adding rules to control ICMP traffic.", Fore.YELLOW))

    # Final recommendations
    audit_results.append(colorize("\nFinal Recommendations:", Fore.YELLOW))
    audit_results.append("1. Regularly review and update firewall rules.")
    audit_results.append("2. Implement the principle of least privilege.")
    audit_results.append("3. Use specific, restrictive rules instead of broad ACCEPT rules.")
    audit_results.append("4. Consider using a configuration management tool for consistent firewall setup.")
    audit_results.append("5. Regularly monitor logs for suspicious activities.")
    
    return "\n".join(audit_results)

def check_traceroute_and_pivoting():
    traceroute = run_command("traceroute google.com")
    
    routing_table_v4 = run_command("ip route show")
    routing_table_v6 = run_command("ip -6 route show")
    
    result = (f"Traceroute:\n{colorize(traceroute, Fore.GREEN)}\n\n"
              f"IPv4 Routing Table:\n{colorize(routing_table_v4, Fore.GREEN)}\n\n"
              f"IPv6 Routing Table:\n{colorize(routing_table_v6, Fore.GREEN)}\n\n")
    
    result += colorize("Pivoting Vulnerability Analysis:\n", Fore.YELLOW)

    # Check for weak access controls
    firewall_rules = run_command("sudo iptables -L")
    if "ACCEPT     all  --  anywhere             anywhere" in firewall_rules:
        result += colorize("⚠ Weak Access Control: Overly permissive firewall rule detected.\n", Fore.RED)
    else:
        result += colorize("✓ No overly permissive firewall rules detected.\n", Fore.GREEN)

    # Check for unrestricted services
    services = run_command("sudo netstat -tuln")
    if "0.0.0.0:*" in services:
        result += colorize("⚠ Unrestricted Services: Services listening on all interfaces detected.\n", Fore.RED)
    else:
        result += colorize("✓ No unrestricted services detected.\n", Fore.GREEN)

    # Check for default configurations
    if "password" in run_command("cat /etc/shadow") or "admin" in run_command("cat /etc/passwd"):
        result += colorize("⚠ Default Configurations: Potential default usernames or weak passwords detected.\n", Fore.RED)
    else:
        result += colorize("✓ No obvious default configurations detected.\n", Fore.GREEN)

    # Check for user privileges
    sudo_users = run_command("grep -Po '^sudo.+:\\K.*$' /etc/group")
    if sudo_users:
        result += colorize(f"⚠ User Privileges: Users with sudo access: {sudo_users}\n", Fore.YELLOW)
    else:
        result += colorize("✓ No users with sudo access detected.\n", Fore.GREEN)

    # Check for logging and auditing
    if not os.path.exists("/var/log/audit/audit.log"):
        result += colorize("⚠ Logging and Auditing: Audit log not found. Ensure proper logging is enabled.\n", Fore.YELLOW)
    else:
        result += colorize("✓ Audit logging appears to be enabled.\n", Fore.GREEN)

    # Check for static routes
    if "static" in routing_table_v4 or "static" in routing_table_v6:
        result += colorize("⚠ Static Routes: Static routes detected. Review for potential security risks.\n", Fore.YELLOW)
    else:
        result += colorize("✓ No static routes detected.\n", Fore.GREEN)

    # Check for promiscuous mode
    if "PROMISC" in run_command("ifconfig"):
        result += colorize("⚠ Promiscuous Mode: Network interface in promiscuous mode detected.\n", Fore.RED)
    else:
        result += colorize("✓ No network interfaces in promiscuous mode detected.\n", Fore.GREEN)

    # Check for disabled security features
    if "inactive" in run_command("sudo ufw status") or "inactive" in run_command("sudo firewall-cmd --state"):
        result += colorize("⚠ Disabled Security Features: Firewall appears to be disabled.\n", Fore.RED)
    else:
        result += colorize("✓ Firewall appears to be active.\n", Fore.GREEN)

    result += colorize("\nRecommendations:\n", Fore.YELLOW)
    result += "1. Regularly review and tighten firewall rules and ACLs.\n"
    result += "2. Disable or restrict access to unnecessary services.\n"
    result += "3. Ensure all default passwords and configurations are changed.\n"
    result += "4. Implement the principle of least privilege for user accounts.\n"
    result += "5. Enable comprehensive logging and regularly review audit logs.\n"
    result += "6. Avoid using static routes for internal traffic when possible.\n"
    result += "7. Disable promiscuous mode on network interfaces unless absolutely necessary.\n"
    result += "8. Ensure all security features, especially firewalls, are enabled and properly configured.\n"

    return result

def generate_html(content):
    # Convert ANSI color codes to HTML
    content = content.replace(Fore.RED, '<span style="color: red;">')
    content = content.replace(Fore.GREEN, '<span style="color: green;">')
    content = content.replace(Fore.YELLOW, '<span style="color: yellow;">')
    content = content.replace(Style.RESET_ALL, '</span>')

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Firewall Information</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; background-color: #1e1e1e; color: #d4d4d4; }}
            pre {{ background-color: #2d2d2d; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            .red {{ color: #ff6b6b; }}
            .green {{ color: #69ff94; }}
            .yellow {{ color: #feca57; }}
        </style>
    </head>
    <body>
        <h1>Firewall Information</h1>
        <pre>{content}</pre>
    </body>
    </html>
    """
    return html_content

def main():
    print(colorize(logo, Fore.CYAN))
    print(colorize("Firewall Analyzer", Fore.YELLOW))
    print(colorize("GitHub: https://github.com/Shadow7726", Fore.GREEN))
    print("\n")

    while True:
        print("\n" + colorize("1. Get IP Tables Information", Fore.GREEN))
        print(colorize("2. Audit Firewall Rules", Fore.GREEN))
        print(colorize("3. Check Traceroute and Pivoting", Fore.GREEN))
        print(colorize("4. Exit", Fore.RED))
        choice = input("Enter your choice (1/2/3/4): ")
        
        if choice == "1":
            output = get_ip_info()
            print(output)
            
            with open("ip_info.html", "w") as f:
                f.write(generate_html(output))
            print(colorize("HTML output saved to ip_info.html", Fore.GREEN))
            
        elif choice == "2":
            audit_result = audit_firewall()
            print(audit_result)
            
            with open("firewall_audit.html", "w") as f:
                f.write(generate_html(audit_result))
            print(colorize("HTML output saved to firewall_audit.html", Fore.GREEN))
            
        elif choice == "3":
            traceroute_result = check_traceroute_and_pivoting()
            print(traceroute_result)
            
            with open("traceroute_info.html", "w") as f:
                f.write(generate_html(traceroute_result))
            print(colorize("HTML output saved to traceroute_info.html", Fore.GREEN))
            
        elif choice == "4":
            print(colorize("Exiting...", Fore.RED))
            break
        else:
            print(colorize("Invalid choice. Please try again.", Fore.RED))

if __name__ == "__main__":
    main()
