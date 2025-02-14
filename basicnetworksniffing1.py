import scapy.all as scapy
import psutil
from prettytable import PrettyTable
import time
from colorama import Fore, Style
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Get MAC and IP using psutil
def get_network_info():
    interfaces = psutil.net_if_addrs()
    t = PrettyTable([f"{Fore.GREEN}Interface", "MAC Address", f"IP Address{Style.RESET_ALL}"])

    network_data = {}
    for interface, details in interfaces.items():
        mac = None
        ip = None
        for detail in details:
            if detail.family == psutil.AF_LINK:
                mac = detail.address
            elif detail.family == 2:  # IPv4
                ip = detail.address
        network_data[interface] = {"MAC": mac or "N/A", "IP": ip or "N/A"}
        t.add_row([interface, mac or "N/A", ip or "N/A"])

    print(t)
    return network_data

# Sniff packets
def sniff(interface):
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

# Callback function to process packets
def packet_callback(packet):
    packet_details = f"{Fore.CYAN}Packet Details:{Style.RESET_ALL}\n"
    
    if IP in packet:
        packet_details += f"{Fore.GREEN}IP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}\n"
        packet_details += f"Protocol: {packet[IP].proto} ; TTL: {packet[IP].ttl}\n"
    
    if TCP in packet:
        packet_details += f"{Fore.YELLOW}TCP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}\n"
    
    if UDP in packet:
        packet_details += f"{Fore.YELLOW}UDP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}\n"
    
    if ICMP in packet:
        packet_details += f"{Fore.YELLOW}ICMP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}\n"
    
    print(packet_details)

# Main execution
def main():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    network_info = get_network_info()

    interface = input("[*] Please enter the interface name: ")
    
    if interface not in network_info:
        print(f"{Fore.RED}[!] Invalid Interface. Please check the available interfaces.{Style.RESET_ALL}")
        return
    
    print(f"IP Address: {network_info[interface]['IP']}")
    print(f"MAC Address: {network_info[interface]['MAC']}")
    
    print("[*] Sniffing Packets... Press Ctrl+C to stop.")
    try:
        sniff(interface)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Stopping the Sniffer...{Style.RESET_ALL}")
        time.sleep(1)

if __name__ == "__main__":
    main()
