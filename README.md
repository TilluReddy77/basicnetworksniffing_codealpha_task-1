# basicnetworksniffing_codealpha_task-1


## 📌 Description
This is a Python-based **Network Packet Sniffer** that captures and analyzes network traffic in real-time. It provides insights into IP, TCP, UDP, and ICMP packet details, making it a useful tool for network analysis, cybersecurity research, and ethical hacking.

The tool lists available network interfaces, allows users to select an interface, and then starts sniffing packets on that interface while displaying detailed information about each captured packet.

---

## 🚀 Features
✅ Displays available network interfaces with **MAC & IP addresses**  
✅ Captures packets on a selected network interface  
✅ Parses and displays details of **IP, TCP, UDP, and ICMP packets**  
✅ Uses **color-coded** output for better readability  
✅ **Handles errors gracefully**, ensuring smooth execution  
✅ **User-friendly CLI** with interactive input  

---

## 🎯 Dependencies
Before running the script, ensure that you have installed the following dependencies:

- `scapy` (for packet sniffing and analysis)
- `psutil` (to fetch network interface details)
- `prettytable` (for formatted output tables)
- `colorama` (for colorful CLI output)



You can install them using:
```bash

pip install scapy psutil prettytable colorama
