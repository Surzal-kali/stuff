from scapy.all import ICMP, IP, sr, sr1, ARP, Ether, TCP, srp
import socket
from ipaddress import ip_network
import logging
import asyncio
import concurrent.futures
import time

TARGET_RANGE = input("Enter target IP range (e.g., 192.168.1.0/24): ")

def send_l2_custom(packet, *args, **kwargs):
    try:
        return srp(packet, *args, **kwargs)
    except Exception as e:
        print(f"[-] Error during packet send: {e}")
        return None, None


def send_l3_custom(packet, *args, **kwargs):
    try:
        return sr(packet, *args, **kwargs)
    except Exception as e:
        print(f"[-] Error during packet send: {e}")
        return None, None

def syn_scan(target_ip, port=80):
    """
    Perform a TCP SYN scan on a specific target and port.
    """
    print(f"[*] Performing SYN scan on {target_ip}:{port}")
    
    packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
    ans = sr1(packet, timeout=2, verbose=0)

    if ans is None:
        print(f"[-] Port {port} is filtered or down.")
    elif ans.haslayer(TCP) and ans[TCP].flags == 0x12: # 0x12 is SYN-ACK
        print(f"[+] Port {port} is OPEN!")
        sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
    elif ans.haslayer(TCP) and ans[TCP].flags == 0x14: # 0x14 is RST-ACK
        print(f"[-] Port {port} is CLOSED.")

def syn_scan_concurrent(target_ip, ports):
    
    """
    Perform a SYN scan on multiple ports concurrently for a target IP.
    """
    print(f"[*] Performing SYN scan on {target_ip} for ports {ports}")

    def syn_port(port):
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        ans = sr1(packet, timeout=2, verbose=0)
        if ans is None:
            return (target_ip, port, "filtered or down")
        elif ans.haslayer(TCP) and ans[TCP].flags == 0x12:
            sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
            return (target_ip, port, "open")
        elif ans.haslayer(TCP) and ans[TCP].flags == 0x14:
            return (target_ip, port, "closed")
        else:
            return (target_ip, port, "unknown")

    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(syn_port, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                ip, port, status = future.result()
                print(f"[*] {ip}:{port} is {status}")

    except Exception as e:
        print(f"[-] Error during SYN scan: {e}")

def icmp_sweep(ip_range):
    """
    Perform an ICMP ping sweep on a range of IPs.
    """
    print(f"[*] Performing ICMP ping sweep on {ip_range}")
    # Convert ip_range to a list of strings
    if isinstance(ip_range, str):
        ip_range = list(ip_network(ip_range).hosts())
    else:
        ip_range = [str(ip) for ip in ip_range]

    packets = [IP(dst=str(ip))/ICMP() for ip in ip_range]
    ans, _ = send_l3_custom(packets, timeout=2, verbose=0)

    if ans is None:
        return []

    alive_ips = [
        rcv[IP].src
        for _, rcv in ans
        if rcv.haslayer(ICMP) and rcv[ICMP].type == 0
    ]
    for ip in alive_ips:
        print(f"[*] {ip} is up.")

    return alive_ips

def arp_scan(ip_range):
    """
    Perform an ARP scan. This populates the system's ARP cache.
    """
    print(f"[*] Populating ARP cache for range: {ip_range}")
    
    try:
        if isinstance(ip_range, list):
            # Scapy can handle a list of strings for pdst
            target_range = [str(ip) for ip in ip_range]
        else:
            target_range = ip_range

        packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_range)
        ans, _ = send_l2_custom(packet, timeout=10, verbose=0)

        if ans is None:
            return []
        
        discovered = []
        for snd, rcv in ans:
            if rcv.haslayer(ARP):
                discovered.append(rcv[ARP].psrc)
                print(f"Found: {rcv[ARP].psrc} -> {rcv[Ether].src}")
        
        return discovered
    except Exception as e:
        print(f"[-] Error during ARP scan: {e}")
        return []


def ping_scan(target_ip):
    """
    Perform a ping scan on a specific target.
    """
    # Convert IPv4Address object to string
    target_ip = str(target_ip)

    if "/" in target_ip:
        print("[-] ping_scan expects a single host IP, not a CIDR range.")
        return False
    
    # ICMP is Layer 3. Scapy will now use the ARP cache populated by arp_scan()
    ans = sr1(IP(dst=target_ip)/ICMP(), timeout=10, verbose=0)
    return ans is not None


def ping_sweep(ip_range):
    """
    Alias for ICMP sweep over a host range.
    """
    return icmp_sweep(ip_range)


class NetworkScanner:
    def __init__(self, target_range):
        self.target_range = target_range
        self.alive_hosts = []
        self.arp_hosts = []

    def perform_icmp_sweep(self):
        self.alive_hosts = icmp_sweep(self.target_range)

    def perform_arp_scan(self):
        self.arp_hosts = arp_scan(self.target_range)

    def perform_syn_scan(self, ports):
        for host in self.alive_hosts:
            syn_scan_concurrent(host, ports)