import scapy.all as scapy
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
import random
import string
import time
import cryptography
from scapy.all import sr1, send, sniff, hexdump, Raw, sendp

TARGET_INTERFACE = "eth0" 

class PacketUtils:
    def dissect_packet(self, packet: scapy.Packet):
        """Dissect a packet."""
        packet.show()

    def extract_payload(self, packet: scapy.Packet) -> bytes:
        """Extract the payload from a packet."""
        if Raw in packet:
            return bytes(packet[Raw].load)
        return b""

    def modify_packet(self, packet: scapy.Packet, **kwargs) -> scapy.Packet:
        """Modify fields of a packet."""
        for field, value in kwargs.items():
            if hasattr(packet, field):
                setattr(packet, field, value)
        return packet

    def random_string(self, length: int = 10) -> str:
        """Generate a random string of specified length."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def export_packet_hex(self, packet: scapy.Packet) -> str | None:
        """Export a packet in hexadecimal format."""
        return hexdump(packet, dump=True)

    def import_packet_hex(self, hex_string: str) -> scapy.Packet:
        """Import a packet from a hexadecimal string."""
        raw_bytes = bytes.fromhex(hex_string)
        return Ether(raw_bytes) if raw_bytes.startswith(b'\x00\x00') else IP(raw_bytes)

    def wait_for_packet(self, filter: str = "", timeout: int = 30) -> scapy.Packet | None:
        """Wait for a packet matching the filter."""
        packets = sniff(iface=TARGET_INTERFACE, filter=filter, count=1, timeout=timeout)
        return packets[0] if packets else None

class PacketCraft:
    def __init__(self, interface: str = TARGET_INTERFACE):
        self.interface = interface
        self.utils = PacketUtils()

    def icmp_echo_request(self, src_ip: str, dst_ip: str, payload: bytes = b"") -> scapy.Packet:
        """Craft an ICMP Echo Request packet."""
        packet = IP(src=src_ip, dst=dst_ip) / ICMP(type=8) / Raw(load=payload)
        return packet

    def icmp_echo_reply(self, src_ip: str, dst_ip: str, payload: bytes = b"") -> scapy.Packet:
        """Craft an ICMP Echo Reply packet."""
        packet = IP(src=src_ip, dst=dst_ip) / ICMP(type=0) / Raw(load=payload)
        return packet

    def craft_http_request(self, src_ip: str, dst_ip: str, method: str = "GET", path: str = "/", headers: dict = None, payload: bytes = b"") -> scapy.Packet:
        """Craft an HTTP request packet."""
        if headers is None:
            headers = {}
        http_layer = HTTPRequest(
            Method=method,
            Path=path,
            Host=headers.get("Host", ""),
            User_Agent=headers.get("User-Agent", ""),
            Accept=headers.get("Accept", ""),
            Accept_Encoding=headers.get("Accept-Encoding", ""),
            Accept_Language=headers.get("Accept-Language", "")
        )
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") / http_layer / Raw(load=payload)
        return packet

    def craft_http_response(self, src_ip: str, dst_ip: str, status_code: int = 200, reason: str = "OK", headers: dict | None = None, payload: bytes = b"") -> scapy.Packet:
        """Craft an HTTP response packet."""
        if headers is None:
            headers = {}
        http_layer = HTTPResponse(
            Status_Code=status_code,
            Reason_Phrase=reason,
            Server=headers.get("Server", ""),
            Content_Type=headers.get("Content-Type", ""),
            Content_Length=str(len(payload))
        )
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") / http_layer / Raw(load=payload)
        return packet

    def craft_dns_response(self, src_ip: str, dst_ip: str, query_name: str, answer_ip: str) -> scapy.Packet:
        """Craft a DNS response packet."""
        dns_layer = DNS(
            id=random.randint(0, 65535),
            qr=1,
            aa=1,
            qd=DNSQR(qname=query_name),
            an=DNSRR(rrname=query_name, rdata=answer_ip)
        )
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / dns_layer
        return packet

    def craft_dns_response_multi(self, src_ip: str, dst_ip: str, query_name: str, answer_ips: list[str]) -> scapy.Packet:
        """Craft a DNS response packet with multiple answers."""
        dns_layer = DNS(
            id=random.randint(0, 65535),
            qr=1,
            aa=1,
            qd=DNSQR(qname=query_name),
            an=DNSRR(rrname=query_name, rdata=answer_ips[0])
        )
        for ip in answer_ips[1:]:
            dns_layer.an /= DNSRR(rrname=query_name, rdata=ip)
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / dns_layer
        return packet

    def craft_tcp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: str = "S", payload: bytes = b"") -> scapy.Packet:
        """Craft a TCP packet."""
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags=flags) / Raw(load=payload)
        return packet

    def craft_udp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes = b"") -> scapy.Packet:
        """Craft a UDP packet."""
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=payload)
        return packet

    def craft_arp_packet(self, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str) -> scapy.Packet:
        """Craft an ARP packet."""
        packet = Ether(src=src_mac, dst=dst_mac) / ARP(hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
        return packet

    def vlan_frame(self, src_mac: str, dst_mac: str, vlan_id: int, payload: bytes = b"") -> scapy.Packet:
        """Craft a VLAN frame."""
        packet = Ether(src=src_mac, dst=dst_mac) / Dot1Q(vlan=vlan_id) / Raw(load=payload)
        return packet

    def craft_icmp_packet(self, src_ip: str, dst_ip: str, payload: bytes = b"") -> scapy.Packet:
        """Craft an ICMP packet."""
        packet = IP(src=src_ip, dst=dst_ip) / ICMP() / Raw(load=payload)
        return packet

    def craft_dns_query(self, src_ip: str, dst_ip: str, query_name: str) -> scapy.Packet:
        """Craft a DNS query packet."""
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name))
        return packet

    def craft_arp_request(self, src_mac: str, src_ip: str, target_ip: str) -> scapy.Packet:
        """Craft an ARP request packet."""
        packet = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(hwsrc=src_mac, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=target_ip, op=1)
        return packet

    def dhcp_discover(self, src_mac: str) -> scapy.Packet:
        """Craft a DHCP discover packet."""
        packet = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=src_mac.replace(":", "")) / DHCP(options=[("message-type", "discover"), "end"])
        return packet

    def craft_mDNS_query(self, src_ip: str, dst_ip: str, query_name: str) -> scapy.Packet:
        """Craft an mDNS query packet."""
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=5353) / DNS(rd=1, qd=DNSQR(qname=query_name))
        return packet

    def send_packet(self, packet: scapy.Packet, count: int = 1, interval: float = 0.1):
        """Send a packet multiple times with a specified interval."""
        for _ in range(count):
            sendp(packet, iface=self.interface, verbose=False)
            time.sleep(interval)

    def sniff_packets(self, filter: str = "", count: int = 10, timeout: int = 30):
        """Sniff packets on the specified interface."""
        packets = sniff(iface=self.interface, filter=filter, count=count, timeout=timeout)
        return packets

    def save_packet(self, packet: scapy.Packet, filename: str):
        """Save a packet to a file."""
        scapy.wrpcap(filename, packet)

    def load_packet(self, filename: str) -> scapy.Packet | None:
        """Load a packet from a file."""
        packets = scapy.rdpcap(filename)
        return packets[0] if packets else None
