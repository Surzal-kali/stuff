"""Scapy packet-crafting tools, exposed to the Brain as @framework_tool callables.

The ``PacketCraft`` / ``PacketUtils`` classes below are the raw engine.  The
module-level ``@framework_tool`` functions further down are the *integration
surface*: each one is a thin wrapper that minted a manifest entry at discovery
time (see ``daharness/registry.py``) so the secretary can call it like any
other framework tool (nmap, paramiko, etc.).

Design notes
------------
* Craft tools return a compact text blob containing a scapy ``summary()`` and
  the packet's ``hex``.  The hex is the currency passed to ``send_packet``,
  ``dissect_packet``, ``modify_packet``, and ``save_packet`` — there is no
  session handle because a crafted packet is stateless (unlike an SSH or MSF
  session).  ``next_hints`` and ``_CHAIN_NEXT`` nudge the model from a craft
  result to ``send_packet``.
* ``send``/``sniff`` need root (raw sockets); craft/dissect do not.  Craft and
  dissection tools are therefore safe to call unprivileged and are the common
  path; send/sniff will simply error if the Brain worker isn't root.
* The capture interface defaults to ``PACKETCRAFT_INTERFACE`` (env) or
  ``enp92s0`` and can be overridden per-call on the send/sniff tools.
"""

import os

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

from constants import framework_tool

TARGET_INTERFACE = os.getenv("PACKETCRAFT_INTERFACE", "enp92s0")
#[ ]TODO:  Needs to take advantage of poor cryptography, it's just sitting there {muy importante now that its on mcp}


# --- module-local helpers -------------------------------------------------

# Singleton engine instance.  Lazy so importing this module during discovery
# never opens a socket or touches an interface.
_craft_instance: "PacketCraft | None" = None


def _craft(interface: str | None = None) -> "PacketCraft":
    """Return the shared PacketCraft engine, bound to ``interface`` if given."""
    global _craft_instance
    if _craft_instance is None or interface is not None:
        _craft_instance = PacketCraft(interface or TARGET_INTERFACE)
    return _craft_instance


def _packet_to_hex(packet: scapy.Packet) -> str:
    """Serialise a crafted packet to a hex string for round-trip through the
    model / send / dissect tools."""
    return bytes(packet).hex()


def _packet_from_hex(hex_string: str) -> scapy.Packet:
    """Reconstruct a packet from a hex string.

    Picks the L2 (``Ether``) or L3 (``IP``) parser by inspecting the IP
    version nibble: crafted IPv4 packets start with ``0x4?``, whereas L2
    frames (ARP, VLAN, DHCP) start with a destination MAC whose high nibble
    is essentially never 4.  This is reliable for everything the craft tools
    below produce.
    """
    raw = bytes.fromhex(hex_string.strip())
    if raw and (raw[0] >> 4) == 4:
        return IP(raw)
    return Ether(raw)


def _craft_result(packet: scapy.Packet) -> str:
    """Standard craft-tool return: summary + hex the model can forward."""
    return (
        f"Packet crafted: {packet.summary()}\n"
        f"hex: {_packet_to_hex(packet)}\n"
        f"Pass the hex to send_packet (to transmit), dissect_packet "
        f"(to inspect), or modify_packet (to change fields)."
    )


def _payload_bytes(payload: str | bytes | None) -> bytes:
    """Coerce a model-supplied payload (usually a str) into bytes."""
    if payload is None or payload == "":
        return b""
    if isinstance(payload, bytes):
        return payload
    return payload.encode("utf-8", errors="replace")
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

    def craft_http_request(self, src_ip: str, dst_ip: str, method: str = "GET", path: str = "/", headers: list[tuple[str, str]] = [], payload: bytes = b"") -> scapy.Packet:
        """Craft an HTTP request packet."""
        headers_dict = dict(headers)
        http_layer = HTTPRequest(
            Method=method,
            Path=path,
            Host=headers_dict.get("Host", ""),
            User_Agent=headers_dict.get("User-Agent", ""),
            Accept=headers_dict.get("Accept", ""),
            Accept_Encoding=headers_dict.get("Accept-Encoding", ""),
            Accept_Language=headers_dict.get("Accept-Language", "")
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


# ===========================================================================
# @framework_tool integration surface
# ===========================================================================
# Everything above is the raw engine.  Everything below is what the Brain sees.
#
# Convention (same as nmap / paramiko_client): one @framework_tool function per
# capability, module-level, with a docstring whose first line is the capability
# blurb used as the semantic-search embedding text.  Craft tools return a text
# blob carrying the packet's hex so it can be forwarded to send / dissect /
# modify / save.  There are NO session handles here — a packet is stateless.

# --- ICMP -----------------------------------------------------------------

@framework_tool(
    "Craft an ICMP Echo Request (ping) packet. Returns the packet hex to pass "
    "to send_packet, dissect_packet, or modify_packet.",
    next_hints=["send_packet with the returned hex"],
)
def craft_icmp_echo(src_ip: str, dst_ip: str, payload: str = ""):
    """Craft an ICMP Echo Request (type 8) packet.

    Args:
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        payload: Optional payload text (encoded to bytes).
    """
    pkt = _craft().icmp_echo_request(src_ip, dst_ip, _payload_bytes(payload))
    return _craft_result(pkt)


@framework_tool(
    "Craft a generic ICMP packet (configurable via modify_packet afterwards). "
    "Returns the packet hex.",
    next_hints=["send_packet with the returned hex", "modify_packet to set ICMP type/code"],
)
def craft_icmp_packet(src_ip: str, dst_ip: str, payload: str = ""):
    """Craft a generic ICMP packet (type/code left at scapy defaults).

    Args:
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        payload: Optional payload text.
    """
    pkt = _craft().craft_icmp_packet(src_ip, dst_ip, _payload_bytes(payload))
    return _craft_result(pkt)


# --- TCP / UDP ------------------------------------------------------------

@framework_tool(
    "Craft a raw TCP packet with chosen flags (e.g. 'S' SYN, 'A' ACK, 'F' FIN, "
    "'R' RST, 'PA' PSH-ACK). Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: str = "S", payload: str = ""):
    """Craft a TCP/IP packet.

    Args:
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        src_port: Source TCP port.
        dst_port: Destination TCP port.
        flags: TCP flag string (S, A, F, R, P, PA, SA, ...).
        payload: Optional payload text.
    """
    pkt = _craft().craft_tcp_packet(src_ip, dst_ip, int(src_port), int(dst_port), flags, _payload_bytes(payload))
    return _craft_result(pkt)


@framework_tool(
    "Craft a raw UDP packet. Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: str = ""):
    """Craft a UDP/IP packet.

    Args:
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        src_port: Source UDP port.
        dst_port: Destination UDP port.
        payload: Optional payload text.
    """
    pkt = _craft().craft_udp_packet(src_ip, dst_ip, int(src_port), int(dst_port), _payload_bytes(payload))
    return _craft_result(pkt)


# --- ARP / L2 / VLAN ------------------------------------------------------

@framework_tool(
    "Craft an ARP request (broadcast) to resolve a target IP's MAC. Returns "
    "the packet hex (an L2/Ether frame — send with send_packet).",
    next_hints=["send_packet with the returned hex"],
)
def craft_arp_request(src_mac: str, src_ip: str, target_ip: str):
    """Craft a broadcast ARP request.

    Args:
        src_mac: Source MAC address (e.g. 'aa:bb:cc:dd:ee:ff').
        src_ip: Source IP (sender protocol address).
        target_ip: IP whose MAC you want to resolve.
    """
    pkt = _craft().craft_arp_request(src_mac, src_ip, target_ip)
    return _craft_result(pkt)


@framework_tool(
    "Craft a directed ARP packet (request or reply depending on op set later). "
    "Returns the packet hex.",
    next_hints=["send_packet with the returned hex", "modify_packet to set ARP op"],
)
def craft_arp_packet(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str):
    """Craft a directed ARP packet between two MAC/IP pairs.

    Args:
        src_mac: Sender MAC.
        dst_mac: Target MAC.
        src_ip: Sender IP.
        dst_ip: Target IP.
    """
    pkt = _craft().craft_arp_packet(src_mac, dst_mac, src_ip, dst_ip)
    return _craft_result(pkt)


@framework_tool(
    "Craft an 802.1Q VLAN-tagged Ethernet frame. Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_vlan_frame(src_mac: str, dst_mac: str, vlan_id: int, payload: str = ""):
    """Craft a VLAN-tagged frame.

    Args:
        src_mac: Source MAC.
        dst_mac: Destination MAC.
        vlan_id: 802.1Q VLAN tag (0-4095).
        payload: Optional payload text.
    """
    pkt = _craft().vlan_frame(src_mac, dst_mac, int(vlan_id), _payload_bytes(payload))
    return _craft_result(pkt)


@framework_tool(
    "Craft a DHCP Discover packet (L2 broadcast). Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_dhcp_discover(src_mac: str):
    """Craft a DHCP DISCOVER.

    Args:
        src_mac: Client MAC address.
    """
    pkt = _craft().dhcp_discover(src_mac)
    return _craft_result(pkt)


# --- DNS / mDNS -----------------------------------------------------------

@framework_tool(
    "Craft a DNS request packet (UDP/53) for a domain name. Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_dns_query(src_ip: str, dst_ip: str, query_name: str):
    """Craft a DNS query.

    Args:
        src_ip: Source IP.
        dst_ip: DNS server IP.
        query_name: Name to resolve (e.g. 'example.com').
    """
    pkt = _craft().craft_dns_query(src_ip, dst_ip, query_name)
    return _craft_result(pkt)


@framework_tool(
    "Craft a forged DNS response (authoritative, single answer). Useful for "
    "DNS spoofing / cache-poisoning demos. Returns the packet hex.",
    next_hints=["send_packet with the returned hex", "report_finding"],
)
def craft_dns_response(src_ip: str, dst_ip: str, query_name: str, answer_ip: str):
    """Craft a forged DNS response with one answer record.

    Args:
        src_ip: Spoofed resolver IP.
        dst_ip: Victim IP.
        query_name: Query name to answer.
        answer_ip: IP to put in the answer record.
    """
    pkt = _craft().craft_dns_response(src_ip, dst_ip, query_name, answer_ip)
    return _craft_result(pkt)


@framework_tool(
    "Craft a forged DNS response with multiple answer records (round-robin / "
    "rotating spoof). Returns the packet hex.",
    next_hints=["send_packet with the returned hex", "report_finding"],
)
def craft_dns_response_multi(src_ip: str, dst_ip: str, query_name: str, answer_ips: list):
    """Craft a forged DNS response with several answer records.

    Args:
        src_ip: Spoofed resolver IP.
        dst_ip: Victim IP.
        query_name: Query name to answer.
        answer_ips: List of IPs to put in the answer records.
    """
    ips = [str(ip) for ip in answer_ips]
    pkt = _craft().craft_dns_response_multi(src_ip, dst_ip, query_name, ips)
    return _craft_result(pkt)


@framework_tool(
    "Craft an mDNS request packet (UDP/5353) for a domain name. Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_mdns_query(src_ip: str, dst_ip: str, query_name: str):
    """Craft an mDNS query.

    Args:
        src_ip: Source IP.
        dst_ip: mDNS target (usually 224.0.0.251).
        query_name: Name to query (e.g. '_http._tcp.local').
    """
    pkt = _craft().craft_mDNS_query(src_ip, dst_ip, query_name)
    return _craft_result(pkt)


# --- HTTP -----------------------------------------------------------------

@framework_tool(
    "Craft an HTTP request packet (TCP/80). Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_http_request(src_ip: str, dst_ip: str, method: str = "GET", path: str = "/", host: str = "", user_agent: str = "", payload: str = ""):
    """Craft an HTTP request packet.

    Args:
        src_ip: Source IP.
        dst_ip: Destination IP (web server).
        method: HTTP method (GET, POST, ...).
        path: Request path.
        host: Host header value.
        user_agent: User-Agent header value.
        payload: Optional body text.
    """
    headers = [("Host", host), ("User-Agent", user_agent)]
    pkt = _craft().craft_http_request(
        src_ip, dst_ip, method=method, path=path, headers=headers, payload=_payload_bytes(payload)
    )
    return _craft_result(pkt)


@framework_tool(
    "Craft an HTTP response packet (TCP/80). Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_http_response(src_ip: str, dst_ip: str, status_code: int = 200, reason: str = "OK", content_type: str = "text/html", payload: str = ""):
    """Craft an HTTP response packet.

    Args:
        src_ip: Server IP.
        dst_ip: Client IP.
        status_code: HTTP status code.
        reason: Reason phrase.
        content_type: Content-Type header value.
        payload: Optional body text.
    """
    body = _payload_bytes(payload)
    pkt = _craft().craft_http_response(
        src_ip, dst_ip, status_code=int(status_code), reason=reason,
        headers={"Content-Type": content_type}, payload=body,
    )
    return _craft_result(pkt)


# --- Transport / capture / analysis --------------------------------------

@framework_tool(
    "Send a previously crafted packet (by hex) on the wire. Requires root "
    "(raw sockets). Pass the hex returned by any craft_* tool.",
    next_hints=["sniff_packets to capture replies", "dissect_packet to inspect a reply"],
)
def send_packet(hex: str, count: int = 1, interval: float = 0.1, interface: str = ""):
    """Send a crafted packet one or more times.

    Args:
        hex: Packet hex string from a craft_* tool.
        count: Number of times to send.
        interval: Seconds between sends.
        interface: Override the default capture interface.
    """
    try:
        pkt = _packet_from_hex(hex)
        iface = interface or TARGET_INTERFACE
        for _ in range(int(count)):
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(float(interval))
        return f"Sent {count} packet(s) on {iface}: {pkt.summary()}"
    except PermissionError as e:
        return (
            f"send_packet requires root/raw-socket capability: {e}. "
            "Run the Brain worker as root, or use craft_* + dissect_packet "
            "for offline analysis."
        )
    except Exception as e:
        return f"send_packet error: {e}"


@framework_tool(
    "Sniff packets on an interface with an optional BPF filter. Returns a "
    "text summary of each captured packet (with its hex for dissection). "
    "Requires root.",
    next_hints=["dissect_packet with a captured hex to inspect a packet fully"],
)
def sniff_packets(filter: str = "", count: int = 10, timeout: int = 30, interface: str = ""):
    """Sniff packets and return a readable summary list.

    Args:
        filter: BPF filter string (e.g. 'tcp port 80', 'icmp').
        count: Number of packets to capture.
        timeout: Capture timeout in seconds.
        interface: Override the default capture interface.
    """
    try:
        iface = interface or TARGET_INTERFACE
        pkts = _craft(iface).sniff_packets(filter=filter, count=int(count), timeout=int(timeout))
        if not pkts:
            return f"No packets captured on {iface} (filter={filter!r})."
        lines = [f"Captured {len(pkts)} packet(s) on {iface}:"]
        for i, p in enumerate(pkts, 1):
            lines.append(f"  [{i}] {p.summary()}  hex={_packet_to_hex(p)}")
        return "\n".join(lines)
    except PermissionError as e:
        return f"sniff_packets requires root/raw-socket capability: {e}."
    except Exception as e:
        return f"sniff_packets error: {e}"


@framework_tool(
    "Dissect a packet (by hex) into a full field-by-field breakdown. No root "
    "needed — pure parsing.",
)
def dissect_packet(hex: str):
    """Dissect a packet hex string into a full scapy show() breakdown.

    Args:
        hex: Packet hex string from a craft_* or sniff_packets tool.
    """
    try:
        pkt = _packet_from_hex(hex)
        show = pkt.show(dump=True)
        return f"{pkt.summary()}\n{show}"
    except Exception as e:
        return f"dissect_packet error: {e}"


@framework_tool(
    "Modify one or more fields on a crafted packet (by hex) and return the new "
    "hex. Pass fields as a JSON object mapping field names to values, e.g. "
    "{\"ttl\": 1, \"flags\": \"RA\"}. No root needed.",
    next_hints=["send_packet with the new hex", "dissect_packet to verify"],
)
def modify_packet(hex: str, fields: dict):
    """Modify fields on a packet and return the updated hex.

    Args:
        hex: Packet hex string to modify.
        fields: JSON object of field-name -> value to set on the packet.
    """
    try:
        pkt = _packet_from_hex(hex)
        # Coerce values: scapy fields are typed; str is accepted for most.
        coerced = {k: v for k, v in fields.items()}
        pkt = _craft().utils.modify_packet(pkt, **coerced)
        return _craft_result(pkt)
    except Exception as e:
        return f"modify_packet error: {e}"


@framework_tool(
    "Export a packet (by hex) as a formatted hexdump for human review. No root "
    "needed.",
)
def export_packet_hex(hex: str):
    """Return a formatted hexdump of a packet.

    Args:
        hex: Packet hex string.
    """
    try:
        pkt = _packet_from_hex(hex)
        dump = hexdump(pkt, dump=True)
        return f"{pkt.summary()}\n{dump}"
    except Exception as e:
        return f"export_packet_hex error: {e}"


@framework_tool(
    "Save a packet (by hex) to a pcap file for later analysis or evidence. No "
    "root needed.",
    next_hints=["report_finding to record the saved pcap path"],
)
def save_packet(hex: str, filename: str):
    """Save a packet to a pcap file.

    Args:
        hex: Packet hex string.
        filename: Output .pcap path.
    """
    try:
        pkt = _packet_from_hex(hex)
        scapy.wrpcap(filename, pkt)
        return f"Saved packet ({pkt.summary()}) to {filename}"
    except Exception as e:
        return f"save_packet error: {e}"


@framework_tool(
    "Load the first packet from a pcap file and return its hex + summary. No "
    "root needed.",
    next_hints=["dissect_packet with the returned hex"],
)
def load_packet(filename: str):
    """Load the first packet from a pcap file.

    Args:
        filename: .pcap path to read.
    """
    try:
        pkts = scapy.rdpcap(filename)
        if not pkts:
            return f"No packets in {filename}."
        pkt = pkts[0]
        return _craft_result(pkt)
    except Exception as e:
        return f"load_packet error: {e}"


@framework_tool(
    "Wait for a single packet matching a BPF filter on the default interface "
    "and return its hex + summary. Requires root.",
    next_hints=["dissect_packet with the returned hex"],
)
def wait_for_packet(filter: str = "", timeout: int = 30, interface: str = ""):
    """Wait for one matching packet.

    Args:
        filter: BPF filter string.
        timeout: Seconds to wait.
        interface: Override the default capture interface.
    """
    try:
        iface = interface or TARGET_INTERFACE
        pkt = _craft(iface).utils.wait_for_packet(filter=filter, timeout=int(timeout))
        if pkt is None:
            return f"No packet matched filter={filter!r} within {timeout}s on {iface}."
        return _craft_result(pkt)
    except PermissionError as e:
        return f"wait_for_packet requires root/raw-socket capability: {e}."
    except Exception as e:
        return f"wait_for_packet error: {e}"
