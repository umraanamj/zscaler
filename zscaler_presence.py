#!/usr/bin/env python3
"""zscaler_presence.py — network health analyzer.

Reads packet captures from two vantage points along a tunnelled path and
produces a troubleshooting report: what's succeeding, what's failing, and where
a flow breaks. Inputs:

  1. --user-pcap    capture(s) at the client end — the endpoint reaching out to
                    destinations (decrypted inner traffic + DNS).
  2. --connector    capture(s) where the tunnel lands/egresses — bidirectional:
                    client requests in, server responses out.
  3. --subnets      optional comma-separated CIDRs to focus on.
  4. --fqdns        optional comma-separated FQDNs to focus on.

The same session appears at both vantage points, so destinations are correlated
across the two captures (by destination IP/port + FQDN; the connector usually
NATs the client source, so that isn't used for matching). For each destination
it reports the specific issue and where it occurred — left the tunnel but never
reached the connector, no SYN-ACK, RST, TLS alert, ICMP unreachable, TCP
retransmissions — plus DNS failures (NXDOMAIN / SERVFAIL / REFUSED / no
response) and a healthy list.

No third-party dependencies — pure standard library; Python 3.7+.

Capture tips
------------
Capture on the interface that carries the decrypted application traffic so the
real destinations, DNS, and TLS SNI are visible:
    sudo tcpdump -i <interface> -w host.pcap
The tool warns when a capture looks like an opaque/encrypted tunnel with no
visible inner destinations.

Usage
-----
    python3 zscaler_presence.py \
        --user-pcap host.pcap \
        --connector connector1.pcap connector2.pcap \
        [--subnets 10.0.0.0/8,192.168.1.0/24] [--fqdns app.example.com] \
        [--source 10.6.0.2] [--show-all] [--no-resolve] [--no-color]
"""

import argparse
import glob
import ipaddress
import os
import shlex
import socket
import struct
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Bump by 0.1 every iteration.
VERSION = "2.9"

# ---------------------------------------------------------------------------
# Terminal colors (auto-disabled when not a TTY or NO_COLOR is set)
# ---------------------------------------------------------------------------


class Palette:
    def __init__(self, enabled):
        codes = {
            "reset": "0", "bold": "1", "dim": "2",
            "red": "31", "green": "32", "yellow": "33",
            "blue": "34", "magenta": "35", "cyan": "36", "grey": "90",
        }
        for name, code in codes.items():
            setattr(self, name, ("\033[%sm" % code) if enabled else "")

    def wrap(self, text, *styles):
        if not styles or not styles[0]:
            return text
        return "".join(styles) + text + self.reset


# ---------------------------------------------------------------------------
# pcap / pcapng readers  (yield (timestamp_float, linktype, packet_bytes))
# ---------------------------------------------------------------------------

# DLT / LINKTYPE values we know how to peel down to an IP packet.
DLT_NULL = 0
DLT_ETHERNET = 1
DLT_RAW_LIST = (12, 14, 101)   # raw IP, various historical numbers
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276


class PcapFormatError(Exception):
    pass


def iter_packets(path):
    """Yield (ts, linktype, data) for every packet in a pcap or pcapng file."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(f)
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d",
                       b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            yield from _iter_classic(f, magic)
        else:
            raise PcapFormatError(
                "%s: not a pcap/pcapng file (bad magic %r)" % (path, magic))


def _iter_classic(f, magic):
    big = magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
    nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
    endian = ">" if big else "<"
    rest = f.read(20)              # remainder of the 24-byte global header
    if len(rest) < 20:
        raise PcapFormatError("truncated pcap global header")
    linktype = struct.unpack(endian + "I", rest[16:20])[0]
    divisor = 1e9 if nano else 1e6
    while True:
        hdr = f.read(16)
        if len(hdr) < 16:
            break
        ts_sec, ts_frac, incl_len, _orig = struct.unpack(endian + "IIII", hdr)
        data = f.read(incl_len)
        if len(data) < incl_len:
            break
        yield (ts_sec + ts_frac / divisor, linktype, data)


def _iter_pcapng(f):
    # We've consumed the 4-byte SHB block type. Read length + byte-order magic.
    raw_len = f.read(4)
    bom = f.read(4)
    if len(raw_len) < 4 or len(bom) < 4:
        raise PcapFormatError("truncated pcapng section header")
    endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
    shb_len = struct.unpack(endian + "I", raw_len)[0]
    # already consumed type(4)+len(4)+bom(4)=12; read the rest of the block
    # (major/minor/section-length/options + trailing total-length)
    f.read(shb_len - 12)

    interfaces = []                # interface_id -> (linktype, ts_divisor)
    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            break
        btype, blen = struct.unpack(endian + "II", hdr)
        if blen < 12:
            break
        body = f.read(blen - 12)
        f.read(4)                  # trailing total-length
        if len(body) < blen - 12:
            break

        if btype == 0x00000001:                     # Interface Description Block
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            divisor = _pcapng_tsresol(body[8:], endian)
            interfaces.append((linktype, divisor))
        elif btype == 0x00000006:                    # Enhanced Packet Block
            iface_id, ts_hi, ts_lo, caplen = struct.unpack(
                endian + "IIII", body[0:16])
            data = body[20:20 + caplen]
            lt, divisor = interfaces[iface_id] if iface_id < len(interfaces) else (DLT_ETHERNET, 1e6)
            ts = ((ts_hi << 32) | ts_lo) / divisor
            yield (ts, lt, data)
        elif btype == 0x00000003:                    # Simple Packet Block
            orig = struct.unpack(endian + "I", body[0:4])[0]
            data = body[4:4 + orig]
            lt, _ = interfaces[0] if interfaces else (DLT_ETHERNET, 1e6)
            yield (0.0, lt, data)
        # all other block types (name resolution, stats, custom) are ignored


def _pcapng_tsresol(opts, endian):
    """Parse the if_tsresol option (code 9) from an IDB; default microseconds."""
    i = 0
    try:
        while i + 4 <= len(opts):
            code, length = struct.unpack(endian + "HH", opts[i:i + 4])
            i += 4
            val = opts[i:i + length]
            if code == 0:                # opt_endofopt
                break
            if code == 9 and length >= 1:
                r = val[0]
                return float(1 << (r & 0x7F)) if (r & 0x80) else 10.0 ** r
            i += length + ((4 - length % 4) % 4)   # pad to 32-bit boundary
    except struct.error:
        pass
    return 1e6


# ---------------------------------------------------------------------------
# Link / IP / L4 decoding
# ---------------------------------------------------------------------------


def _looks_like_ip(b, off):
    return off < len(b) and (b[off] >> 4) in (4, 6)


def link_to_ip(linktype, data):
    """Return the IP-layer bytes from a link-layer frame, or None."""
    if linktype == DLT_ETHERNET:
        if len(data) < 14:
            return None
        etype = struct.unpack(">H", data[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:   # VLAN tag(s)
            etype = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
        if etype in (0x0800, 0x86DD):
            return data[off:]
        return None
    if linktype == DLT_NULL:
        return data[4:] if _looks_like_ip(data, 4) else None
    if linktype == DLT_LINUX_SLL:
        return data[16:] if len(data) > 16 else None
    if linktype == DLT_LINUX_SLL2:
        return data[20:] if len(data) > 20 else None
    if linktype in DLT_RAW_LIST:
        return data if _looks_like_ip(data, 0) else None
    # unknown link type: best-effort sniff for a raw IP header
    return data if _looks_like_ip(data, 0) else None


def decode_ip(ipdata):
    """Return (src, dst, l4proto, l4payload) or None for an IP packet."""
    if not ipdata:
        return None
    version = ipdata[0] >> 4
    try:
        if version == 4:
            ihl = (ipdata[0] & 0x0F) * 4
            if ihl < 20 or len(ipdata) < ihl:
                return None
            proto = ipdata[9]
            src = str(ipaddress.IPv4Address(ipdata[12:16]))
            dst = str(ipaddress.IPv4Address(ipdata[16:20]))
            total = struct.unpack(">H", ipdata[2:4])[0] or len(ipdata)
            return src, dst, proto, ipdata[ihl:total]
        if version == 6:
            if len(ipdata) < 40:
                return None
            nxt = ipdata[6]
            src = str(ipaddress.IPv6Address(ipdata[8:24]))
            dst = str(ipaddress.IPv6Address(ipdata[24:40]))
            payload = ipdata[40:]
            # walk a couple of common extension headers to reach TCP/UDP
            for _ in range(4):
                if nxt in (6, 17) or len(payload) < 8:
                    break
                if nxt in (0, 43, 60):          # hop-by-hop / routing / dest-opts
                    ext_len = (payload[1] + 1) * 8
                    nxt = payload[0]
                    payload = payload[ext_len:]
                else:
                    break
            return src, dst, nxt, payload
    except (ValueError, struct.error, IndexError):
        return None
    return None


def decode_l4(proto, payload):
    """Return (sport, dport, l4payload, seq, flags) for TCP/UDP, else None.
    seq/flags are None for UDP. flags is the TCP flags byte (FIN=1, SYN=2,
    RST=4, PSH=8, ACK=16, …)."""
    try:
        if proto == 6 and len(payload) >= 20:               # TCP
            sport, dport = struct.unpack(">HH", payload[0:4])
            seq = struct.unpack(">I", payload[4:8])[0]
            off = ((payload[12] >> 4) & 0xF) * 4
            flags = payload[13]
            return sport, dport, payload[off:], seq, flags
        if proto == 17 and len(payload) >= 8:               # UDP
            sport, dport = struct.unpack(">HH", payload[0:4])
            return sport, dport, payload[8:], None, None
    except (struct.error, IndexError):
        return None
    return None


def ipv4_fragment(ipdata):
    """For IPv4: (is_fragment, is_continuation). A continuation fragment
    (offset>0) carries no L4 header, so it can't be decoded past IP."""
    try:
        if (ipdata[0] >> 4) == 4 and len(ipdata) >= 8:
            ff = struct.unpack(">H", ipdata[6:8])[0]
            return bool(ff & 0x2000) or (ff & 0x1FFF) > 0, (ff & 0x1FFF) > 0
    except (struct.error, IndexError):
        pass
    return False, False


def parse_tcp_mss(seg):
    """Read the MSS option from a TCP segment's options, or None."""
    try:
        if len(seg) < 20:
            return None
        off = ((seg[12] >> 4) & 0xF) * 4
        i = 20
        while i < off and i < len(seg):
            kind = seg[i]
            if kind == 0:                       # end of options
                break
            if kind == 1:                       # NOP
                i += 1
                continue
            if i + 1 >= len(seg):
                break
            ln = seg[i + 1]
            if ln < 2:
                break
            if kind == 2 and ln == 4 and i + 4 <= len(seg):
                return struct.unpack(">H", seg[i + 2:i + 4])[0]
            i += ln
    except (struct.error, IndexError):
        pass
    return None


# TCP flag bits
TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10


def parse_icmp_error(proto, payload):
    """Classify an ICMP/ICMPv6 error message. Returns a short label or None."""
    if len(payload) < 2:
        return None
    t, code = payload[0], payload[1]
    if proto == 1:                                          # ICMPv4
        if t == 3:
            v4 = {0: "net unreachable", 1: "host unreachable",
                  2: "protocol unreachable", 3: "port unreachable",
                  4: "fragmentation needed", 9: "net admin-prohibited",
                  10: "host admin-prohibited", 13: "comms admin-prohibited"}
            return "ICMP dest unreachable — " + v4.get(code, "code %d" % code)
        if t == 11:
            return "ICMP time exceeded"
    elif proto == 58:                                       # ICMPv6
        if t == 1:
            v6 = {0: "no route", 1: "admin-prohibited", 3: "address unreachable",
                  4: "port unreachable"}
            return "ICMPv6 dest unreachable — " + v6.get(code, "code %d" % code)
        if t == 3:
            return "ICMPv6 time exceeded"
    return None


def icmp_embedded_tuple(proto, payload):
    """ICMP errors quote the original packet that failed. Pull its full identity
    (l4proto, src_ip, src_port, dst_ip, dst_port) so the error can be attributed
    to the exact connection — not every stream sharing the server IP. Ports are
    None when the quote is too short. Returns None if it can't be parsed."""
    inner = payload[8:]                                     # after 8-byte ICMP hdr
    try:
        if proto == 1 and len(inner) >= 20 and (inner[0] >> 4) == 4:
            ihl = (inner[0] & 0x0F) * 4
            l4 = inner[9]
            sip = str(ipaddress.IPv4Address(inner[12:16]))
            dip = str(ipaddress.IPv4Address(inner[16:20]))
            sp = dp = None
            if l4 in (6, 17) and len(inner) >= ihl + 4:
                sp, dp = struct.unpack(">HH", inner[ihl:ihl + 4])
            return l4, sip, sp, dip, dp
        if proto == 58 and len(inner) >= 40 and (inner[0] >> 4) == 6:
            l4 = inner[6]
            sip = str(ipaddress.IPv6Address(inner[8:24]))
            dip = str(ipaddress.IPv6Address(inner[24:40]))
            sp = dp = None
            if l4 in (6, 17) and len(inner) >= 44:
                sp, dp = struct.unpack(">HH", inner[40:44])
            return l4, sip, sp, dip, dp
    except (struct.error, IndexError, ValueError):
        pass
    return None


# TLS alert descriptions we care to name; others shown by number
_TLS_ALERTS = {
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    48: "unknown_ca", 49: "access_denied", 51: "decrypt_error",
    70: "protocol_version", 80: "internal_error", 86: "inappropriate_fallback",
    112: "unrecognized_name", 116: "certificate_required",
}


def tls_scan(app):
    """Walk the TLS records that begin within one TCP segment (from offset 0)
    and report what's there. Returns (has_clienthello, has_serverhello, alert)
    where alert is (level, desc) or None.

    Walking records — and validating each record's version + length — finds a
    ServerHello even when it isn't the first record in the segment, and avoids
    treating coincidental 0x15 bytes in encrypted/mid-stream data as alerts.
    (Records split across TCP segments still can't be seen without full
    reassembly; the handshake record header is normally at the segment start.)"""
    is_ch = is_sh = False
    alert = None
    i, n = 0, len(app)
    while i + 5 <= n:
        ct = app[i]
        if app[i + 1] != 0x03 or app[i + 2] > 0x04 or ct not in (0x14, 0x15, 0x16, 0x17):
            break                                           # not a TLS record start
        rlen = (app[i + 3] << 8) | app[i + 4]
        if ct == 0x16 and i + 5 < n:                        # handshake
            ht = app[i + 5]
            if ht == 0x01:
                is_ch = True
            elif ht == 0x02:
                is_sh = True
        elif ct == 0x15 and rlen == 2 and i + 6 < n:        # alert
            lvl, dsc = app[i + 5], app[i + 6]
            if lvl in (1, 2) and not (lvl == 1 and dsc == 0):   # skip close_notify
                alert = ("fatal" if lvl == 2 else "warning",
                         _TLS_ALERTS.get(dsc, "alert %d" % dsc))
        if rlen == 0:
            break
        i += 5 + rlen
    return is_ch, is_sh, alert


_TLS_VERSIONS = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}


# ---------------------------------------------------------------------------
# Application-layer extractors: DNS answers, TLS SNI, encapsulated-tunnel fingerprint
# ---------------------------------------------------------------------------


def _dns_name(buf, off):
    """Decode a (possibly compressed) DNS name. Returns (name, next_off)."""
    labels = []
    next_off = None
    jumps = 0
    while off < len(buf):
        length = buf[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:                  # compression pointer
            if off + 1 >= len(buf):
                break
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if next_off is None:
                next_off = off + 2
            off = ptr
            jumps += 1
            if jumps > 32:                           # guard against loops
                break
            continue
        off += 1
        labels.append(buf[off:off + length].decode("ascii", "replace"))
        off += length
    if next_off is None:
        next_off = off
    return ".".join(labels), next_off


DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}


def parse_dns(payload):
    """Parse a DNS message. Returns a dict:
      {id, is_response, rcode, qname, answers: [(name, value), ...]}
    or None if it doesn't parse. 'value' is an IP, or 'cname:<name>'."""
    try:
        if len(payload) < 12:
            return None
        txid, flags, qd, an = struct.unpack(">HHHH", payload[0:8])
        is_response = bool(flags & 0x8000)
        rcode = flags & 0x000F
        off = 12
        qname = None
        for i in range(qd):
            name, off = _dns_name(payload, off)
            off += 4                                  # qtype + qclass
            if i == 0:
                qname = name
        answers = []
        for _ in range(an):
            name, off = _dns_name(payload, off)
            if off + 10 > len(payload):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(
                ">HHIH", payload[off:off + 10])
            off += 10
            rdata = payload[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:             # A
                answers.append((name, str(ipaddress.IPv4Address(rdata))))
            elif rtype == 28 and rdlen == 16:         # AAAA
                answers.append((name, str(ipaddress.IPv6Address(rdata))))
            elif rtype == 5:                          # CNAME (alias -> name)
                cname, _ = _dns_name(payload, off - rdlen)
                if cname:
                    answers.append((name, "cname:" + cname))
        return {"id": txid, "is_response": is_response, "rcode": rcode,
                "qname": qname, "answers": answers}
    except (struct.error, IndexError, ValueError):
        return None


def parse_client_hello(tcp_payload):
    """Parse a TLS ClientHello. Returns (sni, version) where either may be None.
    version is the highest version offered (supported_versions ext if present,
    else the ClientHello version field)."""
    p = tcp_payload
    sni = None
    version = None
    try:
        if len(p) < 6 or p[0] != 0x16:               # TLS handshake record
            return None, None
        if p[5] != 0x01:                             # ClientHello
            return None, None
        version = _TLS_VERSIONS.get(struct.unpack(">H", p[9:11])[0])  # client_version
        # skip: record hdr(5) + hs type(1) + hs len(3) + version(2) + random(32)
        i = 5 + 1 + 3 + 2 + 32
        if i >= len(p):
            return sni, version
        i += 1 + p[i]                                # session id
        if i + 2 > len(p):
            return sni, version
        i += 2 + struct.unpack(">H", p[i:i + 2])[0]  # cipher suites
        if i + 1 > len(p):
            return sni, version
        i += 1 + p[i]                                # compression methods
        if i + 2 > len(p):
            return sni, version
        i += 2                                       # extensions block length
        while i + 4 <= len(p):
            ext_type, ext_len = struct.unpack(">HH", p[i:i + 4])
            i += 4
            ext = p[i:i + ext_len]
            if ext_type == 0x0000 and len(ext) >= 5:           # server_name
                name_len = struct.unpack(">H", ext[3:5])[0]
                sni = ext[5:5 + name_len].decode("ascii", "replace")
            elif ext_type == 0x002b and len(ext) >= 1:         # supported_versions
                best = None
                for j in range(1, len(ext) - 1, 2):
                    v = _TLS_VERSIONS.get(struct.unpack(">H", ext[j:j + 2])[0])
                    if v and (best is None or v > best):
                        best = v
                if best:
                    version = best
            i += ext_len
    except (struct.error, IndexError, ValueError):
        return sni, version
    return sni, version


def looks_encapsulated(udp_payload):
    """Encapsulated-tunnel fingerprint: a UDP payload whose first byte is 1-4
    followed by three reserved zero bytes (a common handshake/keepalive shape)."""
    p = udp_payload
    return len(p) >= 4 and p[0] in (1, 2, 3, 4) and p[1] == 0 and p[2] == 0 and p[3] == 0


# ---------------------------------------------------------------------------
# Configured-list loading + matching
# ---------------------------------------------------------------------------


def _as_network(token):
    try:
        if "/" in token:
            return ipaddress.ip_network(token, strict=False)
        return ipaddress.ip_network(token + ("/32" if ":" not in token else "/128"),
                                    strict=False)
    except ValueError:
        return None


def ip_in_networks(ip, networks):
    """Return the matching configured token for ip, or None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for token, net in networks:
        if addr.version == net.version and addr in net:
            return token
    return None


def fqdn_in_configured(fqdn, configured_fqdns):
    """Match an FQDN against configured domains. A configured 'example.com'
    covers 'example.com' and any subdomain (domain-suffix semantics)."""
    f = fqdn.lower().rstrip(".")
    for c in configured_fqdns:
        if f == c or f.endswith("." + c):
            return c
    return None


def parse_ports(spec):
    """Parse a port spec like '443, 8000-8090, 53' into a set of ports, or None
    if the text isn't a port spec (so it can be treated as an IP/FQDN instead)."""
    s = (spec or "").strip()
    if not s or any(ch not in "0123456789,- \t" for ch in s):
        return None
    ports = set()
    for tok in s.replace(" ", "").replace("\t", "").split(","):
        if not tok:
            continue
        if "-" in tok:
            a, _, b = tok.partition("-")
            if not (a.isdigit() and b.isdigit()):
                return None
            lo, hi = sorted((int(a), int(b)))
            if hi - lo > 65535:
                return None
            ports.update(range(lo, hi + 1))
        elif tok.isdigit():
            ports.add(int(tok))
        else:
            return None
    return {p for p in ports if 0 <= p <= 65535} or None


def parse_focus(subnets_str, fqdns_str):
    """Parse comma/space-separated subnet and FQDN focus lists into
    (networks, fqdns)."""
    networks, fqdns = [], set()
    for tok in (subnets_str or "").replace(",", " ").split():
        net = _as_network(tok)
        if net is not None:
            networks.append((tok, net))
    for tok in (fqdns_str or "").replace(",", " ").split():
        fqdns.add(tok.lower().strip(".").lstrip("*").lstrip("."))
    return networks, fqdns


def focus_desc(networks, fqdns):
    if not (networks or fqdns):
        return None
    bits = []
    if networks:
        bits.append("%d subnet(s)" % len(networks))
    if fqdns:
        bits.append("%d FQDN(s)" % len(fqdns))
    sep = " AND " if (networks and fqdns) else " + "
    return sep.join(bits) + " (restrict)"


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------


def reverse_dns_lookup(ips, budget=8.0, workers=32):
    """PTR-resolve a set of IPs concurrently. Returns {ip: hostname} for those
    that resolve within the overall time budget; the rest are left out."""
    ips = list(ips)
    out = {}
    if not ips:
        return out

    def one(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            return ip, None

    ex = ThreadPoolExecutor(max_workers=min(workers, len(ips)))
    futs = [ex.submit(one, ip) for ip in ips]
    try:
        for fut in as_completed(futs, timeout=budget):
            ip, host = fut.result()
            if host:
                out[ip] = host
    except TimeoutError:
        pass                                    # keep whatever resolved in time
    ex.shutdown(wait=False)
    return out


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class CaptureStats:
    def __init__(self):
        self.packets = 0
        self.ip_packets = 0
        self.wg_packets = 0
        self.first_ts = None
        self.last_ts = None

    def stamp(self, ts):
        if ts:
            self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
            self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)


def _record_event(d, label, frame, kind):
    """Note a notable frame (RST, fatal alert) for a destination, bounded."""
    if len(d["events"]) < 12:
        d["events"].append((label, frame, kind))


def _cap_frame(per_file, label, frame, cap=6):
    """Append a frame # to a {file: [frame, ...]} map, bounded per file."""
    frames = per_file.setdefault(label, [])
    if len(frames) < cap:
        frames.append(frame)


def _add_stage_frame(d, stage, label, frame):
    """Record the frame # (per file) where a given flow stage was seen."""
    _cap_frame(d["stage_frames"].setdefault(stage, {}), label, frame)


TL_CAP = 250                                    # max timeline events kept per dest


def _tl(d, ts, label, frame, kind, detail):
    """Append a timestamped event to a destination's timeline (bounded), while
    always tracking the total count and the most recent event."""
    d["tl_count"] += 1
    d["tl_last"] = (ts, label, frame, kind, detail)
    if len(d["timeline"]) < TL_CAP:
        d["timeline"].append((ts, label, frame, kind, detail))


def _dest_factory():
    return {"count": 0, "names": set(), "tls": set(),
            "syn": 0, "synack": 0, "rst": 0, "data": 0,
            "tls_ch": 0, "tls_sh": 0, "alerts": set(),
            "retx": 0, "clients": set(), "files": set(),
            "c2s_bytes": 0, "s2c_bytes": 0, "mss": None,
            "c2s_pkts": 0, "s2c_pkts": 0,         # per-direction packet counts
            "c2s_frames": {}, "s2c_frames": {},   # per-direction file -> [frame #]
            "stage_frames": {},                   # stage -> {file: [frame #]}
            "first_frame": {}, "events": [],       # file -> first frame #; (file,#,kind)
            "timeline": [], "tl_count": 0, "tl_last": None,
            "first_ts": None, "last_ts": None}


class Analyzer:
    """Builds a per-destination network-health picture from both captures
    (user-tunnel and connector) and correlates them to localize problems."""

    # infra ports we don't treat as application destinations
    SKIP_PORTS = {67, 68, 123, 137, 138, 1900, 5355}

    def __init__(self, source_filter=None):
        self.source_filter = source_filter
        self.ip2names = defaultdict(set)        # ip -> {fqdn, ...}
        self.cname_map = defaultdict(set)       # alias -> {target name}
        # per-side destination health: side -> {(proto, server_ip, sport): rec}
        self.dest = {"user": defaultdict(_dest_factory),
                     "conn": defaultdict(_dest_factory)}
        self.streams = {}                       # (file,proto,cip,cport,sip,sport) -> rec
        self._seq = {}                          # (side,src,sport,dst,dport)->nextseq
        self.client_reach = {"user": defaultdict(set), "conn": defaultdict(set)}
        self.client_pkts = {"user": Counter(), "conn": Counter()}
        self.icmp_by_ep = defaultdict(Counter)  # (l4,server_ip,server_port) -> {label:n}
        self.icmp_by_conn = defaultdict(Counter)  # (l4,cip,cport,sip,sport) -> {label:n}
        self.icmp_files = defaultdict(set)      # failed-dest ip -> {file, ...}
        self.icmp_frames = defaultdict(dict)    # ip -> {file: [frame #]}
        self.frag_by_ip = Counter()             # dst ip -> fragmented-packet count
        self.frag_files = defaultdict(set)
        self.frag_frames = defaultdict(dict)    # ip -> {file: [frame #]}
        self.ip_timeline = defaultdict(list)    # ip -> [(ts,file,frame,kind,detail)]
                                                #   for events with no L4 dest (ICMP, frags)
        self.retrans_total = 0
        # DNS
        self.dns_total = 0
        self.dns_pending = {}                   # (side,id,qname)->(qname,file,resolver)
        self.dns_failures = Counter()           # (qname, reason) -> n
        self.dns_failure_files = defaultdict(set)
        self.dns_failure_resolvers = defaultdict(set)
        self.dns_failure_frames = {}            # (qname,reason) -> (file, frame)
        self.dns_query_src = Counter()          # endpoint-side query source -> n (host hint)
        self.dns_q_info = {}                    # lqname -> (file, frame) of the query
        self.dns_ok = {}                        # lqname -> (ips, file, frame, resolver)
        self.dns_timeline = defaultdict(list)   # lqname -> [(ts, file, frame, kind, detail)]
        # capture stats
        self.captures = []                      # [{label, side, stats}]
        self.user_stats = CaptureStats()
        self.conn_stats = CaptureStats()
        self.host_ip = None

    # -- intake --------------------------------------------------------------

    def feed_user(self, path):
        self._feed(path, "user", self.user_stats)

    def feed_connector(self, path):
        self._feed(path, "conn", self.conn_stats)

    def _feed(self, path, side, agg):
        dest = self.dest[side]
        label = os.path.basename(path)
        stats = CaptureStats()                  # per-file stats for the header
        self.captures.append({"label": label, "side": side, "stats": stats})
        for ts, linktype, data in iter_packets(path):
            stats.packets += 1
            agg.packets += 1
            frame = stats.packets                       # 1-based frame # in this file
            ipdata = link_to_ip(linktype, data)
            if ipdata is None:
                continue
            decoded = decode_ip(ipdata)
            if decoded is None:
                continue
            stats.ip_packets += 1
            agg.ip_packets += 1
            stats.stamp(ts)
            agg.stamp(ts)
            src, dst, proto, l4 = decoded

            is_frag, is_cont = ipv4_fragment(ipdata)
            if is_frag:
                self.frag_by_ip[dst] += 1
                self.frag_files[dst].add(label)
                _cap_frame(self.frag_frames[dst], label, frame)
                self._ip_event(dst, ts, label, frame, "IP fragment",
                               "continuation" if is_cont else "first (MF set)")
                if is_cont:
                    continue                            # no L4 header in this fragment

            if proto in (1, 58):                        # ICMP / ICMPv6 errors
                lbl = parse_icmp_error(proto, l4)
                if lbl:
                    quoted = icmp_embedded_tuple(proto, l4)
                    if quoted:
                        l4p, qsip, qsp, qdip, qdp = quoted   # original was client→server
                        # attribute to the exact connection AND its server endpoint,
                        # NOT every stream sharing the server IP
                        self.icmp_by_ep[(l4p, qdip, qdp)][lbl] += 1
                        self.icmp_by_conn[(l4p, qsip, qsp, qdip, qdp)][lbl] += 1
                        tgt = qdip
                        detail = lbl + ((" → :%d" % qdp) if qdp else "")
                    else:
                        tgt = dst                       # couldn't parse the quote
                        detail = lbl
                    self.icmp_files[tgt].add(label)
                    _cap_frame(self.icmp_frames[tgt], label, frame)
                    self._ip_event(tgt, ts, label, frame, "ICMP", detail)
                continue

            l4d = decode_l4(proto, l4)
            if l4d is None:
                continue
            sport, dport, app, seq, flags = l4d

            if proto == 17 and (sport == 53 or dport == 53):
                self._dns(side, app, label, src, dst, frame, ts)
                continue

            if proto == 17 and looks_encapsulated(app):
                stats.wg_packets += 1
                agg.wg_packets += 1
                continue
            if dport in self.SKIP_PORTS or sport in self.SKIP_PORTS:
                continue

            server_ip, server_port, client_ip, client_port = self._orient(
                src, sport, dst, dport, proto, flags)
            self.client_reach[side][client_ip].add(server_ip)
            self.client_pkts[side][client_ip] += 1

            # Update both the per-destination aggregate AND the individual
            # stream (one TCP/UDP connection = a unique 4-tuple, per file).
            d = dest[(proto, server_ip, server_port)]
            skey = (label, proto, client_ip, client_port, server_ip, server_port)
            sd = self.streams.get(skey)
            if sd is None:
                sd = self.streams[skey] = _dest_factory()
                sd["_meta"] = (side, proto, client_ip, client_port,
                               server_ip, server_port)
            recs = (d, sd)

            direction = "c2s" if src == client_ip else "s2c"
            dlabel = "user → server" if direction == "c2s" else "server → user"
            for r in recs:
                r["count"] += 1
                r["clients"].add(client_ip)
                r["files"].add(label)
                if label not in r["first_frame"]:
                    r["first_frame"][label] = frame
                r[direction + "_pkts"] += 1
                fl = r[direction + "_frames"].setdefault(label, [])
                if len(fl) < 8:
                    fl.append(frame)
                if app:
                    r[direction + "_bytes"] += len(app)
                if r["first_ts"] is None:
                    r["first_ts"] = ts
                r["last_ts"] = ts

            if proto != 6:
                if app:
                    for r in recs:
                        _tl(r, ts, label, frame, "data", "%s %dB" % (dlabel, len(app)))
                continue

            # ---- TCP health (applied to the aggregate and the stream) ----
            if flags & TCP_SYN:
                stg = "synack" if flags & TCP_ACK else "syn"
                mss = parse_tcp_mss(l4)             # MSS rides on SYN / SYN-ACK
                for r in recs:
                    r[stg] += 1
                    _add_stage_frame(r, stg, label, frame)
                    _tl(r, ts, label, frame, "SYN-ACK" if flags & TCP_ACK else "SYN",
                        dlabel)
                    if mss is not None:
                        r["mss"] = mss if r["mss"] is None else min(r["mss"], mss)
            if flags & TCP_FIN:
                for r in recs:
                    _tl(r, ts, label, frame, "FIN", dlabel)
            if flags & TCP_RST:
                for r in recs:
                    r["rst"] += 1
                    _add_stage_frame(r, "rst", label, frame)
                    _record_event(r, label, frame, "RST")
                    _tl(r, ts, label, frame, "RST", dlabel)
            if app:
                # retransmit detection is per directional flow (computed once)
                end = (seq + len(app)) & 0xFFFFFFFF
                sk = (side, src, sport, dst, dport)
                ns = self._seq.get(sk)
                keep_alive = (ns is not None and len(app) <= 1
                              and seq == (ns - 1) & 0xFFFFFFFF)
                is_retx = False
                if keep_alive:
                    pass
                elif ns is not None and seq < ns:       # genuinely already-seen data
                    self.retrans_total += 1
                    is_retx = True
                else:
                    self._seq[sk] = end if ns is None else max(ns, end)
                is_ch, is_sh, al = tls_scan(app)
                sni = ver = None
                if is_ch:
                    sni, ver = parse_client_hello(app)
                    if sni:
                        self.ip2names[server_ip].add(sni)
                for r in recs:
                    r["data"] += 1
                    _add_stage_frame(r, "data_" + direction, label, frame)
                    if is_retx:
                        r["retx"] += 1
                        _add_stage_frame(r, "retx", label, frame)
                    if is_ch:
                        r["tls_ch"] += 1
                        _add_stage_frame(r, "clienthello", label, frame)
                        if sni:
                            r["names"].add(sni)
                        if ver:
                            r["tls"].add(ver)
                    elif is_sh:
                        r["tls_sh"] += 1
                        _add_stage_frame(r, "serverhello", label, frame)
                    if al:
                        r["alerts"].add(al)
                        if al[0] == "fatal":
                            _add_stage_frame(r, "alert", label, frame)
                            _record_event(r, label, frame, "alert:%s" % al[1])
                    if keep_alive:
                        _tl(r, ts, label, frame, "keep-alive", dlabel)
                    elif is_retx:
                        _tl(r, ts, label, frame, "retransmit",
                            "%s %dB" % (dlabel, len(app)))
                    elif is_ch:
                        _tl(r, ts, label, frame, "TLS ClientHello", sni or dlabel)
                    elif is_sh:
                        _tl(r, ts, label, frame, "TLS ServerHello", dlabel)
                    elif al:
                        _tl(r, ts, label, frame, "TLS alert",
                            "%s (%s)" % (al[1], al[0]))
                    else:
                        _tl(r, ts, label, frame, "data", "%s %dB" % (dlabel, len(app)))

    @staticmethod
    def _orient(src, sport, dst, dport, proto, flags):
        """Decide which endpoint is the server, returning
        (server_ip, server_port, client_ip, client_port). SYN tells us directly;
        otherwise the lower (more well-known) port is treated as the service."""
        if proto == 6 and (flags & TCP_SYN):
            if flags & TCP_ACK:                         # SYN-ACK → src is server
                return src, sport, dst, dport
            return dst, dport, src, sport               # SYN → dst is server
        if dport <= sport:
            return dst, dport, src, sport
        return src, sport, dst, dport

    def _ip_event(self, ip, ts, label, frame, kind, detail, cap=100):
        """Record a per-IP timeline event for things with no L4 dest of their
        own (ICMP errors, IP fragments) so they still show in the timeline."""
        tl = self.ip_timeline[ip]
        if len(tl) < cap:
            tl.append((ts, label, frame, kind, detail))

    def _dns(self, side, payload, label, src, dst, frame, ts):
        msg = parse_dns(payload)
        if msg is None:
            return
        qname = (msg["qname"] or "").strip(".")
        lname = qname.lower()
        if not msg["is_response"]:
            self.dns_total += 1
            if side == "user":                          # the asker is the host
                self.dns_query_src[src] += 1
            if qname:                                   # resolver = where we asked
                self.dns_pending[(side, msg["id"], lname)] = (qname, label, dst, frame)
                self.dns_q_info.setdefault(lname, (label, frame))
                self.dns_timeline[lname].append(
                    (ts, label, frame, "DNS query", "%s → %s" % (qname, dst)))
            return
        self.dns_pending.pop((side, msg["id"], lname), None)
        if msg["rcode"] in (2, 3, 5) and qname:         # SERVFAIL/NXDOMAIN/REFUSED
            key = (qname, DNS_RCODES.get(msg["rcode"]))
            self.dns_failures[key] += 1
            self.dns_failure_files[key].add(label)
            self.dns_failure_resolvers[key].add(src)    # resolver = who answered
            self.dns_failure_frames.setdefault(key, (label, frame))
            self.dns_timeline[lname].append(
                (ts, label, frame, "DNS " + DNS_RCODES.get(msg["rcode"], "error"),
                 "from %s" % src))
        ips = [v for _n, v in msg["answers"] if not v.startswith("cname:")]
        if qname and ips:                               # resolved to an address
            self.dns_ok.setdefault(lname, (ips, label, frame, src))
            self.dns_timeline[lname].append(
                (ts, label, frame, "DNS resolved", "→ %s" % ", ".join(ips)))
        for name, value in msg["answers"]:
            if value.startswith("cname:"):
                self.cname_map[value[6:]].add(name)
            else:
                self.ip2names[value].add(name)

    # -- naming / host -------------------------------------------------------

    def names_for(self, ip, extra):
        names = set(extra) | set(self.ip2names.get(ip, ()))
        for n in list(names):
            names |= self.cname_map.get(n, set())
        return names

    def detect_host(self):
        """Auto-detect the endpoint/user IP. Strongest signal is who issues DNS
        queries (only the host does that); otherwise fall back to whoever
        initiates the most distinct connections."""
        if self.source_filter:
            self.host_ip = self.source_filter
            return self.host_ip
        reach, pkts = self.client_reach["user"], self.client_pkts["user"]
        dnsq = self.dns_query_src
        candidates = set(reach) | set(dnsq)
        if not candidates:
            self.host_ip = None
            return None

        def score(ip):
            return (dnsq.get(ip, 0) > 0,        # made DNS queries → almost certainly the host
                    len(reach.get(ip, ())),     # reached the most distinct destinations
                    dnsq.get(ip, 0),            # number of queries
                    pkts.get(ip, 0))            # raw packet count

        self.host_ip = max(candidates, key=score)
        return self.host_ip

    def host_candidates(self, limit=4):
        reach = self.client_reach["user"]
        scored = {ip: len(d) for ip, d in reach.items()}
        for ip in self.dns_query_src:                   # DNS askers are host-like too
            scored[ip] = max(scored.get(ip, 0), 1)
        out = [(ip, n) for ip, n in scored.items()
               if ip != self.host_ip and (n >= 2 or ip in self.dns_query_src)]
        out.sort(key=lambda x: -x[1])
        return out[:limit]

    def dns_issue_list(self):
        """All DNS problems: bad rcodes plus queries that got no response.
        Returns (qname, reason, count, files, resolvers, frame) tuples where
        frame is (file, frame_no) or None."""
        issues = Counter(self.dns_failures)
        files = {k: set(v) for k, v in self.dns_failure_files.items()}
        resolvers = {k: set(v) for k, v in self.dns_failure_resolvers.items()}
        frames = dict(self.dns_failure_frames)
        for (qname, label, resolver, frame) in self.dns_pending.values():
            k = (qname, "no response")
            issues[k] += 1
            files.setdefault(k, set()).add(label)
            if resolver:
                resolvers.setdefault(k, set()).add(resolver)
            frames.setdefault(k, (label, frame))
        return sorted(((q, r, n, sorted(files.get((q, r), ())),
                        sorted(resolvers.get((q, r), ())), frames.get((q, r)))
                       for (q, r), n in issues.items()),
                      key=lambda x: (-x[2], x[0]))

    # -- findings ------------------------------------------------------------

    def build_findings(self, subnets=None, focus_fqdns=None, host_only=False):
        """Correlate both sides into per-destination findings with health status
        and the specific issues found. Returns (findings, filtered_out,
        host_hidden)."""
        self.detect_host()
        keys = set(self.dest["user"]) | set(self.dest["conn"])
        # destinations that only ever appeared via an ICMP error
        for (l4p, sip, sport) in self.icmp_by_ep:
            if sip and (l4p, sip, sport or 0) not in keys:
                keys.add((l4p, sip, sport or 0))

        findings = []
        for (proto, sip, sport) in keys:
            u = self.dest["user"].get((proto, sip, sport))
            k = self.dest["conn"].get((proto, sip, sport))
            f = self._finding(proto, sip, sport, u, k)
            findings.append(f)

        # host scoping: keep only transactions the detected host took part in.
        # (Findings merge both captures by destination, so a destination the
        # host hit on the endpoint side keeps its connector-side health too —
        # only other clients' / infra destinations are dropped.)
        host_hidden = 0
        if host_only and self.host_ip:
            scoped = [f for f in findings if self.host_ip in f["clients"]]
            if scoped:                              # fall back if host not seen at all
                host_hidden = len(findings) - len(scoped)
                findings = scoped

        # focus filter (restrict-with-summary)
        filtered_out = 0
        if subnets or focus_fqdns:
            kept = []
            for f in findings:
                if self._in_focus(f, subnets, focus_fqdns):
                    kept.append(f)
                else:
                    filtered_out += 1
            findings = kept

        sev_rank = {"fail": 0, "warn": 1, "ok": 2}
        findings.sort(key=lambda f: (sev_rank[f["severity"]], -f["count"],
                                     f["ip"], f["port"]))
        return findings, filtered_out, host_hidden

    def _finding(self, proto, sip, sport, u, k, correlate=True, icmp_labels=None):
        names = self.names_for(sip, (u["names"] if u else set())
                               | (k["names"] if k else set()))
        tls = sorted((u["tls"] if u else set()) | (k["tls"] if k else set()))
        syn = (u["syn"] if u else 0) + (k["syn"] if k else 0)
        synack = (u["synack"] if u else 0) + (k["synack"] if k else 0)
        rst = (u["rst"] if u else 0) + (k["rst"] if k else 0)
        data = (u["data"] if u else 0) + (k["data"] if k else 0)
        tls_ch = (u["tls_ch"] if u else 0) + (k["tls_ch"] if k else 0)
        tls_sh = (u["tls_sh"] if u else 0) + (k["tls_sh"] if k else 0)
        retx = (u["retx"] if u else 0) + (k["retx"] if k else 0)
        alerts = (u["alerts"] if u else set()) | (k["alerts"] if k else set())
        # ICMP attributed to this exact server endpoint (or this stream, when
        # streams_for passes an explicit per-connection map) — not the whole IP
        icmp = dict(icmp_labels if icmp_labels is not None
                    else self.icmp_by_ep.get((proto, sip, sport), {}))
        count = (u["count"] if u else 0) + (k["count"] if k else 0)
        files = sorted((u["files"] if u else set()) | (k["files"] if k else set())
                       | self.icmp_files.get(sip, set()) | self.frag_files.get(sip, set()))
        c2s = (u["c2s_bytes"] if u else 0) + (k["c2s_bytes"] if k else 0)
        s2c = (u["s2c_bytes"] if u else 0) + (k["s2c_bytes"] if k else 0)
        c2s_pkts = (u["c2s_pkts"] if u else 0) + (k["c2s_pkts"] if k else 0)
        s2c_pkts = (u["s2c_pkts"] if u else 0) + (k["s2c_pkts"] if k else 0)

        def _merge_frames(key):
            out = {}
            for rec in (u, k):
                for lbl, frs in (rec[key] if rec else {}).items():
                    out.setdefault(lbl, []).extend(frs)
            return {lbl: sorted(set(v))[:8] for lbl, v in out.items()}
        c2s_frames = _merge_frames("c2s_frames")
        s2c_frames = _merge_frames("s2c_frames")
        stage_frames = {}
        for rec in (u, k):
            for stg, per_file in (rec["stage_frames"] if rec else {}).items():
                dst_m = stage_frames.setdefault(stg, {})
                for lbl, frs in per_file.items():
                    dst_m.setdefault(lbl, []).extend(frs)
        stage_frames = {stg: {lbl: sorted(set(v))[:6] for lbl, v in m.items()}
                        for stg, m in stage_frames.items()}
        if self.frag_frames.get(sip):                   # IP-level (per-dest) frames
            stage_frames["frag"] = {l: sorted(set(v))[:6]
                                    for l, v in self.frag_frames[sip].items()}
        if self.icmp_frames.get(sip):
            stage_frames["icmp"] = {l: sorted(set(v))[:6]
                                    for l, v in self.icmp_frames[sip].items()}
        msses = [m for m in ((u or {}).get("mss"), (k or {}).get("mss")) if m]
        mss = min(msses) if msses else None
        frag = self.frag_by_ip.get(sip, 0)
        clients = (u["clients"] if u else set()) | (k["clients"] if k else set())
        first_frame = {}
        for rec in (u, k):
            for lbl, fr in (rec["first_frame"] if rec else {}).items():
                first_frame[lbl] = min(fr, first_frame.get(lbl, fr))
        events = (u["events"] if u else []) + (k["events"] if k else [])
        user_seen, conn_seen = u is not None, k is not None
        handshake_ok = bool(synack and not rst)

        issues = []                                     # (text, severity)
        # correlation: reached the tunnel but never showed at the connector
        if (correlate and user_seen and not conn_seen and self.conn_stats.packets
                and proto == 6 and syn):
            issues.append(("left the tunnel but never reached the connector", "fail"))
        if proto == 6 and syn and not synack and not rst:
            issues.append(("no SYN-ACK — server not responding / blocked", "fail"))
        if rst:
            if not synack:                              # SYN answered by RST = refused
                issues.append(("connection refused — RST instead of SYN-ACK (x%d)"
                               % rst, "fail"))
            elif data == 0:                             # handshake then RST, no data
                issues.append(("reset after handshake, no data transferred (RST "
                               "x%d)" % rst, "warn"))
            # RST after data flowed is usually a normal teardown — not flagged
        for level, desc in sorted(alerts):
            issues.append(("TLS alert: %s (%s)" % (desc, level),
                           "fail" if level == "fatal" else "warn"))
        if proto == 6 and tls_ch and not tls_sh and synack:
            issues.append(("TLS ClientHello sent, no ServerHello seen", "warn"))
        # return-route asymmetry: client sent data, server never sent any back
        if proto == 6 and handshake_ok and c2s > 0 and s2c == 0:
            issues.append(("data sent but none returned — possible return-route "
                           "asymmetry (server→client)", "warn"))
        # established but no payload moved either way
        if proto == 6 and handshake_ok and data == 0:
            issues.append(("connection established but no payload — path up, "
                           "issue likely above this layer", "warn"))
        # ICMP is a delivery failure for SOME packet to this endpoint, but if the
        # connection still established and moved data it clearly worked → warn.
        icmp_sev = "warn" if (synack and data) else "fail"
        for label, n in icmp.items():
            issues.append(("%s x%d" % (label, n), icmp_sev))
        if frag:
            issues.append(("IP fragmentation (%d pkts) — possible MTU/path issue"
                           % frag, "warn"))
        if mss is not None and mss < 1280:
            issues.append(("small TCP MSS %d — tight path MTU" % mss, "warn"))
        if retx:
            issues.append(("%d TCP retransmission(s)" % retx, "warn"))

        # established = handshake completed and data moved (a later RST close is
        # a normal teardown, not a failed connection)
        established = proto == 6 and synack and data
        if any(s == "fail" for _t, s in issues):
            severity = "fail"
        elif issues:
            severity = "warn"
        else:
            severity = "ok"

        return {
            "proto": "tcp" if proto == 6 else "udp" if proto == 17 else str(proto),
            "ip": sip, "port": sport,
            "names": sorted(names), "ptr_name": None,
            "tls": tls, "count": count,
            "syn": syn, "synack": synack, "rst": rst, "retx": retx,
            "tls_ch": tls_ch, "tls_sh": tls_sh,
            "c2s_bytes": c2s, "s2c_bytes": s2c, "mss": mss, "frag": frag,
            "c2s_pkts": c2s_pkts, "s2c_pkts": s2c_pkts,
            "c2s_frames": c2s_frames, "s2c_frames": s2c_frames,
            "stage_frames": stage_frames,
            "user_seen": user_seen, "conn_seen": conn_seen,
            "established": bool(established),
            "issues": issues, "severity": severity, "files": files,
            "clients": sorted(clients), "first_frame": first_frame, "events": events,
        }

    def streams_for(self, f):
        """Per-connection (TCP/UDP stream) findings for one destination endpoint.
        Includes every stream to that server:port; the host's own streams are
        flagged and sorted first (connector-side NAT'd streams have a different
        client IP and are marked 'other client')."""
        pn = {"tcp": 6, "udp": 17}.get(f["proto"])
        if pn is None:
            return []
        out = []
        for (lbl, proto, cip, cport, sip, sport), sd in self.streams.items():
            if proto != pn or sip != f["ip"] or sport != f["port"]:
                continue
            side = sd["_meta"][0]
            conn_icmp = self.icmp_by_conn.get((proto, cip, cport, sip, sport), {})
            sf = self._finding(proto, sip, sport,
                               sd if side == "user" else None,
                               sd if side == "conn" else None,
                               correlate=False, icmp_labels=conn_icmp)
            sf["client"] = (cip, cport)
            sf["file"] = lbl
            sf["first_ts"] = sd["first_ts"]
            sf["is_host"] = (cip == self.host_ip)
            out.append(sf)
        out.sort(key=lambda x: (not x["is_host"], x["first_ts"] or 0, x["client"][1]))
        return out

    @staticmethod
    def _in_focus(f, subnets, focus_fqdns):
        # AND: when both lists are given a destination must satisfy BOTH.
        if subnets and not ip_in_networks(f["ip"], subnets):
            return False
        if focus_fqdns and not any(fqdn_in_configured(n, focus_fqdns)
                                   for n in f["names"]):
            return False
        return True

    def resolve_ptr(self, findings, budget=8.0):
        """Reverse-DNS (PTR) the destinations that have no SNI/DNS name yet."""
        need = sorted({f["ip"] for f in findings if not f["names"] and f["ip"]})
        if not need:
            return
        ptr = reverse_dns_lookup(need, budget=budget)
        for f in findings:
            if not f["names"] and f["ip"] in ptr:
                f["ptr_name"] = ptr[f["ip"]]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _fmt_ts(ts):
    if not ts:
        return "n/a"
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_clock(ts):
    import datetime
    dt = datetime.datetime.fromtimestamp(ts)
    return dt.strftime("%H:%M:%S.") + "%03d" % (dt.microsecond // 1000)


def _target_label(t):
    if t["names"]:
        primary = t["names"][0]
        extra = "  (+%d more)" % (len(t["names"]) - 1) if len(t["names"]) > 1 else ""
        return "%s  [%s]%s" % (primary, t["ip"], extra)
    if t.get("ptr_name"):
        return "%s  [%s] (ptr)" % (t["ptr_name"], t["ip"])
    return t["ip"]


def _sev_mark(sev, c):
    return {"fail": c.wrap("✗", c.red), "warn": c.wrap("!", c.yellow),
            "ok": c.wrap("✓", c.green)}[sev]


def _where(f):
    # which capture(s) observed this flow — NOT a network path
    if f["user_seen"] and f["conn_seen"]:
        return "seen in: tunnel + connector captures"
    if f["user_seen"]:
        return "seen in: tunnel capture only"
    if f["conn_seen"]:
        return "seen in: connector capture only"
    return "seen in: ICMP error only"


def _dst(f):
    return "%-9s %s" % (f["proto"] + "/" + str(f["port"]), _target_label(f))


def _frames_str(f):
    """Per-file frame numbers for triangulation: 'host.pcap #5 · conn.pcap #12
    (RST #18)'. Frame numbers match Wireshark's frame.number for that file."""
    ev_by_file = {}
    for lbl, fr, kind in f.get("events", []):
        ev_by_file.setdefault(lbl, []).append((fr, kind))
    parts = []
    for lbl in f["files"]:
        seg = lbl
        ff = f.get("first_frame", {}).get(lbl)
        if ff is not None:
            seg += " #%d" % ff
        evs = ev_by_file.get(lbl)
        if evs:
            seg += " (" + ", ".join("%s #%d" % (k, fr) for fr, k in sorted(evs)) + ")"
        parts.append(seg)
    return " · ".join(parts)


# Plain-English guide to each check: (name, what-pass-means, what-fail-means,
# wireshark filter). pass/fail may be None when only one side is meaningful.
CHECK_GUIDE = [
    ("DNS — finding the server's address", [
        ("DNS query",
         "your machine asked a DNS server for the site's IP address", None,
         "dns.flags.response == 0"),
        ("DNS resolved",
         "the name was found and turned into an IP — name lookup worked",
         "name lookup failed, so the app can't even find its server. "
         "NXDOMAIN = name doesn't exist; SERVFAIL = resolver error; "
         "no response = the DNS server never answered / was unreachable",
         "dns.flags.response == 1     (failures: dns.flags.rcode != 0)"),
    ]),
    ("TCP — opening the connection", [
        ("TCP SYN",
         "your machine asked to open a connection to the server (step 1 of 3)",
         None, "tcp.flags.syn == 1 && tcp.flags.ack == 0"),
        ("TCP SYN-ACK",
         "the server answered — it is reachable and listening on that port",
         "no answer from the server: a firewall is dropping it, the server is "
         "down, the port is wrong, or there's no route. The connection never opens.",
         "tcp.flags.syn == 1 && tcp.flags.ack == 1"),
        ("TCP RST (reset)", None,
         "the connection was forcibly closed: the server refused it (port "
         "closed / app rejected) or a firewall/device killed it",
         "tcp.flags.reset == 1"),
    ]),
    ("TLS — setting up encryption", [
        ("TLS ClientHello",
         "your machine started the encrypted handshake and named the site it "
         "wants (SNI)", None, "tls.handshake.type == 1"),
        ("TLS ServerHello",
         "the server agreed to encrypt and chose the cipher/version — TLS is "
         "proceeding",
         "the server didn't continue TLS: it reset, doesn't do TLS on that "
         "port, or rejected the certificate / SNI / policy",
         "tls.handshake.type == 2"),
        ("TLS alert", None,
         "an encryption error was sent and the session usually aborted — e.g. "
         "bad_certificate, unknown_ca, handshake_failure (a trust / cert / "
         "version / policy problem)",
         "tls.record.content_type == 21   (fatal: tls.alert.level == 2)"),
    ]),
    ("Data — the actual traffic", [
        ("user → server",
         "your machine sent application data (the request)", None,
         "tcp.len > 0 && ip.src == <host-ip>"),
        ("server → user",
         "the server sent data back (the response) — traffic flows both ways",
         "the server never sent anything back although the connection opened: "
         "a return-route / asymmetric-routing problem (no route back to the "
         "client) or the app simply didn't respond",
         "tcp.len > 0 && ip.src == <server-ip>"),
    ]),
    ("Path problems", [
        ("TCP retransmission", None,
         "a segment had to be sent again because it wasn't acknowledged — "
         "packet loss or a slow/unstable path (a few is normal; many is a problem)",
         "tcp.analysis.retransmission   (keep-alives are NOT retransmits: "
         "tcp.analysis.keep_alive)"),
        ("IP fragmentation", None,
         "packets were split because they were bigger than the path allows "
         "(MTU) — common with tunnels; can hurt performance or be dropped if "
         "fragments are filtered",
         "ip.flags.mf == 1 || ip.frag_offset > 0"),
        ("small TCP MSS", None,
         "the connection agreed to small packets, usually from tunnel/MTU "
         "overhead — relevant to MTU issues, not necessarily a failure",
         "tcp.flags.syn == 1 && tcp.options.mss.val < 1380"),
        ("ICMP unreachable / time-exceeded", None,
         "a router or host reported it couldn't deliver the packet: "
         "destination/port unreachable (nothing listening / blocked) or TTL "
         "expired (routing loop)",
         "icmp.type == 3 || icmp.type == 11     (IPv6: icmpv6.type == 1)"),
        ("seen in tunnel only (not at connector)", None,
         "your traffic was in the endpoint/tunnel capture but never reached the "
         "connector capture — it didn't cross (steering / routing / tunnel), or "
         "the connector capture didn't cover it",
         "compare the two captures by destination IP"),
    ]),
]


def render_legend(c, host_ip=None):
    out = ["",
           c.wrap("  GUIDE — what each check means, and how to find it in Wireshark",
                  c.bold, c.cyan),
           c.wrap("  " + "─" * 60, c.grey)]
    for group, entries in CHECK_GUIDE:
        out.append("")
        out.append(c.wrap("  " + group, c.bold))
        for name, ok, fail, filt in entries:
            out.append("    " + c.wrap(name, c.bold))
            if ok:
                out.append("      %s pass : %s" % (c.wrap("✓", c.green), ok))
            if fail:
                out.append("      %s fail : %s" % (c.wrap("✗", c.red), fail))
            if host_ip:
                filt = filt.replace("<host-ip>", host_ip)
            out.append("      %s %s" % (c.wrap("🔎", c.cyan),
                                        c.wrap("wireshark: " + filt, c.cyan)))
    out.append("")
    return "\n".join(out)


def report(analyzer, findings, c, show_all, filtered_out=0, focus_desc=None,
           host_hidden=0):
    out = []
    add = out.append

    # ---- header ----
    add(c.wrap("\n  ZSCALER PRESENCE v%s — network health report" % VERSION,
               c.bold, c.cyan))
    add(c.wrap("  " + "─" * 60, c.grey))
    us = analyzer.user_stats
    add(c.wrap("  captures read:", c.bold)
        + c.wrap("   (tunnel = endpoint/user capture · connector = network "
                 "connector capture)", c.dim))
    for cap in analyzer.captures:
        st = cap["stats"]
        tag = "tunnel" if cap["side"] == "user" else "connector"
        add("    [%-9s] %-26s %s pkts (%s IP)  %s → %s" % (
            tag, cap["label"], st.packets, st.ip_packets,
            _fmt_ts(st.first_ts), _fmt_ts(st.last_ts)))
    origin = "from --source" if analyzer.source_filter else "auto-detected"
    add("  host machine IP     : %s  [%s]" % (analyzer.host_ip or "unknown", origin))
    others = analyzer.host_candidates()
    if others:
        add(c.wrap("  other local IPs     : %s" % ", ".join(
            "%s(%d dests)" % (ip, n) for ip, n in others), c.dim))
    if host_hidden:
        add(c.wrap("  scope               : host only — %d other destination(s) "
                   "hidden (--all-traffic to show)" % host_hidden, c.cyan))

    syn = sum(f["syn"] for f in findings)
    synack = sum(f["synack"] for f in findings)
    rst = sum(f["rst"] for f in findings)
    retx = sum(f["retx"] for f in findings)
    add("  tcp                 : SYN %d · SYN-ACK %d · %s · retransmits %s" % (
        syn, synack,
        c.wrap("RST %d" % rst, c.red if rst else c.grey),
        c.wrap(str(retx), c.yellow if retx else c.grey)))
    dns_issues = analyzer.dns_issue_list()
    add("  dns                 : %d queries · %s" % (
        analyzer.dns_total,
        c.wrap("%d failures" % len(dns_issues),
               c.red if dns_issues else c.grey)))
    if focus_desc:
        add(c.wrap("  focus               : %s" % focus_desc, c.cyan))

    if us.wg_packets and len(findings) <= 2 and not analyzer.source_filter:
        add("")
        add(c.wrap("  ⚠ The user capture looks like an opaque/encrypted tunnel "
                   "(%d encapsulated packets, %d inner destinations). Re-capture "
                   "on the interface carrying decrypted traffic."
                   % (us.wg_packets, len(findings)), c.yellow))

    poi = [f for f in findings if f["severity"] != "ok"]
    healthy = [f for f in findings if f["severity"] == "ok"]

    _section_poi(add, poi, c)
    _section_dns(add, dns_issues, c)
    _section_retx(add, findings, c)
    _section_healthy(add, healthy, c, show_all)
    _section_nonfindings(add, analyzer, c)

    if filtered_out:
        add("")
        add(c.wrap("  (focus filter hid %d destination(s) outside the given "
                   "subnets/FQDNs)" % filtered_out, c.dim))

    # ---- summary ----
    add("")
    add(c.wrap("  SUMMARY", c.bold))
    add(c.wrap("  " + "─" * 60, c.grey))
    fails = sum(1 for f in findings if f["severity"] == "fail")
    warns = sum(1 for f in findings if f["severity"] == "warn")
    add("  destinations %d   %s %d   %s %d   %s %d" % (
        len(findings),
        c.wrap("FAILING", c.red), fails,
        c.wrap("DEGRADED", c.yellow), warns,
        c.wrap("HEALTHY", c.green), len(healthy)))
    add("  dns failures %d   retransmits %d" % (len(dns_issues), retx))
    add("")
    print("\n".join(out))


def _finding_detail(add, f, c):
    """Full per-destination detail block used by the main report's POI section."""
    add("    %s %s   %s" % (_sev_mark(f["severity"], c), _dst(f),
                            c.wrap(_where(f), c.dim)))
    if f["issues"]:
        for text, sev in f["issues"]:
            col = c.red if sev == "fail" else c.yellow
            add("        %s %s" % (c.wrap("-", col), c.wrap(text, col)))
    elif f["established"]:
        add(c.wrap("        - established, no issues", c.green))
    add(c.wrap("        SYN %d / SYN-ACK %d / RST %d / retx %d · packets %d"
               % (f["syn"], f["synack"], f["rst"], f["retx"], f["count"]), c.dim))
    if f["proto"] == "tcp":
        extra = "        bytes c2s %d / s2c %d" % (f["c2s_bytes"], f["s2c_bytes"])
        if f.get("mss"):
            extra += " · MSS %d" % f["mss"]
        if f.get("frag"):
            extra += " · %d fragmented" % f["frag"]
        add(c.wrap(extra, c.dim))
    if f["files"]:
        add(c.wrap("        frames: %s" % _frames_str(f), c.dim))


def _section_poi(add, poi, c):
    add("")
    add(c.wrap("  ⚠ POINTS OF INTEREST — failing / degraded destinations",
               c.bold, c.red))
    add(c.wrap("  " + "─" * 60, c.grey))
    if not poi:
        add(c.wrap("    none — everything observed looks healthy. ✓", c.green))
        return
    for f in poi:
        _finding_detail(add, f, c)


def _section_dns(add, dns_issues, c):
    if not dns_issues:
        return
    add("")
    add(c.wrap("  ⚠ DNS ISSUES", c.bold, c.red))
    add(c.wrap("  " + "─" * 60, c.grey))
    for qname, reason, n, files, resolvers, frame in dns_issues[:40]:
        colour = c.yellow if reason == "no response" else c.red
        tail = (c.wrap("  ×%d" % n, c.dim) if n > 1 else "")
        if resolvers:
            tail += c.wrap("  via %s" % ", ".join(resolvers), c.dim)
        if frame:
            tail += c.wrap("  @ %s #%d" % (frame[0], frame[1]), c.dim)
        elif files:
            tail += c.wrap("  in: %s" % ", ".join(files), c.dim)
        add("    %s %-12s %s%s" % (c.wrap("•", colour), c.wrap(reason, colour),
                                   qname, tail))
    if len(dns_issues) > 40:
        add(c.wrap("    … and %d more" % (len(dns_issues) - 40), c.dim))


def _section_retx(add, findings, c):
    hot = sorted((f for f in findings if f["retx"]), key=lambda f: -f["retx"])
    if not hot:
        return
    add("")
    add(c.wrap("  ⚠ RETRANSMISSION HOTSPOTS", c.bold, c.yellow))
    add(c.wrap("  " + "─" * 60, c.grey))
    for f in hot[:20]:
        loc = c.wrap("  in: %s" % ", ".join(f["files"]), c.dim) if f["files"] else ""
        add("    %s %-6s %s%s" % (c.wrap("•", c.yellow),
                                  c.wrap("%d×" % f["retx"], c.yellow), _dst(f), loc))


def _section_healthy(add, healthy, c, show_all):
    add("")
    add(c.wrap("  ✓ HEALTHY — established, no issues", c.bold, c.green))
    add(c.wrap("  " + "─" * 60, c.grey))
    if not healthy:
        add(c.wrap("    none.", c.dim))
        return
    if not show_all:
        add(c.wrap("    %d destination(s) healthy. Use --show-all to list."
                   % len(healthy), c.dim))
        return
    for f in healthy:
        tls = ("  " + "/".join(f["tls"])) if f["tls"] else ""
        add("    %s %s%s" % (c.wrap("•", c.green), _dst(f), c.wrap(tls, c.dim)))


def _section_nonfindings(add, analyzer, c):
    """State plainly what this capture point cannot tell you, so the report
    doesn't imply coverage it doesn't have."""
    sides = {cap["side"] for cap in analyzer.captures}
    notes = [
        "policy / enablement / posture allow-deny decisions are control-plane "
        "and not present in packet data",
        "root cause of a non-response (firewall drop vs host down vs ACL) can't "
        "be distinguished from packets alone — only the symptom is visible",
        "whether a destination IP belongs to a given configured segment/subnet "
        "is a config question, not visible here (use --subnets to scope)",
    ]
    if analyzer.dns_total == 0:
        notes.append("no DNS traffic in these captures — name resolution "
                     "success/failure not assessed (names are from TLS SNI / PTR)")
    if "conn" not in sides:
        notes.append("no connector capture provided — can't confirm whether "
                     "traffic actually reached the connector / server side")
    elif "user" not in sides:
        notes.append("no endpoint capture provided — can't see what the client "
                     "originated before the connector")
    add("")
    add(c.wrap("  NOT OBSERVABLE FROM THIS CAPTURE", c.bold, c.grey))
    add(c.wrap("  " + "─" * 60, c.grey))
    for n in notes:
        add(c.wrap("    · " + n, c.dim))


def _dns_flow(analyzer, target, c):
    """DNS stage of the flow for an FQDN: was it queried? did it resolve?"""
    ok_mark, bad, skip = c.wrap("✓", c.green), c.wrap("✗", c.red), c.wrap("·", c.grey)
    ln = target.lower().strip(".")
    q = analyzer.dns_q_info.get(ln)
    ok = analyzer.dns_ok.get(ln)
    fails = [((qq, rr), analyzer.dns_failure_frames.get((qq, rr)),
              sorted(analyzer.dns_failure_resolvers.get((qq, rr), ())))
             for (qq, rr) in analyzer.dns_failures if qq.lower() == ln]
    pend = [v for v in analyzer.dns_pending.values() if v[0].lower() == ln]
    if not (q or ok or fails or pend):
        return []
    lines = ["    %s" % c.wrap("DNS  " + target, c.bold)]
    if q:
        lines.append("      %s query sent          %s"
                     % (ok_mark, c.wrap("@ %s #%d" % (q[0], q[1]), c.dim)))
    else:
        lines.append("      %s query not seen in capture" % skip)
    if ok:
        ips, lbl, fr, res = ok
        lines.append("      %s resolved → %s   %s" % (ok_mark, ", ".join(ips),
                     c.wrap("via %s  @ %s #%d" % (res, lbl, fr), c.dim)))
    elif fails:
        (_qq, rr), frame, res = fails[0]
        loc = "  @ %s #%d" % (frame[0], frame[1]) if frame else ""
        lines.append("      %s %s   %s" % (bad, c.wrap(rr, c.red),
                     c.wrap(("via %s" % ", ".join(res)) + loc, c.dim)))
    elif pend:
        _qn, lbl, res, fr = pend[0]
        lines.append("      %s no response   %s" % (bad,
                     c.wrap("via %s  @ %s #%d" % (res, lbl, fr), c.dim)))
    return lines


def _stage_frames_str(f, stage):
    """'host.pcap #3 · conn.pcap #1' for a given stage, or ''."""
    sf = f.get("stage_frames", {}).get(stage)
    if not sf:
        return ""
    return " · ".join("%s %s" % (lbl, ",".join("#%d" % n for n in sf[lbl]))
                      for lbl in sorted(sf))


def _drill_endpoint(add, f, c):
    """Stage-by-stage flow ladder for one endpoint of the drilled target.
    Each line carries its own file + frame #."""
    ok_mark, bad, skip = c.wrap("✓", c.green), c.wrap("✗", c.red), c.wrap("·", c.grey)

    def st(mark, name, stage, detail=""):
        loc = _stage_frames_str(f, stage)
        tail = detail
        if loc:
            tail = (detail + "   " if detail else "") + loc
        add("      %s %-16s %s" % (mark, name, c.wrap(tail, c.dim)))

    add("")
    add("    %s %s   %s" % (_sev_mark(f["severity"], c), _dst(f),
                            c.wrap(_where(f), c.dim)))
    if f["proto"] == "tcp":
        st(ok_mark if f["syn"] else skip, "TCP SYN", "syn")
        if f["synack"]:
            st(ok_mark, "TCP SYN-ACK", "synack")
        elif f["syn"]:
            st(bad, "TCP SYN-ACK", "synack", "no response from server")
        else:
            st(skip, "TCP SYN-ACK", "synack")
        if f["tls_ch"] or f["tls_sh"] or f["tls"]:
            st(ok_mark if f["tls_ch"] else skip, "TLS ClientHello", "clienthello",
               "/".join(f["tls"]))
            if f["tls_sh"]:
                st(ok_mark, "TLS ServerHello", "serverhello")
            else:
                alert = next((t for t, _s in f["issues"] if t.startswith("TLS alert")),
                             None)
                if alert:
                    st(bad, "TLS ServerHello", "alert", alert)
                elif f["tls_ch"]:
                    st(bad, "TLS ServerHello", "serverhello", "not seen")
                else:
                    st(skip, "TLS ServerHello", "serverhello")
        st(ok_mark if f["c2s_bytes"] else skip, "user → server", "data_c2s",
           ("%d bytes" % f["c2s_bytes"]) if f["c2s_bytes"] else "")
        if f["s2c_bytes"]:
            st(ok_mark, "server → user", "data_s2c", "%d bytes" % f["s2c_bytes"])
        elif f["c2s_bytes"]:
            st(bad, "server → user", "data_s2c", "none returned")
        else:
            st(skip, "server → user", "data_s2c")
        if f["rst"]:
            st(bad, "TCP RST", "rst", "connection reset")
    else:
        st(ok_mark if f["c2s_pkts"] else skip, "user → server", "data_c2s",
           "%d pkts, %d bytes" % (f["c2s_pkts"], f["c2s_bytes"]))
        st(ok_mark if f["s2c_pkts"] else (bad if f["c2s_pkts"] else skip),
           "server → user", "data_s2c",
           ("%d pkts, %d bytes" % (f["s2c_pkts"], f["s2c_bytes"]))
           if f["s2c_pkts"] else "none returned")

    # anomalies not represented by a stage line — with the frames where found
    note_stage = [("retransmission", "retx"), ("fragmentation", "frag"),
                  ("ICMP", "icmp"), ("MSS", "syn"), ("reach the connector", "syn")]
    for t, _s in f["issues"]:
        stg = next((s for kw, s in note_stage if kw in t), None)
        if stg is None:
            continue
        loc = _stage_frames_str(f, stg)
        line = c.wrap("        ! %s" % t, c.yellow)
        if loc:
            line += c.wrap("   " + loc, c.dim)
        add(line)

    res = {"fail": c.wrap("FAILED", c.red), "warn": c.wrap("DEGRADED", c.yellow),
           "ok": c.wrap("OK", c.green)}[f["severity"]]
    add("      ⇒ result: %s" % res)


def run_drilldown(analyzer, target, c):
    """Deep-dive on an IP/subnet, an FQDN, or a set of ports/port-ranges:
    a stage-by-stage flow of the host's transactions and where each broke."""
    ports = parse_ports(target)
    if ports is not None:                               # port search
        findings, _flt, _hid = analyzer.build_findings(host_only=True)
        findings = [f for f in findings if f["port"] in ports]
        _sort_findings(findings)
        _emit_drill(analyzer, c, "port(s) %s" % target, findings, None)
        return
    net = _as_network(target)
    if net is not None:
        findings, _flt, _hid = analyzer.build_findings([(target, net)], set(),
                                                       host_only=True)
        _emit_drill(analyzer, c, target, findings, None)
    else:
        fq = {target.lower().strip(".").lstrip("*").lstrip(".")}
        findings, _flt, _hid = analyzer.build_findings([], fq, host_only=True)
        _emit_drill(analyzer, c, target, findings, fq)


def _sort_findings(findings):
    rank = {"fail": 0, "warn": 1, "ok": 2}
    findings.sort(key=lambda f: (rank[f["severity"]], -f["count"], f["ip"], f["port"]))


def _emit_drill(analyzer, c, label, findings, dns_names):
    out = []
    add = out.append
    host = analyzer.host_ip or "host"
    dns_lines = []
    for nm in (dns_names or ()):
        dns_lines += _dns_flow(analyzer, nm, c)

    add(c.wrap("\n  ▼ DRILL-DOWN: %s   (source %s)" % (label, host), c.bold, c.cyan))
    add(c.wrap("  " + "─" * 60, c.grey))
    if not findings and not dns_lines:
        add(c.wrap("    no host traffic matching %s in these captures." % label, c.dim))
        add("")
        print("\n".join(out))
        return

    if findings:
        est = sum(1 for f in findings if f["established"])
        fails = sum(1 for f in findings if f["severity"] == "fail")
        warns = sum(1 for f in findings if f["severity"] == "warn")
        add("  %d endpoint(s) · %s established · %s failing · %s degraded" % (
            len(findings), c.wrap(str(est), c.green),
            c.wrap(str(fails), c.red), c.wrap(str(warns), c.yellow)))

    add("")
    add(c.wrap("  TRANSACTION FLOW", c.bold))
    for line in dns_lines:
        add(line)
    for f in findings:
        _drill_endpoint(add, f, c)
        _render_streams(add, analyzer, f, c)

    _drill_timeline(add, analyzer, findings, c, dns_names=dns_names)
    add("")
    print("\n".join(out))


def _render_streams(add, analyzer, f, c):
    """Break a destination endpoint into its individual TCP/UDP streams
    (connections), each with a one-line status and a Wireshark filter to
    isolate it."""
    streams = analyzer.streams_for(f)
    if not streams:
        return
    pf = "udp" if f["proto"] == "udp" else "tcp"
    add(c.wrap("      streams (%d):" % len(streams), c.bold))
    for sf in streams[:25]:
        cip, cport = sf["client"]
        syn = "✓" if sf["syn"] else "✗"
        sa = "✓" if sf["synack"] else ("✗" if sf["syn"] else "·")
        extra = []
        if sf["rst"]:
            extra.append(c.wrap("RST", c.red))
        if sf["retx"]:
            extra.append(c.wrap("%d retx" % sf["retx"], c.yellow))
        if sf["tls"]:
            extra.append("/".join(sf["tls"]))
        res = {"fail": c.wrap("FAILED", c.red), "warn": c.wrap("DEGRADED", c.yellow),
               "ok": c.wrap("OK", c.green)}[sf["severity"]]
        tag = "" if sf["is_host"] else c.wrap("  (other client)", c.dim)
        add("        %s %-21s SYN%s/ACK%s  ↑%dB/↓%dB%s  → %s  %s%s" % (
            _sev_mark(sf["severity"], c), "%s:%d" % (cip, cport), syn, sa,
            sf["c2s_bytes"], sf["s2c_bytes"],
            ("  " + " ".join(extra)) if extra else "", res,
            c.wrap("[%s]" % sf["file"], c.dim), tag))
        # why: the exact reason(s) behind a FAILED/DEGRADED verdict
        for text, sev in sf["issues"]:
            col = c.red if sev == "fail" else c.yellow
            add(c.wrap("            ↳ why: %s" % text, col))
        # raw evidence the verdict was computed from
        add(c.wrap("            evidence: SYN %d · SYN-ACK %d · RST %d · "
                   "ClientHello %d · ServerHello %d · retx %d · ↑%dB ↓%dB"
                   % (sf["syn"], sf["synack"], sf["rst"], sf["tls_ch"],
                      sf["tls_sh"], sf["retx"], sf["c2s_bytes"], sf["s2c_bytes"]),
                   c.dim))
        add(c.wrap("            wireshark: ip.addr==%s && %s.port==%d && ip.addr==%s "
                   "&& %s.port==%d" % (cip, pf, cport, f["ip"], pf, f["port"]), c.cyan))
    if len(streams) > 25:
        add(c.wrap("        … and %d more stream(s)" % (len(streams) - 25), c.dim))


def _drill_timeline(add, analyzer, findings, c, dns_names=None):
    """Chronological, timestamped event list for the drilled target — so you can
    see whether a failure was the end of the story or traffic carried on after.
    Each event is tagged with its destination so multi-endpoint searches (e.g. a
    port search across several servers) stay readable."""
    events = []                                         # (ts, file, frame, kind, detail, dst)
    for ln in (dns_names or ()):
        for ev in analyzer.dns_timeline.get(ln, []):
            events.append(ev + ("dns",))
    proto_num = {"tcp": 6, "udp": 17}
    extra, last_extra = 0, None
    seen_ips = set()
    for f in findings:
        dst = "%s:%s" % (f["ip"], f["port"])
        pn = proto_num.get(f["proto"])
        if pn is not None:
            key = (pn, f["ip"], f["port"])
            for s in ("user", "conn"):
                d = analyzer.dest[s].get(key)
                if not d:
                    continue
                for ev in d["timeline"]:
                    events.append(ev + (dst,))
                if d["tl_count"] > len(d["timeline"]):
                    extra += d["tl_count"] - len(d["timeline"])
                    if d["tl_last"] and (last_extra is None
                                         or d["tl_last"][0] > last_extra[0]):
                        last_extra = d["tl_last"]
        if f["ip"] not in seen_ips:                     # ICMP errors / fragments
            seen_ips.add(f["ip"])
            for ev in analyzer.ip_timeline.get(f["ip"], []):
                events.append(ev + (f["ip"],))
    if not events:
        return
    events.sort(key=lambda e: e[0])
    multi = len({(f["ip"], f["port"]) for f in findings}) > 1

    fail_kinds = {"RST", "TLS alert", "retransmit", "ICMP"}
    add("")
    add(c.wrap("  TIMELINE", c.bold) + c.wrap("   (time · file #frame · event — "
        "did traffic continue after a failure?)", c.dim))
    if len({e[1] for e in events}) > 1:
        add(c.wrap("    note: timestamps are per-capture; clocks across files "
                   "may differ", c.dim))
    for ts, lbl, fr, kind, detail, dst in events[:120]:
        col = (c.red if (kind in fail_kinds or kind.startswith("DNS ")
                         and kind not in ("DNS query", "DNS resolved"))
               else c.yellow if kind in ("keep-alive", "IP fragment") else "")
        dcol = (c.wrap("%-21s " % dst, c.dim)) if multi else ""
        add("    %s  %s%-13s #%-6d %s %s" % (
            _fmt_clock(ts), dcol, lbl, fr, c.wrap("%-16s" % kind, col),
            c.wrap(detail, c.dim)))
    if len(events) > 120:
        add(c.wrap("    … %d more shown-events trimmed" % (len(events) - 120), c.dim))
    if extra and last_extra:
        add(c.wrap("    (+%d more events after the per-flow cap — last at %s, %s)"
                   % (extra, _fmt_clock(last_extra[0]), last_extra[3]), c.dim))


# ---------------------------------------------------------------------------
# Interactive terminal wizard (no command-line file paths needed)
# ---------------------------------------------------------------------------


def _open_gui():
    """Return a hidden Tk root for native file dialogs, or None if there's no
    GUI (headless/SSH) or the user opted out via ZSP_NO_GUI."""
    if os.environ.get("ZSP_NO_GUI"):
        return None
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)    # bring dialogs to the front
        except Exception:
            pass
        root.update()
        return root
    except Exception:
        return None


def _pick_files(root, title, multiple=True):
    """Open a native file-open dialog; return a list of chosen paths."""
    from tkinter import filedialog
    ftypes = [("Capture files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")]
    try:
        if multiple:
            sel = filedialog.askopenfilenames(parent=root, title=title, filetypes=ftypes)
        else:
            one = filedialog.askopenfilename(parent=root, title=title, filetypes=ftypes)
            sel = (one,) if one else ()
        root.update()
        return [p for p in root.tk.splitlist(sel) if p]
    except Exception:
        return []


def _enable_path_completion():
    """Tab-completion of filesystem paths via readline (typed fallback only)."""
    try:
        import readline
    except ImportError:
        return

    def complete(text, state):
        stub = os.path.expanduser(text)
        matches = [m + ("/" if os.path.isdir(m) else "") for m in glob.glob(stub + "*")]
        return matches[state] if state < len(matches) else None

    readline.set_completer(complete)
    readline.set_completer_delims(" \t\n")       # keep "/" and "." in the word
    if "libedit" in (getattr(readline, "__doc__", "") or ""):
        readline.parse_and_bind("bind ^I rl_complete")     # macOS libedit
    else:
        readline.parse_and_bind("tab: complete")           # GNU readline


def _expand_paths(line):
    """Turn a typed line into (existing_paths, missing). Handles quoted/escaped
    drag-and-drop paths, globs, ~, and several space-separated entries."""
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    paths, missing = [], []
    for tok in tokens:
        tok = os.path.expanduser(tok.strip())
        if not tok:
            continue
        hits = glob.glob(tok)
        if hits:
            paths.extend(sorted(h for h in hits if os.path.isfile(h)))
        elif os.path.isfile(tok):
            paths.append(tok)
        else:
            missing.append(tok)
    return paths, missing


def _ask_files_typed(c, required):
    print(c.wrap("    type path(s) — Tab completes, space-separated for several",
                 c.dim))
    while True:
        try:
            line = input(c.wrap("    > ", c.cyan)).strip()
        except EOFError:
            line = ""
        if not line:
            if required:
                print(c.wrap("    a capture is required — please add at least one.",
                             c.yellow))
                continue
            return []
        paths, missing = _expand_paths(line)
        for m in missing:
            print(c.wrap("    ! not found: %s" % m, c.red))
        if paths:
            for p in paths:
                print(c.wrap("    + %s" % p, c.green))
            return paths
        if not required:
            return []


def _ask_files(c, label, title, required, root):
    """Pick one or more capture files via a native dialog (typed fallback)."""
    print(c.wrap("\n  " + label, c.bold, c.cyan))
    if root is None:
        return _ask_files_typed(c, required)
    print(c.wrap("    opening a file browser — navigate to your captures…", c.dim))
    while True:
        paths = [p for p in _pick_files(root, title) if os.path.isfile(p)]
        if paths:
            for p in paths:
                print(c.wrap("    + %s" % p, c.green))
            return paths
        if not required:
            print(c.wrap("    (none selected — skipped)", c.dim))
            return []
        if not _ask_yesno(c, "  nothing selected — open the browser again?", default=True):
            return []


def _ask_yesno(c, label, default=False):
    suffix = " [y/N]" if not default else " [Y/n]"
    try:
        ans = input(c.wrap("\n  " + label + suffix + " ", c.cyan)).strip().lower()
    except EOFError:
        return default
    if not ans:
        return default
    return ans[0] == "y"


def _ask_text(c, label):
    try:
        return input(c.wrap("\n  " + label + " (Enter to skip) ", c.cyan)).strip() or None
    except EOFError:
        return None


def run_wizard(color_on):
    """Interactive terminal flow used when no captures are given on the CLI."""
    c = Palette(color_on)
    if not sys.stdin.isatty():
        sys.stderr.write(
            "No captures given and stdin is not a terminal.\n"
            "Run interactively, or pass --user-pcap (see --help).\n")
        return 2

    print(c.wrap("\n  ZSCALER PRESENCE v%s — network health analyzer" % VERSION,
                 c.bold, c.cyan))
    print(c.wrap("  pick your captures, then a few optional prompts.", c.dim))

    _enable_path_completion()
    root = _open_gui()
    if root is None:
        print(c.wrap("  (no GUI file browser available — type paths instead)", c.dim))
    try:
        user_paths = _ask_files(
            c, "Endpoint / tunnel capture(s)  [required]",
            "Select endpoint / tunnel capture(s)", True, root)
        conn_paths = _ask_files(
            c, "Connector / gateway capture(s)  [optional]",
            "Select connector / gateway capture(s)", False, root)
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass

    analyzer = Analyzer()
    try:
        for path in user_paths:
            analyzer.feed_user(path)
        for path in conn_paths:
            analyzer.feed_connector(path)
    except PcapFormatError as e:
        print(c.wrap("\n  ! %s" % e, c.red))
        return 1

    # auto-detect and show the host IP, so the override is clearly optional
    host = analyzer.detect_host()
    if host:
        print(c.wrap("\n  host machine IP auto-detected: %s" % host, c.green))
    else:
        print(c.wrap("\n  could not auto-detect a host IP (no application flows "
                     "in the endpoint capture — is it the encrypted tunnel?)",
                     c.yellow))

    subnets_str = _ask_text(c, "Focus on subnets? comma-separated CIDRs, e.g. "
                               "10.0.0.0/8,192.168.1.0/24")
    fqdns_str = _ask_text(c, "Focus on FQDNs? comma-separated, e.g. "
                             "app.example.com,api.example.net")
    override = _ask_text(c, "Override host IP? Enter to keep %s" % (host or "auto"))
    if override:
        analyzer.source_filter = override
    host_only = _ask_yesno(c, "Limit to the host's own traffic? (isolates this "
                              "host's transactions)", default=True)
    show_all = _ask_yesno(c, "List the healthy (established, no-issue) "
                             "destinations too?", default=False)
    networks, fqdns = parse_focus(subnets_str, fqdns_str)

    findings, filtered, host_hidden = analyzer.build_findings(
        networks, fqdns, host_only=host_only)
    _resolve_step(analyzer, findings, c, enabled=True)
    report(analyzer, findings, c, show_all, filtered_out=filtered,
           focus_desc=focus_desc(networks, fqdns), host_hidden=host_hidden)

    # offer repeated deep-dives on a specific IP / FQDN
    while True:
        target = _ask_text(c, "Drill into an IP, FQDN, or port(s) — e.g. "
                              "443,8000-8090 (blank to finish)")
        if not target:
            break
        run_drilldown(analyzer, target, c)
    return 0


def _resolve_step(analyzer, findings, c, enabled):
    """Fill in FQDNs for IP-only destinations via reverse DNS, with a note."""
    if not enabled:
        return
    need = sum(1 for f in findings if not f["names"] and f["ip"])
    if not need:
        return
    print(c.wrap("  resolving %d IP-only destination(s) via reverse DNS…" % need,
                 c.dim))
    analyzer.resolve_ptr(findings)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Network health analyzer — correlate an endpoint/tunnel "
                    "capture and connector captures to localize problems.")
    ap.add_argument("--version", action="version",
                    version="zscaler-presence %s" % VERSION)
    ap.add_argument("--user-pcap", "-u", nargs="+", metavar="PCAP",
                    help="capture(s) from the endpoint. "
                         "Omit all file args for the interactive terminal wizard.")
    ap.add_argument("--connector", "-c", nargs="*", default=[], metavar="PCAP",
                    help="capture(s) from the gateway / connector(s)")
    ap.add_argument("--subnets", metavar="CIDRs",
                    help="focus on these comma-separated subnets/CIDRs")
    ap.add_argument("--fqdns", metavar="LIST",
                    help="focus on these comma-separated FQDNs")
    ap.add_argument("--source", "-s", metavar="IP",
                    help="override the auto-detected host IP")
    ap.add_argument("--all-traffic", action="store_true",
                    help="show every destination, not just the host's own "
                         "transactions (host-only is the default)")
    ap.add_argument("--drill", metavar="IP|FQDN|PORTS",
                    help="after the report, deep-dive on this IP/subnet, FQDN, "
                         "or port spec (e.g. 443,8000-8090)")
    ap.add_argument("--show-all", action="store_true",
                    help="list the healthy destinations too")
    ap.add_argument("--no-resolve", action="store_true",
                    help="skip reverse-DNS (PTR) lookups for IP-only destinations")
    ap.add_argument("--explain", action="store_true",
                    help="print a plain-English guide to each check (what "
                         "pass/fail means + the Wireshark filter) and exit")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI color")
    args = ap.parse_args(argv)

    color_on = (not args.no_color) and sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    if args.explain:
        print(render_legend(Palette(color_on)))
        return 0

    # No capture given on the command line -> interactive terminal wizard.
    if not args.user_pcap:
        return run_wizard(color_on)

    c = Palette(color_on)

    missing = [p for p in (args.user_pcap + args.connector) if not os.path.isfile(p)]
    if missing:
        ap.error("file(s) not found: " + ", ".join(missing))

    networks, fqdns = parse_focus(args.subnets, args.fqdns)

    analyzer = Analyzer(source_filter=args.source)
    try:
        for path in args.user_pcap:
            analyzer.feed_user(path)
        for path in args.connector:
            analyzer.feed_connector(path)
    except PcapFormatError as e:
        ap.error(str(e))

    findings, filtered, host_hidden = analyzer.build_findings(
        networks, fqdns, host_only=not args.all_traffic)
    _resolve_step(analyzer, findings, c, enabled=not args.no_resolve)
    report(analyzer, findings, c, args.show_all, filtered_out=filtered,
           focus_desc=focus_desc(networks, fqdns), host_hidden=host_hidden)
    if args.drill:
        run_drilldown(analyzer, args.drill, c)
    return 0


if __name__ == "__main__":
    sys.exit(main())
