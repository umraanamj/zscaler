# Zscaler Presence — network health analyzer

A zero-dependency Python tool that reads packet captures from two vantage points
along a tunnelled path and produces a network **troubleshooting** report:
what's succeeding, what's failing, and where a flow breaks.

The running version is printed in the header; `--version` prints it and exits.

Run with **`--explain`** for an optional plain-English guide — for every check
it says what passing and failing mean and the exact Wireshark filter to pull it
up (e.g. `TLS ServerHello → tls.handshake.type == 2`).

## Inputs

| Input | Flag | Meaning |
|-------|------|---------|
| Endpoint / tunnel capture | `--user-pcap` (1+) | Captured at the client end — the user reaching out to destinations (decrypted inner traffic + DNS). |
| Connector / gateway capture | `--connector` (0+) | Captured where the tunnel lands/egresses — **bidirectional**: client requests in, server responses out. |
| Focus subnets | `--subnets` | Comma-separated CIDRs to focus on (optional). |
| Focus FQDNs | `--fqdns` | Comma-separated FQDNs to focus on (optional). |

The same session shows up at both vantage points, so the two captures are
**correlated per destination** (by destination IP/port + FQDN — the connector
usually NATs the client source, so that isn't used for matching).

## What it reports

- **Points of interest** — per destination, the specific problem and where it
  occurred:
  - `left the tunnel but never reached the connector` (steering / tunnel issue)
  - `no SYN-ACK — server not responding / blocked`
  - `connection reset (RST)`
  - `TLS alert: bad_certificate (fatal)` / `handshake_failure` / …
  - `TLS ClientHello sent, no ServerHello seen`
  - `data sent but none returned` — possible **return-route asymmetry** (server→client), with per-direction byte counts
  - `connection established but no payload` — path is up, issue is above this layer
  - `IP fragmentation` / `small TCP MSS` — possible **MTU / path** issues
  - ICMP `dest unreachable` / `time exceeded` (attributed to the failed destination)
  - `N TCP retransmission(s)`
- **DNS issues** — `NXDOMAIN`, `SERVFAIL`, `REFUSED`, and queries that got **no
  response**, each shown by name, the **resolver** that answered/didn't
  (`via 10.0.0.53`), and the source file. Reported globally (not hidden by a
  subnet focus, since resolvers usually sit outside the focused subnet).
- **Retransmission hotspots** — destinations ranked by retransmit count.
- **Healthy** — established, clean destinations (count; `--show-all` to list).
- **Header summary** — each capture file read (with per-file packet counts and
  time span), auto-detected host IP, SYN / SYN-ACK / RST / retransmit totals,
  DNS query/failure counts.

By default the report is **scoped to the detected host's own transactions** —
other clients' traffic and connector infrastructure are hidden (with a one-line
count; `--all-traffic` shows everything). Because findings merge both captures
by destination, host scoping keeps the connector-side health of the host's
destinations even when the connector NATs the client source.

Every finding and DNS issue is annotated with the **source file(s) and frame
numbers** it came from (`frames: conn-west.pcap #3 (RST #4) · host.pcap #3`,
DNS `@ host.pcap #1`). Frame numbers match Wireshark's `frame.number` for that
file, so you can sweep at a high level here and then jump straight to the exact
packet in the exact pcap to dig deeper.

A **"NOT OBSERVABLE FROM THIS CAPTURE"** footer states plainly what the vantage
point can't tell you (policy/enablement decisions, root cause of a non-response,
config-level segment membership, and — when absent — DNS or the connector side),
so the report never implies coverage it doesn't have.

Each destination is named by **TLS SNI** and observed **DNS**, and IP-only
destinations are resolved by **reverse DNS (PTR)** (`--no-resolve` to skip). The
**host IP is auto-detected** from the endpoint capture — primarily from who
issues DNS queries (only the host does that), falling back to whoever initiates
the most distinct connections; `--source` overrides it. It warns when a capture
looks like an opaque/encrypted tunnel (capture wasn't on the tunnel interface,
so inner destinations aren't visible).

## Focus filters

`--subnets` and `--fqdns` restrict the report to matching destinations and print
a one-line note of how many were hidden, so nothing is silently dropped. When
**both** are given they are **AND**ed — a destination must be in one of the
subnets *and* match one of the FQDNs to be shown. (Note: an IP-only destination
with no resolved name can never satisfy an FQDN filter.)

```sh
--subnets 10.0.0.0/8,192.168.1.0/24
--fqdns   app.example.com,api.example.net
```

## Capturing

Capture on the interface that carries the **decrypted** application traffic so
the real destinations, DNS, and TLS SNI are visible:

```sh
sudo tcpdump -i <interface> -w host.pcap        # endpoint / tunnel side
sudo tcpdump -i <interface> -w connector.pcap   # connector / gateway side (both directions)
```

## Usage

### Interactive (default)

Run with no arguments. A native file-browser window opens for each capture so
you can navigate to where the pcaps live and select them — no typing paths. Then
it prompts for optional focus subnets/FQDNs:

```sh
python3 zscaler_presence.py
```

If there's no GUI (headless/SSH) or you set `ZSP_NO_GUI=1`, the wizard falls
back to typing paths (with Tab-completion). Everything runs locally.

After the report, the wizard repeatedly asks **"Drill into an IP, FQDN, or
port(s)?"** — answer with an IP/subnet, an FQDN, or a **port spec** like
`443`, `443,8080`, or `8000-8090,53` (multiple ports and/or ranges). It prints a
**stage-by-stage flow** of the host's transactions to the matching destinations
across every capture, so you can see exactly where each broke:

```
TRANSACTION FLOW
  DNS  app.example.com
    ✓ query sent          @ host.pcap #1
    ✓ resolved → 203.0.113.10   via 10.0.0.53  @ host.pcap #2
  ! tcp/443  app.example.com [203.0.113.10]  seen in: tunnel + connector captures
    ✓ TCP SYN          conn.pcap #1 · host.pcap #3
    ✓ TCP SYN-ACK      conn.pcap #2
    ✓ TLS ClientHello  TLS1.2   conn.pcap #3 · host.pcap #4
    ✗ TLS ServerHello  not seen
    ✓ user → server    154 bytes   conn.pcap #3,#6 · host.pcap #4
    ✗ server → user    none returned
    ⇒ result: DEGRADED
```

After the flow ladder, the drill-down prints a **TIMELINE** — every event for
that target in chronological order with timestamps, file, and frame number:

```
TIMELINE   (time · file #frame · event)
  16:13:20.040  good.pcap #3   data          user → server 9B
  16:13:20.300  good.pcap #4   retransmit    user → server 9B
  16:13:20.330  good.pcap #5   data          server → user 11B   ← recovered
  16:13:20.045  bad.pcap  #4   ICMP          port unreachable → :443
  16:13:20.800  good.pcap #7   FIN           user → server
```

Timestamps are the capture's own (local) time, matching Wireshark's default
view. DNS, SYN/SYN-ACK, TLS, data, keep-alives, retransmits, RST, FIN,
**ICMP errors and IP fragments** all appear in the timeline.

This answers "was the failure terminal?" — if something fails but traffic
continues after it (like the retransmit above), it probably recovered; if a
failure (RST, alert) is the **last** event, that's where it stopped.

Because the host can open several connections to the same `server:port`, each
endpoint is also **split into its individual TCP/UDP streams** — every connection
(unique client-port 4-tuple) with its own SYN/SYN-ACK/data/RST status and a
ready-to-paste Wireshark filter to isolate just that stream
(`ip.addr==<host> && tcp.port==<cport> && ip.addr==<server> && tcp.port==<sport>`).

Each flow-ladder stage is ✓ / ✗ / · (not seen) and carries **its own file + frame number(s)**
so you can jump straight to that packet — and so do the anomaly lines
(`! retransmission … conn.pcap #4`, `! ICMP … #7`, `! fragmentation … #6`).
Traffic directions read **user → server** and **server → user**. A DNS failure
(NXDOMAIN / SERVFAIL / no response) shows at the DNS stage and stops there. Blank
to finish; on the command line, `--drill IP|FQDN` does the same.

### Command line

```sh
python3 zscaler_presence.py \
    --user-pcap host.pcap \
    --connector connector1.pcap connector2.pcap \
    [--subnets 10.0.0.0/8,192.168.1.0/24] \
    [--fqdns app.example.com,api.example.net] \
    [--source 10.6.0.2]   # override the auto-detected host
    [--show-all]          # also list healthy destinations
    [--no-resolve]        # skip reverse-DNS (PTR) lookups
    [--no-color]
```

## How it works

Pure standard library — its own pcap/pcapng parser plus decoders for
Ethernet/NULL/raw-IP/Linux-SLL link layers, IPv4/IPv6, TCP (flags, seq,
retransmit tracking), UDP, ICMP/ICMPv6 errors (incl. the quoted original packet),
DNS (rcodes, query/response matching, A/AAAA/CNAME), TLS ClientHello (SNI +
version), ServerHello and TLS alerts, and an encapsulated-tunnel fingerprint.
Reverse-DNS uses the system resolver. No `pip install` and no external binaries —
runs on a locked-down host with only Python 3.7+.

For each destination the two captures are merged into a single health picture;
the server side of each connection is identified from the TCP SYN direction (or
the lower/well-known port when no handshake was captured).

Retransmissions are detected from a single vantage point (a data segment whose
sequence number falls before the next-expected seq), with **TCP keep-alives
excluded** (a ≤1-byte segment at `seq = next−1` is a keep-alive, not a
retransmission). This is a heuristic — for an authoritative count, validate
against Wireshark's `tcp.analysis.retransmission` filter; out-of-order vs.
retransmission requires per-segment timing that this single-pass parser doesn't
track.
