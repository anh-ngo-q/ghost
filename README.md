# Lab 03: Ghost Machine - ARP Spoofing Attack

## Overview

This lab demonstrates an ARP spoofing attack that makes a non-existent "ghost" machine appear real on a local network. The attacker convinces a victim (hostA) that a machine with IP address `10.10.0.10` exists, even though no such machine is physically connected to the network.

## Network Topology

| Host     | IP Address   |
|----------|--------------|
| hostA    | 10.10.0.4    |
| hostB    | 10.10.0.5    |
| attacker | 10.10.0.13   |
| ghost    | 10.10.0.10 (non-existent) |

## The Vulnerability

The ARP (Address Resolution Protocol) has no authentication mechanism. When a host needs to find the MAC address for an IP address, it broadcasts an ARP Request to the entire local network. Any host can respond claiming to own that IP address, and the requesting host will trust the response without verification.

## Attack Description

When hostA attempts to ping the ghost IP (`10.10.0.10`), the attacker intercepts and responds to make it appear the ghost exists.

### Attack Steps

1. **Attacker listens** for ARP Request broadcasts asking "Who has 10.10.0.10?"

2. **Attacker sends spoofed ARP Reply** (unicast) to hostA claiming "10.10.0.10 is at [attacker's MAC address]." This causes hostA to update its ARP table with a false mapping.

3. **Attacker listens** for ICMP Echo Requests destined for 10.10.0.10.

4. **Attacker sends spoofed ICMP Echo Reply** with source IP set to 10.10.0.10 (not the attacker's real IP). This completes the illusion that the ghost machine exists and is responding.

### Packet Sequence Diagram

```
hostA                                   attacker
  |                                         |
  |---- ARP Request (broadcast) ----------->|
  |     "Who has 10.10.0.10?"               |
  |                                         |
  |<--- ARP Reply (unicast) ----------------|
  |     "10.10.0.10 is at [attacker MAC]"   |
  |                                         |
  |---- ICMP Echo Request ----------------->|
  |     (dst IP: 10.10.0.10)                |
  |                                         |
  |<--- ICMP Echo Reply (spoofed) ----------|
  |     (src IP: 10.10.0.10)                |
```

## Usage

### Prerequisites

- Docker environment with hostA, hostB, and attacker containers
- Python 3 with Scapy library (pre-installed in containers)

### Running the Exploit

1. Start the Docker environment:
   ```bash
   docker compose up -d
   ```

2. On the attacker machine, run the exploit with root privileges:
   ```bash
   sudo ./exploit.py
   ```

3. On hostA, ping the ghost machine:
   ```bash
   ping -c3 10.10.0.10
   ```

4. Observe that hostA receives responses from the non-existent ghost machine.

### Expected Output

**On attacker:**
```
[*] Starting ghost exploit for 10.10.0.10...
[*] Listening on eth0
[*] ARP Request for 10.10.0.10 from 10.10.0.4
[+] Sent spoofed ARP Reply: 10.10.0.10 is at xx:xx:xx:xx:xx:xx
[*] ICMP Echo Request for 10.10.0.10 from 10.10.0.4
[+] Sent spoofed ICMP Echo Reply from 10.10.0.10
```

**On hostA:**
```
PING 10.10.0.10 (10.10.0.10) 56(84) bytes of data.
64 bytes from 10.10.0.10: icmp_seq=1 ttl=64 time=78.6 ms
64 bytes from 10.10.0.10: icmp_seq=2 ttl=64 time=17.0 ms
```

## Files

- `exploit.py` - Main exploit script
- `docker-compose.yml` - Container configuration
- `volumes/` - Shared directory between host and containers

## Tools Used

- **Scapy** - Python library for packet crafting and sniffing
- **tcpdump** - Packet capture utility
- **Wireshark** - Packet analysis (optional, for debugging)

## References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [ARP Protocol (RFC 826)](https://tools.ietf.org/html/rfc826)
- [ICMP Protocol (RFC 792)](https://tools.ietf.org/html/rfc792)
