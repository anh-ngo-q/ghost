#!/usr/bin/env python3
from scapy.all import *

GHOST_IP = "10.10.0.10"
INTERFACE = "eth0"

def handle_packet(pkt):
    my_mac = get_if_hwaddr(INTERFACE)
    
    # ignore packets from ourselves
    if pkt[Ether].src == my_mac:
        return
    
    # handle ARP Request for GHOST_IP
    if ARP in pkt and pkt[ARP].op == 1 and pkt[ARP].pdst == GHOST_IP:
        print(f"[*] ARP Request for {GHOST_IP} from {pkt[ARP].psrc}")
        
        arp_reply = Ether(dst=pkt[Ether].src) / ARP(
            op=2,                   
            hwsrc=my_mac,          
            psrc=GHOST_IP,        
            hwdst=pkt[ARP].hwsrc,   
            pdst=pkt[ARP].psrc     
        )
        sendp(arp_reply, iface=INTERFACE, verbose=False)
        print(f"[+] Sent spoofed ARP Reply: {GHOST_IP} is at {my_mac}")
    
    # handle ICMP Echo Request for GHOST_IP
    if IP in pkt and ICMP in pkt and pkt[IP].dst == GHOST_IP:
        if pkt[ICMP].type == 8: 
            print(f"[*] ICMP Echo Request for {GHOST_IP} from {pkt[IP].src}")
            
            icmp_reply = Ether(dst=pkt[Ether].src) / IP(
                src=GHOST_IP,        
                dst=pkt[IP].src     
            ) / ICMP(
                type=0,            
                id=pkt[ICMP].id,    
                seq=pkt[ICMP].seq   
            ) / Raw(load=pkt[Raw].load if Raw in pkt else b'')
            
            sendp(icmp_reply, iface=INTERFACE, verbose=False)
            print(f"[+] Sent spoofed ICMP Echo Reply from {GHOST_IP}")

print(f"[*] Starting ghost exploit for {GHOST_IP}...")
print(f"[*] Listening on {INTERFACE}")
sniff(iface=INTERFACE, filter="arp or icmp", prn=handle_packet)