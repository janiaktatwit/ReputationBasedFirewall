from dataclasses import dataclass
from typing import Optional
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP
from scapy.utils import rdpcap
import sys
import random


@dataclass
class FirewallRule: #other fields added for later implemntation
    rule_id: int = 0
    source_ip: str = "default"
    destination_ip: str = "default"
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: int = 0          # TCP = 6, UDP = 17, ICMP = 1
    action: str ="default"           # ALLOW or DENY
    priority: int = 0
    trust_score: float = 0.0

@dataclass
@dataclass
class Packet:
    source_ip: str = "default"
    destination_ip: str = "default"
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: int = 0

rules: list[FirewallRule] = []
packets: list[Packet] = []

KNOWN_MALICIOUS_IPS = []
KNOWN_TRUSTED_IPS = ["23.197.45.160"]  # 23.197.45.160 == amazon from .pcap (technically akamaitechnologies, but its a proxy for amazon.com)


def loadTraffic():

    args = sys.argv

    if len(args) < 2:
        print("Provide a pcap file as an argument.")
        sys.exit(1)

    packets_read = rdpcap(args[1])
    packets = []

    for packet in packets_read:
        if not packet.haslayer(IP):
            continue

        source_port = None
        destination_port = None

        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        new_packet = Packet(
            source_ip=packet[IP].src,
            destination_ip=packet[IP].dst,
            protocol=packet[IP].proto,
            source_port=source_port,
            destination_port=destination_port
        )

        packets.append(new_packet)

    return packets

def scoreUpdate(p, r):
    if p.source_ip in KNOWN_TRUSTED_IPS:
        trusted = True

    elif p.source_ip in KNOWN_MALICIOUS_IPS:
        trusted = False

    else:
        return
    
    correct = (p.source_ip in KNOWN_TRUSTED_IPS and p.action == "ALLOW") or (p.source_ip in KNOWN_MALICIOUS_IPS and p.action == "DENY")
    
    if correct:
        r.trust_score += 1
        update = 1
    else:
        r.trust_score -= 1
        update = -1

    print(
        f"Rule {r.rule_id}: "
        f"Action={r.action}, "
        f"Packet={p.source_ip}, "  
        f"Update={update}, " 
        f"Trust Score={r.trust_score}"
    )

def createRulesPOC(): ##creates random list mimicking a firewall log (10 rules)
    known_source = ""
    action = ""
    
    for i in range(10):
        num = random.randint(1, 10)
        rule =FirewallRule(rule_id=i)
        if num <= 5: rule.action = "ALLOW"
        else: rule.action = "DENY"
        num2 = random.randint(1,10)
        rule.source_ip = "MALICIOUS" if num2 <= 5 else "TRUSTED"
        
        rules.append(rule)




def createTrafficPOC(): ##creates random list mimicking a incoming traffic log (10 packets)
    known_source = ""
    action = ""
    
    for i in range(10):
        num = random.randint(1, 10)
        packet = Packet()
        #if num <= 5: packet.protocol = "TCP"
        #else: packet.protocol = "UDP"
        num2 = random.randint(1,10)
        packet.source_ip = "MALICIOUS" if num2 <= 5 else "TRUSTED"    
        packets.append(packet)
        
def scoreUpdatePOC():
    for i in range(len(rules)):
        if rules[i].action == "ALLOW" and packets[i].source_ip == "TRUSTED":
            rules[i].trust_score += 1
            update = 1
        elif rules[i].action == "DENY" and packets[i].source_ip == "MALICIOUS":
            rules[i].trust_score += 1
            update = 1
        else: ##menaing that the rule is allowing a malicious source or denying a trusted source, which is bad for the firewall rules reputation
            rules[i].trust_score -= 1
            update = -1
        print(f"Rule {rules[i].rule_id}: "
        f"Action={rules[i].action}, "
        f"Packet={packets[i].source_ip}, "
        f"Update={update}, "
        f"Trust Score={rules[i].trust_score}"
        )
        
if __name__ == "__main__":
    print("Program started")
    createRulesPOC()
    createTrafficPOC()
    print(f"Rules: {len(rules)}")
    print(f"Packets: {len(packets)}")
    scoreUpdatePOC()