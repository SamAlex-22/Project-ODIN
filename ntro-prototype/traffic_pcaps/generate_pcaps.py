from scapy.all import *
import random
import time
import os

def generate_benign(count=100, out_file="benign.pcap"):
    print(f"Generating {out_file}...")
    packets = []
    base_time = time.time() - 3600 # 1 hour ago
    
    for i in range(count):
        src_ip = f"192.168.1.{random.randint(10, 50)}"
        dst_ip = f"10.0.0.{random.randint(10, 50)}"
        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443, 53])
        
        # Simple TCP handshake
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S")
        pkt.time = base_time + (i * 0.1)
        packets.append(pkt)
        
    wrpcap(out_file, packets)

def generate_syn_flood(count=1000, target="10.0.0.1", out_file="attack_syn_flood.pcap"):
    print(f"Generating {out_file}...")
    packets = []
    base_time = time.time() - 3000
    
    for i in range(count):
        # Spoofed source IPs
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        sport = random.randint(1024, 65535)
        
        pkt = Ether()/IP(src=src_ip, dst=target)/TCP(sport=sport, dport=8080, flags="S")
        pkt.time = base_time + (i * 0.001) # fast rate
        packets.append(pkt)
        
    wrpcap(out_file, packets)

def generate_recon(target="10.0.0.1", src="192.168.1.100", out_file="attack_recon.pcap"):
    print(f"Generating {out_file}...")
    packets = []
    base_time = time.time() - 2500
    
    for port in range(1, 1001):
        pkt = Ether()/IP(src=src, dst=target)/TCP(sport=54321, dport=port, flags="S")
        pkt.time = base_time + (port * 0.01)
        packets.append(pkt)
        
    wrpcap(out_file, packets)

def generate_c2(src="192.168.1.200", dst="10.0.0.99", port=9999, out_file="attack_c2.pcap"):
    print(f"Generating {out_file}...")
    packets = []
    base_time = time.time() - 2000
    
    # 20 beacons, 30s interval, slight jitter
    for i in range(20):
        interval = 30 + random.uniform(-2, 2)
        base_time += interval
        sport = random.randint(1024, 65535)
        
        # simple SYN to simulate the connection
        pkt = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=port, flags="S")
        pkt.time = base_time
        packets.append(pkt)
        
    wrpcap(out_file, packets)

def generate_dns_tunnel(src="192.168.1.150", dst="8.8.8.8", out_file="attack_dns_tunnel.pcap"):
    print(f"Generating {out_file}...")
    packets = []
    base_time = time.time() - 1000
    
    for i in range(50):
        # random high entropy subdomain
        subdomain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=30))
        qname = f"{subdomain}.evil.com"
        
        pkt = Ether()/IP(src=src, dst=dst)/UDP(sport=random.randint(1024, 65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=qname))
        pkt.time = base_time + (i * 0.5)
        packets.append(pkt)
        
    wrpcap(out_file, packets)

def main():
    generate_benign()
    generate_syn_flood()
    generate_recon()
    generate_c2()
    generate_dns_tunnel()
    print("Done generating PCAPs.")

if __name__ == "__main__":
    main()
