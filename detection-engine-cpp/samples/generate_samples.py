#!/usr/bin/env python3
"""
Generates labelled test captures for the CyberGuard Network IDS.

    pip install scapy
    python generate_samples.py            # writes the .pcap files into this folder

Every attack capture also contains ordinary background traffic (HTTPS browsing
and DNS lookups) so the NIDS has to pick the attack out of normal activity.
All addresses are private (192.168.1.0/24) or reserved documentation /
example ranges; nothing here touches a real network.
"""
import os
import random
import struct

from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw  # noqa: E402

random.seed(7)
OUT = os.path.dirname(os.path.abspath(__file__))
T0 = 1_700_000_000.0          # capture start time (epoch seconds)
LAN_GW = "192.168.1.1"
DNS_SERVER = "8.8.8.8"
SNAPLEN = 256                 # long packets are stored truncated, like tcpdump -s 256

MAC_A, MAC_B = "02:00:00:00:00:01", "02:00:00:00:00:02"


def eth(pkt):
    return Ether(src=MAC_A, dst=MAC_B) / pkt


def write_pcap(name, packets, snaplen=SNAPLEN):
    """packets: list of (timestamp, scapy packet). Writes classic pcap, truncating each packet to snaplen."""
    packets.sort(key=lambda x: x[0])
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))
        for ts, pkt in packets:
            raw = bytes(pkt)
            cap = raw[:snaplen]
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            f.write(struct.pack("<IIII", sec, usec, len(cap), len(raw)))
            f.write(cap)
    print(f"  {name:<34} {len(packets):>6} packets  {os.path.getsize(path) / 1024:>8.1f} KB")


# ---------------------------------------------------------------- building blocks
def tcp_session(t, cli, cport, srv, sport, up=600, down=4000, rtt=0.03, mss=1400, close=True):
    """Complete TCP conversation: handshake, request/response data, FIN teardown."""
    out = []
    cs, ss = random.randint(1, 2**31), random.randint(1, 2**31)
    out.append((t, eth(IP(src=cli, dst=srv) / TCP(sport=cport, dport=sport, flags="S", seq=cs))))
    out.append((t + rtt, eth(IP(src=srv, dst=cli) / TCP(sport=sport, dport=cport, flags="SA", seq=ss, ack=cs + 1))))
    t += rtt * 1.1
    out.append((t, eth(IP(src=cli, dst=srv) / TCP(sport=cport, dport=sport, flags="A", seq=cs + 1, ack=ss + 1))))
    cs += 1; ss += 1
    for direction, total in (("up", up), ("down", down)):
        sent = 0
        while sent < total:
            n = min(mss, total - sent)
            t += 0.002
            if direction == "up":
                out.append((t, eth(IP(src=cli, dst=srv) / TCP(sport=cport, dport=sport, flags="PA", seq=cs, ack=ss) / Raw(b"x" * n))))
                cs += n
            else:
                out.append((t, eth(IP(src=srv, dst=cli) / TCP(sport=sport, dport=cport, flags="PA", seq=ss, ack=cs) / Raw(b"y" * n))))
                ss += n
            sent += n
        t += rtt / 2
    if close:
        t += 0.01
        out.append((t, eth(IP(src=cli, dst=srv) / TCP(sport=cport, dport=sport, flags="FA", seq=cs, ack=ss))))
        out.append((t + rtt, eth(IP(src=srv, dst=cli) / TCP(sport=sport, dport=cport, flags="FA", seq=ss, ack=cs + 1))))
        out.append((t + rtt * 1.1, eth(IP(src=cli, dst=srv) / TCP(sport=cport, dport=sport, flags="A", seq=cs + 1, ack=ss + 1))))
    return out


def dns_lookup(t, cli, name, answer="93.184.216.34", rtt=0.02):
    qid = random.randint(0, 65535)
    sport = random.randint(20000, 60000)
    q = eth(IP(src=cli, dst=DNS_SERVER) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
    r = eth(IP(src=DNS_SERVER, dst=cli) / UDP(sport=53, dport=sport) /
            DNS(id=qid, qr=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=300, rdata=answer)))
    return [(t, q), (t + rtt, r)]


SITES = [("www.wikipedia.org", "208.80.154.224"), ("github.com", "140.82.112.3"), ("www.google.com", "142.250.182.4"),
         ("stackoverflow.com", "151.101.1.69"), ("docs.python.org", "151.101.0.223"), ("www.bbc.com", "151.101.64.81")]


def background(duration, clients=("192.168.1.21", "192.168.1.22", "192.168.1.23"), sessions=30):
    """Ordinary browsing: a DNS lookup then an HTTPS session, spread over the capture."""
    out = []
    for _ in range(sessions):
        t = T0 + random.uniform(0, duration)
        cli = random.choice(clients)
        name, ip = random.choice(SITES)
        out += dns_lookup(t, cli, name, ip)
        out += tcp_session(t + 0.05, cli, random.randint(40000, 60000), ip, 443,
                           up=random.randint(400, 1500), down=random.randint(3000, 30000))
    return out


# ---------------------------------------------------------------- scenarios
def normal_traffic():
    return background(300, sessions=60)


def port_scan():
    pk = background(120)
    attacker, target = "203.0.113.50", "192.168.1.20"
    open_ports = {22, 80, 443}
    t = T0 + 30
    for port in range(1, 1025):
        t += 0.004
        sp = random.randint(40000, 60000)
        pk.append((t, eth(IP(src=attacker, dst=target) / TCP(sport=sp, dport=port, flags="S", seq=1000))))
        if port in open_ports:
            pk.append((t + 0.001, eth(IP(src=target, dst=attacker) / TCP(sport=port, dport=sp, flags="SA", seq=5000, ack=1001))))
            pk.append((t + 0.002, eth(IP(src=attacker, dst=target) / TCP(sport=sp, dport=port, flags="R", seq=1001))))
        else:
            pk.append((t + 0.001, eth(IP(src=target, dst=attacker) / TCP(sport=port, dport=sp, flags="RA", seq=0, ack=1001))))
    return pk


def syn_flood():
    pk = background(60)
    target = "192.168.1.10"
    t = T0 + 20
    for _ in range(1500):
        t += 0.002
        src = f"{random.randint(11, 220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        pk.append((t, eth(IP(src=src, dst=target) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=random.randint(1, 2**31)))))
    return pk


def ssh_bruteforce():
    pk = background(120)
    attacker, target = "198.51.100.23", "192.168.1.15"
    t = T0 + 10
    for _ in range(80):   # 80 short login attempts, ~1 per second
        pk += tcp_session(t, attacker, random.randint(40000, 60000), target, 22, up=320, down=180, rtt=0.05)
        t += random.uniform(0.8, 1.3)
    return pk


def c2_beaconing():
    pk = background(480)
    victim, c2 = "192.168.1.30", "45.33.32.156"
    t = T0 + 5
    for _ in range(16):   # every 30 s (+/- 0.5 s) for 8 minutes
        pk += tcp_session(t, victim, random.randint(40000, 60000), c2, 8443, up=220, down=90, rtt=0.12)
        t += 30 + random.uniform(-0.5, 0.5)
    return pk


def dns_tunneling():
    pk = background(180)
    victim = "192.168.1.35"
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    t = T0 + 15
    for i in range(120):   # data smuggled out inside long random sub-domain labels
        label = "".join(random.choice(alphabet) for _ in range(58))
        name = f"{label}.{i:04d}.t.exfil-cdn.xyz"
        pk += dns_lookup(t, victim, name, "10.0.0.1")
        t += random.uniform(0.3, 1.2)
    return pk


def data_exfiltration():
    pk = background(120)
    insider, dropbox = "192.168.1.40", "185.199.108.153"
    # one long upload of ~60 MB to an external host (stored truncated, so the file stays small)
    pk += tcp_session(T0 + 20, insider, 51515, dropbox, 443, up=60_000_000, down=2000, rtt=0.08, mss=1460)
    return pk


def udp_icmp_flood():
    pk = background(60)
    target = "192.168.1.10"
    t = T0 + 10
    for _ in range(2000):   # UDP flood on NTP
        t += 0.002
        src = f"198.51.100.{random.randint(1, 254)}"
        pk.append((t, eth(IP(src=src, dst=target) / UDP(sport=random.randint(1024, 65535), dport=123) / Raw(b"\x00" * 48))))
    t = T0 + 25
    for _ in range(600):    # ICMP echo flood
        t += 0.005
        src = f"203.0.113.{random.randint(1, 254)}"
        pk.append((t, eth(IP(src=src, dst=target) / ICMP(type=8, id=1, seq=random.randint(0, 65535)) / Raw(b"p" * 56))))
    return pk


def network_sweep():
    pk = background(120)
    scanner = "192.168.1.77"
    t = T0 + 20
    for host in range(2, 80):      # ping sweep of the /24
        if f"192.168.1.{host}" == scanner:
            continue
        t += 0.02
        dst = f"192.168.1.{host}"
        pk.append((t, eth(IP(src=scanner, dst=dst) / ICMP(type=8, id=7, seq=host))))
        if host % 5 == 0:
            pk.append((t + 0.001, eth(IP(src=dst, dst=scanner) / ICMP(type=0, id=7, seq=host))))
    t = T0 + 40
    for host in range(2, 80):      # SMB (445) sweep: the worm / ransomware pattern
        if f"192.168.1.{host}" == scanner:
            continue
        t += 0.02
        dst = f"192.168.1.{host}"
        sp = random.randint(40000, 60000)
        pk.append((t, eth(IP(src=scanner, dst=dst) / TCP(sport=sp, dport=445, flags="S", seq=1))))
        pk.append((t + 0.001, eth(IP(src=dst, dst=scanner) / TCP(sport=445, dport=sp, flags="RA", ack=2))))
    return pk


def backdoor_and_cleartext():
    pk = background(120)
    victim = "192.168.1.50"
    # reverse shell to the Metasploit default port
    pk += tcp_session(T0 + 15, victim, 49872, "203.0.113.99", 4444, up=15000, down=4000, rtt=0.1)
    # Telnet and FTP logins (credentials in clear text)
    pk += tcp_session(T0 + 40, "192.168.1.24", 50111, "192.168.1.5", 23, up=400, down=900)
    pk += tcp_session(T0 + 55, "192.168.1.24", 50112, "192.168.1.6", 21, up=300, down=700)
    return pk


if __name__ == "__main__":
    print("Writing CyberGuard NIDS test captures:")
    write_pcap("01_normal_traffic_generated.pcap", normal_traffic())
    write_pcap("02_port_scan.pcap", port_scan())
    write_pcap("03_syn_flood.pcap", syn_flood())
    write_pcap("04_ssh_bruteforce.pcap", ssh_bruteforce())
    write_pcap("05_c2_beaconing.pcap", c2_beaconing())
    write_pcap("06_dns_tunneling.pcap", dns_tunneling())
    write_pcap("07_data_exfiltration.pcap", data_exfiltration(), snaplen=80)  # headers only, keeps the file small
    write_pcap("08_udp_icmp_flood.pcap", udp_icmp_flood())
    write_pcap("09_network_sweep.pcap", network_sweep())
    write_pcap("10_backdoor_cleartext.pcap", backdoor_and_cleartext())
