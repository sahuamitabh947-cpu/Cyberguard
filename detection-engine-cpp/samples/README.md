# Network IDS test captures

Upload any of these on the **Network IDS** page (Analyse capture file) or send them straight to the engine:

```bash
curl -X POST "http://localhost:5050/analyze/pcap?name=test.pcap" \
     -H "Content-Type: application/octet-stream" --data-binary @02_port_scan.pcap
```

Every attack capture also contains ordinary background traffic (HTTPS browsing + DNS lookups),
so the NIDS has to pick the attack out of normal activity. All IPs are private or reserved
documentation ranges.

| File | Scenario | Expected result |
|---|---|---|
| normal_traffic.pcap | Normal browsing | **Safe**, 0 alerts |
| 01_normal_traffic_generated.pcap | Normal browsing (60 HTTPS sessions + DNS) | **Safe**, 0 alerts |
| 02_port_scan.pcap | External host SYN-scans ports 1–1024 of one server | **High**: port_scan + ML probe / DoS / anomaly |
| 03_syn_flood.pcap | 1,500 SYNs from spoofed sources in 3 s | **Critical**: syn_flood + ML DoS |
| 04_ssh_bruteforce.pcap | 80 SSH login attempts in ~80 s | **High**: brute_force_suspected |
| 05_c2_beaconing.pcap | Infected PC calls an external server every 30 s | **High**: beaconing (C2) |
| 06_dns_tunneling.pcap | 120 DNS queries with long random sub-domains | **High**: dns_tunneling (exfiltration) |
| 07_data_exfiltration.pcap | Insider uploads ~60 MB to an external host | **High**: large_outbound_transfer + ML |
| 08_udp_icmp_flood.pcap | 2,000-packet UDP flood + 600-packet ICMP flood | **High**: udp_flood, icmp_flood + ML |
| 09_network_sweep.pcap | Ping sweep + SMB (445) sweep of the whole subnet | **High**: ping_sweep, host_sweep + ML probe |
| 10_backdoor_cleartext.pcap | Reverse shell to port 4444 + Telnet and FTP logins | **Medium**: suspicious_port, cleartext_protocol ×2 |
| attack_mix.pcap | Several attacks together | **Critical**: 9 alerts |

`07_data_exfiltration.pcap` stores packet headers only (like `tcpdump -s 80`), so the file is ~4 MB
while the capture represents a 60 MB upload; the engine reads true sizes from the IP headers.

## Regenerate or create your own

```bash
pip install scapy
python generate_samples.py
```

Edit a scenario function in `generate_samples.py` (IPs, counts, timing) to build new test cases.
You can also record real traffic with Wireshark (File → Save As → pcapng) and upload it.
