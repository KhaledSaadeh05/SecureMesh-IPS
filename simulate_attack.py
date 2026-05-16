"""
simulate_attack.py -- SecureMesh IPS v3 OOP Edition (Slim)
AttackSimulator class — sends spoofed packets to test the IPS.

Usage:
  sudo python3 simulate_attack.py --iface eth0
  sudo python3 simulate_attack.py --iface eth0 --all-tests
  sudo python3 simulate_attack.py --iface eth0 --ip 192.0.2.123
"""

import argparse
import time
import os
import sys


class AttackSimulator:
    """
    Sends fake packets with spoofed source IPs to test the IPS.
    ENCAPSULATION: _iface, _target_ip, _test_ips all private.
    """

    BLOCKLIST_FILE = "malicious_ips.txt"

    def __init__(self, iface: str, target_ip: str = "192.168.1.1"):
        if iface.startswith("lo"):
            print("[!] Do not use loopback. Use eth0, wlan0 etc.")
            sys.exit(1)
        self._iface     = iface       # private
        self._target_ip = target_ip  # private
        self._test_ips  = []         # private

    def load_ips_from_file(self, path=None):
        path = path or self.BLOCKLIST_FILE
        if not os.path.exists(path):
            print(f"[!] File not found: {path}")
            sys.exit(1)
        with open(path, "r") as f:
            self._test_ips = [l.strip() for l in f
                              if l.strip() and not l.strip().startswith("#")]

    def set_single_ip(self, ip: str):
        self._test_ips = [ip]

    def _disable_rp_filter(self):
        os.system(f"sysctl -w net.ipv4.conf.{self._iface}.rp_filter=0 > /dev/null 2>&1")
        os.system("sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null 2>&1")
        print("[+] rp_filter disabled.")

    def _send_tcp(self, src_ip, count=5):
        import scapy.config; scapy.config.conf.ipv6_enabled=False
        from scapy.layers.inet import IP, TCP
        from scapy.sendrecv import send
        for _ in range(count):
            send(IP(src=src_ip, dst=self._target_ip) /
                 TCP(sport=12345, dport=80, flags="S"),
                 iface=self._iface, verbose=False)
        print(f"[SENT] {count}x TCP SYN from {src_ip}")

    def _send_icmp(self, src_ip):
        import scapy.config; scapy.config.conf.ipv6_enabled=False
        from scapy.layers.inet import IP, ICMP
        from scapy.sendrecv import send
        send(IP(src=src_ip, dst=self._target_ip) / ICMP(),
             iface=self._iface, verbose=False)
        print(f"[SENT] ICMP from {src_ip}")

    def _send_brute_force(self, src_ip, port=22):
        import scapy.config; scapy.config.conf.ipv6_enabled=False
        from scapy.layers.inet import IP, TCP
        from scapy.sendrecv import send
        print(f"[*] Brute force from {src_ip} -> port {port}...")
        for i in range(15):
            send(IP(src=src_ip, dst=self._target_ip) /
                 TCP(sport=i+1000, dport=port, flags="S"),
                 iface=self._iface, verbose=False)
            time.sleep(0.2)
        print(f"[+] Brute force done for {src_ip}")

    def _send_port_scan(self, src_ip):
        import scapy.config; scapy.config.conf.ipv6_enabled=False
        from scapy.layers.inet import IP, TCP
        from scapy.sendrecv import send
        print(f"[*] Port scan from {src_ip}...")
        for port in [21, 22, 23, 25, 80, 443, 3306, 8080, 8443, 9090]:
            send(IP(src=src_ip, dst=self._target_ip) /
                 TCP(sport=12345, dport=port, flags="S"),
                 iface=self._iface, verbose=False)
            time.sleep(0.1)
        print(f"[+] Port scan done for {src_ip}")

    def _send_malicious_port(self, src_ip):
        import scapy.config; scapy.config.conf.ipv6_enabled=False
        from scapy.layers.inet import IP, TCP
        from scapy.sendrecv import send
        send(IP(src=src_ip, dst=self._target_ip) /
             TCP(sport=12345, dport=4444, flags="S"),
             iface=self._iface, verbose=False)
        print(f"[SENT] Malicious port 4444 from {src_ip}")

    def run(self, all_tests=False, count=3):
        self._disable_rp_filter()
        print(f"\n[*] Testing {len(self._test_ips)} IP(s)...")
        input("\nPress ENTER when the IPS is running and ready...\n")
        for ip in self._test_ips:
            print(f"\n{'■'*50}\n  Testing IP: {ip}\n{'■'*50}")
            if all_tests:
                self._send_tcp(ip, count=5);        time.sleep(0.3)
                self._send_icmp(ip);                time.sleep(0.3)
                self._send_malicious_port(ip);      time.sleep(0.3)
                self._send_brute_force(ip);         time.sleep(0.3)
                self._send_port_scan(ip)
            else:
                self._send_tcp(ip, count=3);        time.sleep(1)
        print("\n" + "="*60)
        print("  Simulation complete. Open http://127.0.0.1:5000")
        print("="*60)


def main():
    parser = argparse.ArgumentParser(description="SecureMesh IPS v3 -- Attack Simulation")
    parser.add_argument("--iface",     required=True)
    parser.add_argument("--count",     type=int, default=3)
    parser.add_argument("--ip",        help="Test a single IP")
    parser.add_argument("--target",    default="192.168.1.1")
    parser.add_argument("--all-tests", action="store_true")
    args = parser.parse_args()

    print("="*60)
    print("  SecureMesh IPS v3 OOP -- Attack Simulation")
    print("="*60)
    print(f"  Interface : {args.iface}")
    print(f"  Target IP : {args.target}")
    print("="*60)

    sim = AttackSimulator(iface=args.iface, target_ip=args.target)
    if args.ip:
        sim.set_single_ip(args.ip)
    else:
        sim.load_ips_from_file()

    sim.run(all_tests=args.all_tests, count=args.count)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Must run as root: sudo python3 simulate_attack.py --iface eth0")
        sys.exit(1)
    main()
