"""
main.py -- SecureMesh IPS v3 OOP Edition (Slim)
Entry point. Wires all components together.

Usage:
  sudo python3 main.py --iface eth0 --dashboard
  sudo python3 main.py --iface eth0 --passive
  sudo python3 main.py --iface eth0 --dashboard --syslog
"""

import os
import sys
import argparse
import threading

from ips_core import (
    IPDatabase, AlertLogger, SyslogLogger,
    TCPRSTInjector, PacketAnalyzer, Sniffer, PreflightChecker
)
from dashboard import Dashboard


class SecureMeshIPS:
    """
    Top-level orchestrator. Wires all components together.

    COMPOSITION: contains all other objects (has-a).
    ENCAPSULATION: all components private.
    """

    def __init__(self, args):
        self._iface = args.iface or "eth0"

        # Build all components
        self._db           = IPDatabase()
        self._alert_logger = AlertLogger()
        self._syslog       = SyslogLogger()
        self._injector     = TCPRSTInjector(iface=self._iface)
        self._analyzer     = PacketAnalyzer(
            db=self._db,
            injector=self._injector,
            alert_logger=self._alert_logger,
            syslog_logger=self._syslog,
        )
        self._sniffer   = Sniffer(
            analyzer=self._analyzer,
            iface=self._iface,
            force_passive=args.passive,
        )
        self._dashboard = Dashboard(
            analyzer=self._analyzer,
            ip_db=self._db,
            iface=self._iface,
        )
        self._preflight = PreflightChecker(iface=self._iface, db=self._db)
        self._args      = args

    def _print_banner(self):
        stats = self._db.get_stats()
        print("=" * 60)
        print(" SecureMesh IPS v3 OOP Edition -- Starting")
        print("=" * 60)
        print(f"  Interface : {self._iface}")
        print(f"  Mode      : {'Passive' if self._args.passive else 'NFQueue'}")
        print(f"  Dashboard : {'http://127.0.0.1:5000' if self._args.dashboard else 'off'}")
        print(f"  Blacklist : {stats['blacklist']} IP(s)")
        print(f"  Detectors : {len(self._analyzer.list_detectors())}")
        print("=" * 60)

    def start(self):
        self._iface = self._preflight.run()
        self._injector.set_iface(self._iface)
        self._sniffer._iface = self._iface

        if self._args.syslog:
            self._syslog.setup()

        self._print_banner()

        if self._args.dashboard:
            print("[*] Dashboard -> http://127.0.0.1:5000  (admin / securemesh)")
            threading.Thread(target=self._dashboard.start, daemon=True).start()

        self._sniffer.start()


def main():
    if os.name == "nt":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Must run as Administrator.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("[!] Must be root. Use: sudo python3 main.py")
            sys.exit(1)

    parser = argparse.ArgumentParser(description="SecureMesh IPS v3 OOP")
    parser.add_argument("--iface",     default=os.environ.get("SECUREMESH_IFACE", "eth0"))
    parser.add_argument("--dashboard", action="store_true")
    parser.add_argument("--passive",   action="store_true")
    parser.add_argument("--syslog",    action="store_true")
    args = parser.parse_args()

    SecureMeshIPS(args).start()


if __name__ == "__main__":
    main()
