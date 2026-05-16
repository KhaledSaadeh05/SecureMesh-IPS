"""
ips_core.py -- SecureMesh IPS v3 OOP Edition (Slim)
All core classes in one file.

OOP CONCEPTS:
  Encapsulation  -- All internal state hidden as private (_prefix) attributes.
                    Public interface is clean methods only.
  Inheritance    -- Detector classes share abstract base classes.
                    Loggers share BaseLogger. Injector has BaseInjector.
  Polymorphism   -- PacketAnalyzer calls detect() on every detector in a list
                    without knowing the specific type. Each handles its own logic.
  Composition    -- PacketAnalyzer CONTAINS detectors, injector, logger, db (has-a).

CLASS HIERARCHY:
  BaseDetector (abstract)
    ├── BlacklistDetector           Stage 2
    ├── BaseFloodDetector (abstract)
    │     ├── SYNFloodDetector      Stage 5
    │     └── ICMPFloodDetector     Stage 6
    ├── BaseImmediateBlockDetector (abstract)
    │     ├── MaliciousPortDetector Stage 7
    │     ├── BruteForceDetector    Stage 8
    │     └── PayloadDetector       Stage 9
    └── IOCScoringDetector          Stage 10

  BaseLogger (abstract)
    ├── AlertLogger
    └── SyslogLogger

  BaseInjector (abstract)
    └── TCPRSTInjector

  IPDatabase
  PacketAnalyzer   (composes all of the above)
  Sniffer          (composes PacketAnalyzer)
  PreflightChecker
"""

# ── Standard library ──────────────────────────────────────────────────────────
import os
import sys
import socket
import sqlite3
import logging
import logging.handlers
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ── Third-party ───────────────────────────────────────────────────────────────
import pandas as pd

# Import scapy surgically to avoid IPv6 route loader crash on some Linux configs
import scapy.config
scapy.config.conf.ipv6_enabled = False   # IPS only needs IPv4
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.packet import Raw
from scapy.sendrecv import send, sniff


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DetectionResult:
    """
    Returned by every detector's detect() method.
    Encapsulates the block/accept decision and why.
    """
    should_block: bool
    reason:       str = ""
    score:        int = 0
    action:       str = ""


@dataclass
class PacketStats:
    """
    Per-IP mutable state tracked across packets.
    ENCAPSULATION: reset() wipes all state cleanly after a block event.
    """
    count:            int            = 0
    score:            int            = 0
    ports:            set            = field(default_factory=set)
    reasons:          list           = field(default_factory=list)
    syn_times:        list           = field(default_factory=list)
    icmp_times:       list           = field(default_factory=list)
    rate_scored:      bool           = False
    scan_scored:      bool           = False
    activity_scored:  bool           = False
    syn_scored:       bool           = False
    icmp_scored:      bool           = False
    last_seen:        Optional[datetime] = None

    def reset(self):
        self.count = 0; self.score = 0; self.ports = set()
        self.reasons = []; self.syn_times = []; self.icmp_times = []
        self.rate_scored = False; self.scan_scored = False
        self.activity_scored = False; self.syn_scored = False
        self.icmp_scored = False

    def add_reason(self, reason: str):
        if reason not in self.reasons:
            self.reasons.append(reason)


# ══════════════════════════════════════════════════════════════════════════════
# ABSTRACT BASE CLASSES
# ══════════════════════════════════════════════════════════════════════════════

class BaseDetector(ABC):
    """
    Abstract base for all detection stages.
    ENCAPSULATION: _name, _enabled are private.
    INHERITANCE:   All detector classes inherit from here.
    """
    def __init__(self, name: str, enabled: bool = True):
        self._name    = name       # private
        self._enabled = enabled    # private

    @property
    def name(self) -> str:
        return self._name

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self):
        self._enabled = True

    def disable(self):
        self._enabled = False

    @abstractmethod
    def detect(self, packet, stats: PacketStats, window_size: int) -> DetectionResult:
        pass

    def __repr__(self):
        return f"<{self.__class__.__name__} '{self._name}' {'ON' if self._enabled else 'OFF'}>"


class BaseFloodDetector(BaseDetector):
    """
    Shared parent for SYN and ICMP flood detectors.
    INHERITANCE: Both flood detectors inherit _limit, _time_window, _ioc_score
                 and the shared helper methods from here.
    ENCAPSULATION: All thresholds private.
    """
    def __init__(self, name: str, limit: int, time_window: int, ioc_score: int):
        super().__init__(name)
        self._limit       = limit        # private
        self._time_window = time_window  # private
        self._ioc_score   = ioc_score    # private

    def _evict_old(self, times: list, now: datetime) -> list:
        return [t for t in times if (now - t).total_seconds() <= self._time_window]

    def _is_flood(self, times: list) -> bool:
        return len(times) > self._limit

    @abstractmethod
    def detect(self, packet, stats: PacketStats, window_size: int) -> DetectionResult:
        pass


class BaseImmediateBlockDetector(BaseDetector):
    """
    Shared parent for detectors that block INSTANTLY (no score threshold).
    INHERITANCE: MaliciousPort, BruteForce, Payload inherit _make_block_result().
    ENCAPSULATION: _ioc_score private.
    """
    def __init__(self, name: str, ioc_score: int):
        super().__init__(name)
        self._ioc_score = ioc_score   # private

    def _make_block_result(self, reason: str) -> DetectionResult:
        return DetectionResult(
            should_block=True,
            reason=reason,
            score=self._ioc_score,
            action="TCP RST + Kernel DROP"
        )

    @abstractmethod
    def detect(self, packet, stats: PacketStats, window_size: int) -> DetectionResult:
        pass


class BaseLogger(ABC):
    """
    Abstract base for all alert loggers.
    INHERITANCE: AlertLogger and SyslogLogger inherit from here.
    ENCAPSULATION: _enabled private.
    """
    def __init__(self, enabled: bool = True):
        self._enabled = enabled  # private

    @property
    def enabled(self) -> bool:
        return self._enabled

    @abstractmethod
    def log(self, src_ip: str, dst_ip: str, port: int,
            detection: str, action: str, score: int):
        pass


class BaseInjector(ABC):
    """
    Abstract base for packet injection.
    INHERITANCE: TCPRSTInjector inherits from here.
    ENCAPSULATION: _iface private.
    """
    def __init__(self, iface: str = None):
        self._iface = iface   # private

    def set_iface(self, iface: str):
        self._iface = iface

    @property
    def iface(self) -> str:
        return self._iface

    @abstractmethod
    def inject(self, packet) -> bool:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# DETECTOR CLASSES  (Stages 2, 5, 6, 7, 8, 9, 10)
# ══════════════════════════════════════════════════════════════════════════════

class BlacklistDetector(BaseDetector):
    """
    Stage 2 — O(1) frozenset blacklist check.
    INHERITANCE: BaseDetector.
    ENCAPSULATION: _is_blacklisted_fn private (injected dependency).
    """
    def __init__(self, is_blacklisted_fn):
        super().__init__("BlacklistDetector")
        self._is_blacklisted_fn = is_blacklisted_fn   # private

    def detect(self, packet, stats: PacketStats, window_size: int) -> DetectionResult:
        if IP not in packet:
            return DetectionResult(should_block=False)
        if self._is_blacklisted_fn(packet[IP].src):
            return DetectionResult(
                should_block=True, reason="Blacklisted IP",
                score=999, action="TCP RST + Kernel DROP"
            )
        return DetectionResult(should_block=False)


class SYNFloodDetector(BaseFloodDetector):
    """
    Stage 5 — SYN flood: too many TCP SYN packets.
    INHERITANCE: BaseFloodDetector → BaseDetector.
    Shares _evict_old() and _is_flood() with ICMPFloodDetector.
    """
    def __init__(self, limit=50, time_window=60, ioc_score=25):
        super().__init__("SYNFloodDetector", limit, time_window, ioc_score)

    def detect(self, packet, stats: PacketStats, window_size: int) -> DetectionResult:
        if TCP not in packet or packet[TCP].flags != "S":
            return DetectionResult(should_block=False)
        now = datetime.now()
        stats.syn_times.append(now)
        stats.syn_times = self._evict_old(stats.syn_times, now)
        if self._is_flood(stats.syn_times) and not stats.syn_scored:
            stats.syn_scored = True
            stats.score += self._ioc_score
            stats.add_reason("SYN Flood")
        return DetectionResult(should_block=False)


class ICMPFloodDetector(BaseFloodDetector):
    """
    Stage 6 — ICMP flood: too many ping packets.
    INHERITANCE: BaseFloodDetector → BaseDetector.
    Same parent as SYNFloodDetector — differs only in packet type tracked.
    """
    def __init__(self, limit=100, time_window=60, ioc_score=20):
        super().__init__("ICMPFloodDetector", limit, time_window, ioc_score)

    def detect(self, packet, stats: PacketStats, window_size: int) -> DetectionResult:
        if ICMP not in packet:
            return DetectionResult(should_block=False)
        now = datetime.now()
        stats.icmp_times.append(now)
        stats.icmp_times = self._evict_old(stats.icmp_times, now)
        if self._is_flood(stats.icmp_times) and not stats.icmp_scored:
            stats.icmp_scored = True
            stats.score += self._ioc_score
            stats.add_reason("ICMP Flood")
        return DetectionResult(should_block=False)


class MaliciousPortDetector(BaseImmediateBlockDetector):
    """
    Stage 7 — Known backdoor/C2 port access. IMMEDIATE block.
    INHERITANCE: BaseImmediateBlockDetector → BaseDetector.
    ENCAPSULATION: _malicious_ports private frozenset.
    """
    DEFAULT_PORTS = frozenset([4444, 5555, 6666, 31337, 1337, 9999])

    def __init__(self, ports=None, ioc_score=25):
        super().__init__("MaliciousPortDetector", ioc_score)
        self._malicious_ports = ports if ports is not None else self.DEFAULT_PORTS  # private

    def detect(self, packet, stats: PacketStats, window_size: int) -> DetectionResult:
        if TCP not in packet:
            return DetectionResult(should_block=False)
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        hit   = dport if dport in self._malicious_ports else \
                sport if sport in self._malicious_ports else None
        if hit:
            reason = f"Malicious port access (port {hit})"
            stats.score += self._ioc_score
            stats.add_reason(reason)
            return self._make_block_result(reason)
        return DetectionResult(should_block=False)


class BruteForceDetector(BaseImmediateBlockDetector):
    """
    Stage 8 — Repeated connection attempts to same port. IMMEDIATE block.
    INHERITANCE: BaseImmediateBlockDetector → BaseDetector.
    ENCAPSULATION: _limit, _window, _tracker, _tracker_lock all private.
    """
    def __init__(self, limit=10, window=30, ioc_score=30):
        super().__init__("BruteForceDetector", ioc_score)
        self._limit        = limit    # private
        self._window       = window   # private
        self._tracker      = defaultdict(lambda: {"count": 0, "time": datetime.now()})
        self._tracker_lock = threading.Lock()

    def _cleanup(self):
        now = datetime.now()
        with self._tracker_lock:
            dead = [k for k, v in list(self._tracker.items())
                    if (now - v["time"]).total_seconds() > self._window * 2]
            for k in dead:
                del self._tracker[k]

    def detect(self, packet, stats: PacketStats, window_size: int) -> DetectionResult:
        if TCP not in packet:
            return DetectionResult(should_block=False)
        self._cleanup()
        src_ip = packet[IP].src
        dport  = packet[TCP].dport
        now    = datetime.now()
        triggered = False
        bf_count  = 0
        with self._tracker_lock:
            bf = self._tracker[(src_ip, dport)]
            if (now - bf["time"]).total_seconds() > self._window:
                bf["count"] = 0
                bf["time"]  = now
            bf["count"] += 1
            if bf["count"] > self._limit:
                triggered = True
                bf_count  = bf["count"]
                bf["count"] = 0
                bf["time"]  = now
        if triggered:
            reason = f"Brute Force on port {dport} ({bf_count} attempts in {self._window}s)"
            stats.score += self._ioc_score
            stats.add_reason(reason)
            return self._make_block_result(reason)
        return DetectionResult(should_block=False)


class PayloadDetector(BaseImmediateBlockDetector):
    """
    Stage 9 — Malicious strings in packet payload. IMMEDIATE block.
    INHERITANCE: BaseImmediateBlockDetector → BaseDetector.
    ENCAPSULATION: _signatures private list.
    """
    DEFAULT_SIGNATURES = [
        b"/bin/sh", b"/bin/bash", b"cmd.exe", b"powershell",
        b"wget http", b"curl http", b"nmap", b"metasploit",
        b"meterpreter", b"\x90\x90\x90\x90",
    ]

    def __init__(self, signatures=None, ioc_score=35):
        super().__init__("PayloadDetector", ioc_score)
        self._signatures = signatures if signatures is not None else self.DEFAULT_SIGNATURES[:]  # private

    def detect(self, packet, stats: PacketStats, window_size: int) -> DetectionResult:
        if Raw not in packet:
            return DetectionResult(should_block=False)
        payload = bytes(packet[Raw].load)
        for sig in self._signatures:
            if sig in payload:
                reason = f"Malicious payload: {sig.decode('utf-8', errors='replace')}"
                stats.score += self._ioc_score
                stats.add_reason(reason)
                return self._make_block_result(reason)
        return DetectionResult(should_block=False)


class IOCScoringDetector(BaseDetector):
    """
    Stage 10 — Accumulates IOC scores. Blocks when total >= threshold.
    INHERITANCE: BaseDetector directly.
    ENCAPSULATION: All thresholds private.
    """
    def __init__(self, alert_threshold=60, ioc_packet_rate=15,
                 ioc_port_scan=20, ioc_repeat=10,
                 packet_rate_limit=10, port_scan_limit=5, activity_limit=20):
        super().__init__("IOCScoringDetector")
        self._alert_threshold   = alert_threshold    # private
        self._ioc_packet_rate   = ioc_packet_rate    # private
        self._ioc_port_scan     = ioc_port_scan      # private
        self._ioc_repeat        = ioc_repeat         # private
        self._packet_rate_limit = packet_rate_limit  # private
        self._port_scan_limit   = port_scan_limit    # private
        self._activity_limit    = activity_limit     # private

    def set_threshold(self, value: int):
        self._alert_threshold = value
        print(f"[IOC] Alert threshold updated to {value}")

    def detect(self, packet, stats: PacketStats, window_size: int) -> DetectionResult:
        stats.count += 1
        if TCP in packet:
            stats.ports.add(packet[TCP].dport)

        if stats.count > self._packet_rate_limit and not stats.rate_scored:
            stats.score += self._ioc_packet_rate
            stats.rate_scored = True
            stats.add_reason("High packet rate")

        if len(stats.ports) > self._port_scan_limit and not stats.scan_scored:
            stats.score += self._ioc_port_scan
            stats.scan_scored = True
            stats.add_reason("Port scanning behavior")

        if window_size > self._activity_limit and not stats.activity_scored:
            stats.score += self._ioc_repeat
            stats.activity_scored = True
            stats.add_reason("Repeated activity in short time")

        if stats.score >= self._alert_threshold:
            return DetectionResult(
                should_block=True,
                reason=", ".join(set(stats.reasons)),
                score=stats.score,
                action="TCP RST + Kernel DROP"
            )
        return DetectionResult(should_block=False)


# ══════════════════════════════════════════════════════════════════════════════
# TCP RST INJECTOR
# ══════════════════════════════════════════════════════════════════════════════

class TCPRSTInjector(BaseInjector):
    """
    Forges TCP RST+ACK to terminate attacker connections.
    INHERITANCE: BaseInjector.
    ENCAPSULATION: _iface private (inherited). Injection logic hidden.
    """
    def __init__(self, iface: str = None):
        super().__init__(iface)

    def inject(self, packet) -> bool:
        try:
            if TCP not in packet:
                return False
            rst = (
                IP(src=packet[IP].dst, dst=packet[IP].src) /
                TCP(
                    sport=packet[TCP].dport,
                    dport=packet[TCP].sport,
                    flags="RA",
                    seq=packet[TCP].ack,
                    ack=packet[TCP].seq + 1,
                )
            )
            send(rst, iface=self._iface, verbose=False)
            print(f"[IPS ACTION] TCP RST+ACK -> {packet[IP].src}:{packet[TCP].sport}")
            return True
        except Exception as e:
            print(f"[IPS WARNING] RST failed: {e}")
            return False


# ══════════════════════════════════════════════════════════════════════════════
# LOGGERS  (plain text — no encryption)
# ══════════════════════════════════════════════════════════════════════════════

class AlertLogger(BaseLogger):
    """
    Writes alerts to plain text log file + SQLite database.
    INHERITANCE: BaseLogger.
    ENCAPSULATION: _log_file, _db_file, _max_log_bytes private.
    NOTE: Logs are plain text — no encryption.
    """
    def __init__(self, log_file="alerts.log", db_file="alerts.db",
                 max_log_bytes=10*1024*1024):
        super().__init__(enabled=True)
        self._log_file      = log_file          # private
        self._db_file       = db_file           # private
        self._max_log_bytes = max_log_bytes     # private
        self._init_db()

    def _init_db(self):
        try:
            con = sqlite3.connect(self._db_file)
            con.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        TEXT,
                    src_ip    TEXT,
                    dst_ip    TEXT,
                    port      INTEGER,
                    detection TEXT,
                    action    TEXT,
                    score     INTEGER
                )
            """)
            con.commit()
            con.close()
        except Exception as e:
            print(f"[DB] Init error: {e}")

    def _rotate_if_needed(self):
        try:
            if os.path.exists(self._log_file) and \
               os.path.getsize(self._log_file) >= self._max_log_bytes:
                os.replace(self._log_file, self._log_file + ".1")
                print("[IPS] Log rotated.")
        except OSError as e:
            print(f"[!] Log rotation failed: {e}")

    def _save_db(self, src_ip, dst_ip, port, detection, action, score):
        try:
            con = sqlite3.connect(self._db_file, timeout=5)
            con.execute(
                "INSERT INTO alerts(ts,src_ip,dst_ip,port,detection,action,score) "
                "VALUES(?,?,?,?,?,?,?)",
                (datetime.now().isoformat(), src_ip, dst_ip,
                 port, detection, action, score),
            )
            con.commit()
            con.close()
        except Exception as e:
            print(f"[DB] Write error: {e}")

    def log(self, src_ip, dst_ip, port, detection, action, score):
        if not self._enabled:
            return
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_text = (
            f"\nALERT DETECTED\n{'='*30}\n"
            f"Time: {ts}\nSource IP: {src_ip}\nDest IP: {dst_ip}\n"
            f"Port: {port}\nDetection: {detection}\n"
            f"Action: {action}\nScore: {score}\n"
        )
        self._rotate_if_needed()
        with open(self._log_file, "a") as f:
            f.write(alert_text)
        self._save_db(src_ip, dst_ip, port, detection, action, score)
        print(f"[IPS ALERT] {src_ip} | {detection} | {action}")

    @property
    def db_file(self):
        return self._db_file


class SyslogLogger(BaseLogger):
    """
    Optional syslog export.
    INHERITANCE: BaseLogger.
    ENCAPSULATION: _handler private.
    """
    def __init__(self):
        super().__init__(enabled=False)
        self._handler = None   # private

    def setup(self):
        try:
            h = logging.handlers.SysLogHandler(address="/dev/log")
            h.setFormatter(logging.Formatter("SecureMeshIPS: %(message)s"))
            logging.getLogger("securemesh").addHandler(h)
            self._handler = h
            self._enabled = True
            print("[IPS] Syslog export enabled.")
        except Exception as e:
            print(f"[IPS] Syslog setup failed: {e}")

    def log(self, src_ip, dst_ip, port, detection, action, score):
        if not self._enabled or not self._handler:
            return
        logging.getLogger("securemesh").warning(
            f"ALERT src={src_ip} | {detection} | {action}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# IP DATABASE
# ══════════════════════════════════════════════════════════════════════════════

class IPDatabase:
    """
    Stores blacklist + whitelist IPs.
    Two parallel structures:
      _blacklist_set -- frozenset for O(1) hot-path checks
      _df            -- pandas DataFrame for dashboard display

    ENCAPSULATION: All internals private. Public API is
    is_blacklisted(), record_ip(), get_blacklist(), get_whitelist(), get_stats().
    """
    def __init__(self, blocklist_file="malicious_ips.txt", reload_interval=300):
        self._blocklist_file  = blocklist_file    # private
        self._reload_interval = reload_interval   # private
        self._lock            = threading.Lock()  # private
        self._reload_time     = 0.0               # private
        self._blacklist_set   = frozenset()       # private — fast path
        self._df              = pd.DataFrame(     # private — dashboard
            columns=["ip","status","first_seen","last_seen","hit_count","source"]
        )
        self._init()

    def _read_file(self) -> list:
        if not os.path.exists(self._blocklist_file):
            print(f"[DB] Warning: {self._blocklist_file} not found -- blacklist empty.")
            return []
        with open(self._blocklist_file, "r") as f:
            return [l.strip() for l in f
                    if l.strip() and not l.strip().startswith("#")]

    def _init(self):
        ips = self._read_file()
        now = datetime.now()
        rows = [{"ip": ip, "status": "blacklist", "first_seen": now,
                 "last_seen": now, "hit_count": 0, "source": "file"} for ip in ips]
        self._df = pd.DataFrame(rows) if rows else pd.DataFrame(
            columns=["ip","status","first_seen","last_seen","hit_count","source"])
        self._blacklist_set = frozenset(ips)
        self._reload_time   = time.time()
        print(f"[DB] Initialised -- {len(self._blacklist_set)} blacklisted IP(s) loaded.")

    def _reload_if_needed(self):
        if time.time() - self._reload_time < self._reload_interval:
            return
        new_ips  = self._read_file()
        now      = datetime.now()
        existing = set(self._df["ip"].values) if not self._df.empty else set()
        new_rows = []
        for ip in new_ips:
            if ip not in existing:
                new_rows.append({"ip": ip, "status": "blacklist",
                                 "first_seen": now, "last_seen": now,
                                 "hit_count": 0, "source": "file"})
            else:
                self._df.loc[self._df["ip"] == ip, "status"] = "blacklist"
        if new_rows:
            self._df = pd.concat([self._df, pd.DataFrame(new_rows)], ignore_index=True)
        self._blacklist_set = frozenset(
            self._df.loc[self._df["status"] == "blacklist", "ip"].values)
        self._reload_time = time.time()
        if new_rows:
            print(f"[DB] Reloaded -- {len(new_rows)} new IP(s) added.")

    # ── Public API ─────────────────────────────────────────────────────────
    def is_blacklisted(self, ip: str) -> bool:
        """O(1) check. Called on EVERY packet — must be instant."""
        return ip in self._blacklist_set

    def record_ip(self, ip: str, is_malicious: bool = False):
        with self._lock:
            self._reload_if_needed()
            now   = datetime.now()
            match = self._df[self._df["ip"] == ip]
            if not match.empty:
                idx = match.index[0]
                self._df.at[idx, "last_seen"]  = now
                self._df.at[idx, "hit_count"] += 1
                if is_malicious and self._df.at[idx, "status"] != "blacklist":
                    self._df.at[idx, "status"] = "blacklist"
                    self._blacklist_set = self._blacklist_set | {ip}
            else:
                new_row = pd.DataFrame([{
                    "ip": ip,
                    "status": "blacklist" if is_malicious else "whitelist",
                    "first_seen": now, "last_seen": now,
                    "hit_count": 1, "source": "auto",
                }])
                self._df = pd.concat([self._df, new_row], ignore_index=True)
                if is_malicious:
                    self._blacklist_set = self._blacklist_set | {ip}

    def get_blacklist(self, limit=200) -> pd.DataFrame:
        with self._lock:
            return self._df[self._df["status"] == "blacklist"].copy().head(limit)

    def get_whitelist(self, limit=200) -> pd.DataFrame:
        with self._lock:
            return self._df[self._df["status"] == "whitelist"].copy().head(limit)

    def get_stats(self) -> dict:
        with self._lock:
            total     = len(self._df)
            blacklist = int((self._df["status"] == "blacklist").sum()) if not self._df.empty else 0
            whitelist = int((self._df["status"] == "whitelist").sum()) if not self._df.empty else 0
        return {"total": total, "blacklist": blacklist, "whitelist": whitelist}


# ══════════════════════════════════════════════════════════════════════════════
# PACKET ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

class PacketAnalyzer:
    """
    Orchestrates the 10-stage detection pipeline.

    COMPOSITION (has-a):
      _db       -- IPDatabase
      _injector -- TCPRSTInjector
      _loggers  -- list of BaseLogger
      _detectors-- list of BaseDetector   ← POLYMORPHISM

    ENCAPSULATION: counters, stats, window, seen_ips all private.

    POLYMORPHISM: _run_detectors() calls detect() on every detector object
    in _detectors without knowing the specific class type.
    """
    def __init__(self, db: IPDatabase, injector: TCPRSTInjector,
                 alert_logger: AlertLogger, syslog_logger: SyslogLogger = None,
                 time_window: int = 60):
        # COMPOSITION
        self._db            = db
        self._injector      = injector
        self._alert_logger  = alert_logger
        self._syslog_logger = syslog_logger

        # ENCAPSULATION: private counters
        self._total_packets   = 0
        self._blocked_packets = 0
        self._counter_lock    = threading.Lock()

        # ENCAPSULATION: private state
        self._seen_ips      = set()
        self._seen_lock     = threading.Lock()
        self._ip_stats      = defaultdict(PacketStats)
        self._time_window   = time_window
        self._packet_window = deque()
        self._window_lock   = threading.Lock()

        # POLYMORPHISM: ordered list of BaseDetector objects
        self._detectors = [
            BlacklistDetector(is_blacklisted_fn=self._db.is_blacklisted),  # Stage 2
            SYNFloodDetector(),           # Stage 5
            ICMPFloodDetector(),          # Stage 6
            MaliciousPortDetector(),      # Stage 7
            BruteForceDetector(),         # Stage 8
            PayloadDetector(),            # Stage 9
            IOCScoringDetector(),         # Stage 10
        ]

    # ── Private helpers ────────────────────────────────────────────────────
    def _record_new_ip(self, src_ip: str):
        with self._seen_lock:
            if src_ip not in self._seen_ips:
                self._seen_ips.add(src_ip)
                threading.Thread(target=self._db.record_ip,
                                 args=(src_ip, False), daemon=True).start()

    def _update_window(self, now, src_ip) -> int:
        with self._window_lock:
            self._packet_window.append((now, src_ip))
            while (self._packet_window and
                   (now - self._packet_window[0][0]).total_seconds() > self._time_window):
                self._packet_window.popleft()
            return len(self._packet_window)

    def _handle_block(self, packet, result: DetectionResult, src_ip: str, stats: PacketStats):
        if TCP in packet:
            self._injector.inject(packet)
        threading.Thread(target=self._db.record_ip,
                         args=(src_ip, True), daemon=True).start()
        port = (packet[TCP].dport if TCP in packet else
                packet[UDP].dport if UDP in packet else 0)
        for logger in [l for l in [self._alert_logger, self._syslog_logger] if l and l.enabled]:
            logger.log(
                src_ip=packet[IP].src if IP in packet else "Unknown",
                dst_ip=packet[IP].dst if IP in packet else "Unknown",
                port=port, detection=result.reason,
                action=result.action or "TCP RST + Kernel DROP",
                score=result.score,
            )
        with self._counter_lock:
            self._blocked_packets += 1
        stats.reset()

    def _run_detectors(self, packet, stats, window_size):
        """
        POLYMORPHISM: calls detect() on each BaseDetector object.
        Stops at first detector that returns should_block=True.
        """
        for detector in self._detectors:
            if not detector.enabled:
                continue
            result = detector.detect(packet, stats, window_size)
            if result.should_block:
                return result
        return None

    # ── Public API ─────────────────────────────────────────────────────────
    def analyze_packet(self, packet) -> bool:
        """10-stage pipeline. Returns True=DROP, False=ACCEPT."""
        if IP not in packet:
            return False

        src_ip = packet[IP].src
        now    = datetime.now()

        with self._counter_lock:
            self._total_packets += 1

        self._record_new_ip(src_ip)
        window_size = self._update_window(now, src_ip)

        stats           = self._ip_stats[src_ip]
        stats.last_seen = now

        result = self._run_detectors(packet, stats, window_size)
        if result and result.should_block:
            self._handle_block(packet, result, src_ip, stats)
            return True

        return False

    def get_packet_stats(self) -> dict:
        with self._counter_lock:
            return {"total": self._total_packets, "blocked": self._blocked_packets}

    def list_detectors(self) -> list:
        return [(d.name, d.enabled) for d in self._detectors]


# ══════════════════════════════════════════════════════════════════════════════
# SNIFFER
# ══════════════════════════════════════════════════════════════════════════════

class Sniffer:
    """
    Captures live packets and passes each to PacketAnalyzer.
    Tries NFQueue (kernel drop) first. Falls back to passive Scapy sniff.

    ENCAPSULATION: _iface, _analyzer, _force_passive all private.
    COMPOSITION: has-a PacketAnalyzer (injected).
    """
    def __init__(self, analyzer: PacketAnalyzer, iface="eth0", force_passive=False):
        self._analyzer      = analyzer    # private
        self._iface         = iface if iface and not iface.startswith("lo") else "eth0"
        self._force_passive = force_passive

    def _nfqueue_callback(self, nfpacket):
        try:
            packet = IP(nfpacket.get_payload())
            if self._analyzer.analyze_packet(packet):
                nfpacket.drop()
            else:
                nfpacket.accept()
        except Exception as e:
            print(f"[NFQ] Parse error, accepting: {e}")
            try:
                nfpacket.accept()
            except Exception:
                pass

    def _try_nfqueue(self) -> bool:
        try:
            from netfilterqueue import NetfilterQueue
            nfq = NetfilterQueue()
            nfq.bind(0, self._nfqueue_callback)
            print("[IPS] NFQueue mode active -- kernel-level blocking enabled.")
            try:
                nfq.run()
            except KeyboardInterrupt:
                pass
            finally:
                nfq.unbind()
            return True
        except ImportError:
            print("[IPS] netfilterqueue not installed -- falling back to passive.")
            print("     Install: sudo pip3 install NetfilterQueue --break-system-packages")
            return False
        except Exception as e:
            print(f"[IPS] NFQueue failed ({e}) -- falling back to passive.")
            return False

    def _run_passive(self):
        print(f"[IPS] Passive sniff mode on: {self._iface}")
        sniff(iface=self._iface, prn=self._analyzer.analyze_packet,
              store=False, filter="ip")

    def start(self):
        """Start sniffing. Blocks until Ctrl+C."""
        if self._force_passive:
            self._run_passive()
            return
        if not self._try_nfqueue():
            self._run_passive()

    @property
    def iface(self):
        return self._iface


# ══════════════════════════════════════════════════════════════════════════════
# PREFLIGHT CHECKER
# ══════════════════════════════════════════════════════════════════════════════

class PreflightChecker:
    """
    Startup validation checks.
    ENCAPSULATION: _iface, _db private.
    """
    def __init__(self, iface: str, db: IPDatabase):
        self._iface = iface if iface and not iface.startswith("lo") else "eth0"
        self._db    = db

    def _check_root(self):
        if os.name != "nt" and os.geteuid() != 0:
            print("[!] Not root. Run with sudo.")
            sys.exit(1)

    def _check_raw_socket(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            s.close()
        except PermissionError:
            print("[!] Cannot open raw socket -- run as root")
            sys.exit(1)
        except (OSError, AttributeError):
            pass

    def _detect_iface(self) -> str:
        try:
            r = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True)
            p = r.stdout.split()
            if "dev" in p:
                return p[p.index("dev") + 1]
        except Exception:
            pass
        return None

    def _disable_rp_filter(self):
        print(f"[+] Disabling rp_filter on {self._iface}...")
        for key in [f"net.ipv4.conf.{self._iface}.rp_filter", "net.ipv4.conf.all.rp_filter"]:
            try:
                subprocess.run(["sysctl", "-w", f"{key}=0"],
                               capture_output=True, text=True)
            except FileNotFoundError:
                pass
        print("[+] rp_filter disabled.")

    def _check_nfqueue(self):
        try:
            r = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True)
            if "NFQUEUE" not in r.stdout:
                print("[!] No NFQUEUE iptables rules found. Run:")
                print(f"    sudo iptables -I INPUT   -i {self._iface} -j NFQUEUE --queue-num 0")
                print(f"    sudo iptables -I FORWARD -i {self._iface} -j NFQUEUE --queue-num 0")
            else:
                print("[+] NFQUEUE iptables rules found -- kernel blocking ready.")
        except Exception as e:
            print(f"[!] iptables check failed: {e}")

    def run(self) -> str:
        """Run all checks. Returns validated interface name."""
        print("[*] SecureMesh IPS v3 preflight checks...")
        self._check_root()
        self._check_raw_socket()
        if not self._iface or self._iface.startswith("lo"):
            detected = self._detect_iface()
            self._iface = detected if detected and not detected.startswith("lo") else "eth0"
        print(f"[+] {self._iface} is a real interface -- RST injection will use this NIC.")
        self._disable_rp_filter()
        self._check_nfqueue()
        stats = self._db.get_stats()
        print(f"[+] Blacklist: {stats['blacklist']} IP(s) | Whitelist: {stats['whitelist']} IP(s)")
        print("[+] Preflight complete.")
        print("-" * 60)
        return self._iface
