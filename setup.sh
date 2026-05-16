#!/bin/bash
# =============================================================================
# SecureMesh IPS v3 -- One-Command Setup Script
# Run: sudo bash setup.sh
# FIX (Deploy): awk interface detection changed from '/dev/{print $5}' to
#               '$4=="dev"{print $5}' -- the old pattern matched ANY line
#               containing the substring "dev" (e.g. lines with "device"
#               or version strings).  The new pattern requires that field 4
#               is exactly "dev", matching the ip-route output format:
#                 default via <gw> dev <iface> proto ...
# =============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }
ok()     { echo -e "  ${GREEN}[OK]${NC}  $1"; }
warn()   { echo -e "  ${YELLOW}[!!]${NC}  $1"; }
err()    { echo -e "  ${RED}[ERR]${NC} $1"; exit 1; }

echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║     SecureMesh IPS v3  Setup         ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

# ── Root check ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  err "Must run as root:  sudo bash setup.sh"
fi

# ── Detect interface ──────────────────────────────────────────────────────────
banner "Detecting network interface"

# FIX: use $4=="dev" (exact field match) instead of /dev/ (substring match)
# ip route output: "default via <gw> dev <iface> proto dhcp ..."
#                   $1       $2  $3  $4   $5
IFACE=$(ip route show default 2>/dev/null | awk '$4=="dev"{print $5}' | head -1)

if [ -z "$IFACE" ]; then
  warn "Could not auto-detect interface. Defaulting to wlan0"
  IFACE="wlan0"
fi

# Reject loopback
if [[ "$IFACE" == lo* ]]; then
  warn "Default route is on loopback -- forcing wlan0"
  IFACE="wlan0"
fi
ok "Interface: $IFACE"

# ── System packages ───────────────────────────────────────────────────────────
banner "Installing system packages"
apt-get update -qq
apt-get install -y -qq python3 python3-pip libnetfilter-queue-dev iptables
ok "System packages installed"

# ── Python packages ───────────────────────────────────────────────────────────
banner "Installing Python packages"
pip3 install -r requirements.txt --break-system-packages -q 2>&1 | tail -3
ok "Python packages installed"

# ── rp_filter disable ─────────────────────────────────────────────────────────
banner "Disabling rp_filter on $IFACE (required for spoofed-IP testing)"
sysctl -w net.ipv4.conf.${IFACE}.rp_filter=0 > /dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0       > /dev/null 2>&1 || true
ok "rp_filter disabled"

# ── iptables NFQueue rules -- interface-specific so only wlan0 traffic is intercepted ──
banner "Installing iptables NFQueue rules on $IFACE"
iptables -I INPUT   -i ${IFACE} -j NFQUEUE --queue-num 0 2>/dev/null || warn "INPUT rule already exists"
iptables -I FORWARD -i ${IFACE} -j NFQUEUE --queue-num 0 2>/dev/null || warn "FORWARD rule already exists"
# OUTPUT does not take -i; use -o instead so locally-generated packets are also inspected
iptables -I OUTPUT  -o ${IFACE} -j NFQUEUE --queue-num 0 2>/dev/null || warn "OUTPUT rule already exists"
ok "NFQueue rules active on $IFACE"
warn "REMEMBER: run 'sudo bash cleanup.sh' when done to remove iptables rules"

# ── Write cleanup script ──────────────────────────────────────────────────────
cat > cleanup.sh << 'CLEANUP_EOF'
#!/bin/bash
# Detect the same interface that setup.sh used
IFACE=$(ip route show default 2>/dev/null | awk '$4=="dev"{print $5}' | head -1)
[ -z "$IFACE" ] && IFACE="wlan0"
echo "[*] Removing iptables NFQueue rules for $IFACE..."
iptables -D INPUT   -i ${IFACE} -j NFQUEUE --queue-num 0 2>/dev/null && echo "[+] INPUT removed"   || echo "[!] INPUT rule not found"
iptables -D FORWARD -i ${IFACE} -j NFQUEUE --queue-num 0 2>/dev/null && echo "[+] FORWARD removed" || echo "[!] FORWARD rule not found"
iptables -D OUTPUT  -o ${IFACE} -j NFQUEUE --queue-num 0 2>/dev/null && echo "[+] OUTPUT removed"  || echo "[!] OUTPUT rule not found"
echo "[+] Cleanup complete."
CLEANUP_EOF
chmod +x cleanup.sh
ok "cleanup.sh written"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  Setup complete!${NC}"
echo ""
echo -e "  ${BOLD}Start the IPS:${NC}"
echo -e "    sudo python3 main.py --iface ${IFACE} --dashboard"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}"
echo -e "    http://127.0.0.1:5000   (admin / securemesh)"
echo ""
echo -e "  ${BOLD}Simulate attacks (second terminal):${NC}"
echo -e "    sudo python3 simulate_attack.py --iface ${IFACE} --all-tests"
echo ""
echo -e "  ${BOLD}Stop & clean up:${NC}"
echo -e "    Ctrl+C, then:  sudo bash cleanup.sh"
echo ""
