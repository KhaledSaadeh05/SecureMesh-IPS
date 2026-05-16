# SecureMesh IPS v3 — Network Intrusion Prevention System, Network Intrusion Detection System
A Python-based Network Intrusion Prevention System (IPS) that detects and blocks network attacks in real time, with a live web dashboard. Built with Scapy, Flask, and iptables.
📌 What Is This Project?
SecureMesh IPS v3 is a network security tool that sits between your computer and the internet and watches all incoming and outgoing network traffic. When it detects something suspicious — like someone trying to flood your network with fake requests, scan your ports, or connect from a known-bad IP address — it automatically blocks them and logs the event so you can review it later.

Think of it like a smart security guard for your network:
* It watches every packet (small chunk of data) that travels through your network interface.
* It runs each packet through a series of detection checks.
* If something looks dangerous, it blocks the attacker and writes an alert to a log.
* You can see all of this happening live in a browser-based dashboard.

This project was built as a university networking/security project and demonstrates core Object-Oriented Programming (OOP) concepts applied to real network security.

✨ Features:
* Live Packet Sniffing ==> Captures all network packets on a chosen interface in real time.
* IP Blacklist ==> Instantly blocks traffic from IPs listed in malicious_ips.txt.
* SYN Flood Detection ==> Detects attackers sending too many connection requests.
* ICMP Flood Detection ==> Catches ping-based denial-of-service (DoS) attacks.
* Port Scan Detection ==> Identifies IPs probing multiple ports to find weaknesses.
* Brute Force Detection ==> Blocks repeated login attempts (e.g., SSH on port 22).
* Malicious Port Detection ==> Blocks known backdoor/trojan ports (e.g., port 4444).
* IOC Scoring System ==> Assigns a threat score to each IP; blocks when score is too high.
* Web Dashboard ==> Live browser dashboard with stats, alerts, blacklist & whitelist management.
* Alert Logging ==> All alerts stored in a local SQLite database.
* Syslog Support ==> Optional forwarding of alerts to a system syslog server.
* TCP RST Injection ==> Actively kills malicious TCP connections (not just dropping packets).
* Built-in Attack Simulator ==> A test script that generates fake attack traffic so you can verify the IPS works.

🗂️ Project Structure:
The project folder is called securemesh_slim and it contains 7 files, each one responsible for a specific job. The first file is main.py, which is the starting point of the whole program — when you run the project, this is the file you run first, and it connects all the other parts together. The second file is ips_core.py, which is the most important and largest file in the project — it contains all the detection logic and all the classes that handle things like blocking IPs, analyzing packets, logging alerts, and injecting TCP resets. The third file is dashboard.py, which builds the web interface using Flask so you can open your browser and see everything happening live, including alerts, blocked IPs, and traffic statistics. The fourth file is simulate_attack.py, which is a testing tool that sends fake attack packets to your own machine so you can check that the IPS is working correctly without needing a real attacker. The fifth file is malicious_ips.txt, which is a simple text file where you write down the IP addresses you want to block — one address per line — and the system reads and reloads this file automatically every 5 minutes. The sixth file is requirements.txt, which lists all the Python libraries that need to be installed before the project can run, such as Scapy, Flask, and pandas. The seventh and last file is setup.sh, which is a Linux shell script that installs everything automatically with a single command, so you don't have to install each library manually one by one.


🧠 How It Works — Step by Step:
Network Traffic
      │
      ▼
 [Sniffer] ──── captures every packet on your interface
      │
      ▼
 [PacketAnalyzer] ──── runs each packet through all detectors:
      │
      ├── Stage 1: Is this IP whitelisted? → Allow immediately
      ├── Stage 2: Is this IP blacklisted? → Block immediately
      ├── Stage 3: High packet rate?       → Add threat score
      ├── Stage 4: Port scanning?          → Add threat score
      ├── Stage 5: SYN flood?              → Block
      ├── Stage 6: ICMP flood?             → Block
      ├── Stage 7: Malicious port?         → Block
      ├── Stage 8: Brute force?            → Block
      ├── Stage 9: Bad payload?            → Block
      └── Stage 10: IOC score too high?    → Block
              │
              ▼
       [AlertLogger] ──── writes the alert to SQLite database
       [TCPRSTInjector] ── kills the malicious TCP connection
       [Dashboard] ──────  shows everything live in your browser

🏗️ OOP Design (for university report)
This project also demonstrates 4 main Object-Oriented Programming (OOP) concepts:
1- Encapsulation — The important data inside each class is kept private using _ before variable names. The program interacts with objects through methods instead of changing the variables directly.
2- Inheritance — All detector classes inherit from BaseDetector. All logger classes inherit from BaseLogger. This means shared behaviour is written once and reused.
3- Polymorphism — PacketAnalyzer calls .detect() on a list of detector objects without knowing what type each one is. Each detector handles its own logic. Same method call, different behaviours.
4- Composition — The main class SecureMeshIPS is built using other objects like IPDatabase, Sniffer, and Dashboard inside it. This follows the “has-a” relationship instead of inheritance.



Class Hierarchy:
BaseDetector (abstract)
  ├── BlacklistDetector
  ├── BaseFloodDetector
  │     ├── SYNFloodDetector
  │     └── ICMPFloodDetector
  ├── BaseImmediateBlockDetector
  │     ├── MaliciousPortDetector
  │     ├── BruteForceDetector
  │     └── PayloadDetector
  └── IOCScoringDetector

BaseLogger (abstract)
  ├── AlertLogger
  └── SyslogLogger

BaseInjector (abstract)
  └── TCPRSTInjector


⚙️ Requirements:
* OS: Linux (Ubuntu/Debian recommended)
* Python: 3.8 or higher
* Privileges: Must run as root (sudo) — required to capture raw packets
* Libraries:
scapy>=2.5.0,<2.6.0      # Packet capture and injection
flask>=3.0.0              # Web dashboard
cryptography>=42.0.0      # Cryptographic utilities
NetfilterQueue>=1.1.0     # Linux kernel packet interception
pandas>=2.0.0             # Data handling for alerts



🚀 Installation & Usage:
# In a ONE terminal, run:
Step 1 — Install everything automatically ==>(sudo bash setup.sh).
This will:
- Detect your network interface automatically.
- Install all required system and Python packages.
- Set up iptables rules to route traffic through the IPS.
- Generate a cleanup.sh script to undo everything when you're done.

Step 2 — Start the IPS ==> (sudo python3 main.py --iface eth0 --dashboard + sudo python3 main.py --iface eth0 --passive +
sudo python3 main.py --iface eth0 --dashboard --syslog).
Replace eth0 with your actual network interface (e.g., wlan0 for Wi-Fi).


Step 3 — Open the Dashboard ==> (http://127.0.0.1:5000 It can be somewhat different).
Login credentials:
Username: admin
Password: securemesh

The dashboard shows:
- Live count of blacklisted/whitelisted IPs.
- Total packets sniffed and blocked.
- Recent alerts with IP, detection reason, and action taken.
- Full alert history, blacklist, and whitelist management.

# In a second terminal, run:

Step 4 — Test it with the Attack Simulator (optional) ==> (sudo python3 simulate_attack.py --iface eth0 --all-tests +
sudo python3 simulate_attack.py --iface eth0 --ip 192.0.2.1).
This sends fake spoofed packets to test every detection stage. You'll see the alerts appear live in the dashboard.

Step 5 — Stop and clean up ==> (sudo bash cleanup.sh).
This removes the iptables rules that were added during setup.


📋 Custom Blacklist
Edit malicious_ips.txt to add your own blocked IPs:
# Lines starting with # are comments
192.168.1.100
10.0.0.55
203.0.113.7
...
The IPS auto-reloads this file every 5 minutes — no restart needed.





🖥️ Dashboard Pages:
* Home ==> / ==> Live stats and recent alerts.
* Blacklist ==> /blacklist ==> All currently blocked IPs.
* Whitelist ==> /whitelist ==> Trusted IPs that are always allowed.
* Alerts ==> /alerts ==> Full alert history.
* Live API ==> /api/live ==> JSON endpoint for live stats.
* Alerts API ==> /api/alerts ==> JSON endpoint for recent alerts.


👨‍💻 Technologies Used:
* Python 3 — Main programming language
* Scapy — Packet sniffing, crafting, and injection
* Flask — Web framework for the dashboard
* SQLite — Lightweight database for storing alerts
* iptables / NFQueue — Linux kernel firewall integration
* pandas — Data processing for alert queries
* threading — Running the sniffer and dashboard simultaneously




# This project was developed for educational purposes as part of a Network Security course assignment at The University of Jordan (https://www.ju.edu.jo/home.aspx).

⚠️ Important Notes:
1- This tool needs root/sudo permissions because capturing network packets requires low-level system access.
2- Only use this project on networks that you own or have permission to test. Using it on other people’s networks without permission is illegal.
3- The attack simulator (simulate_attack.py) sends fake/spoofed packets, so it should only be used in a safe lab or testing environment.
4- After finishing, run sudo bash cleanup.sh to remove the iptables rules and return the system back to normal.

