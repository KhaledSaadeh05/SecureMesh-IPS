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
securemesh_slim/
│
├── main.py               # Entry point — starts everything up
├── ips_core.py           # All detection logic and core classes
├── dashboard.py          # Web dashboard (Flask)
├── simulate_attack.py    # Sends fake attack packets for testing
├── malicious_ips.txt     # Your custom IP blacklist (one IP per line)
├── requirements.txt      # Python libraries needed
└── setup.sh              # One-command installer for Linux

🧠 How It Works — Step by Step:
When the program runs, the first thing that happens is that network traffic starts flowing through your machine's network interface. The Sniffer sits there and captures every single packet that passes through, no matter where it came from or where it is going. Once a packet is captured, it gets passed to the PacketAnalyzer, which is the brain of the whole system — it takes each packet and runs it through 10 detection stages one by one. In the first stage, it checks if the source IP address is on the whitelist, and if it is, the packet is allowed through immediately without any further checks. In the second stage, it checks if the IP is on the blacklist, and if it is, the packet gets blocked right away. In the third stage, it checks whether this IP is sending packets at a suspiciously high rate, and if so, it adds points to that IP's threat score. In the fourth stage, it checks whether the IP is trying to connect to many different ports, which is a sign of port scanning, and again adds to the threat score. From stage five onwards, the system looks for more specific and dangerous attack types — stage five blocks SYN flood attacks, stage six blocks ICMP flood attacks, stage seven blocks connections coming from known malicious ports like backdoor ports, stage eight blocks brute force attempts such as repeated login tries on SSH, and stage nine blocks packets that contain dangerous or suspicious content in their payload. Finally, in stage ten, if an IP has collected too many threat score points from the earlier stages, it gets blocked automatically even if no single attack was caught directly. Once a threat is detected and a blocking decision is made, three things happen at the same time — the AlertLogger writes the full details of the alert into a local SQLite database so you have a record of everything, the TCPRSTInjector sends a TCP reset signal to forcefully kill the malicious connection, and the Dashboard updates live in your browser so you can see the alert appear on your screen in real time.

🏗️ OOP Design (for university report)
This project also demonstrates 4 main Object-Oriented Programming (OOP) concepts:
1- Encapsulation — The important data inside each class is kept private using _ before variable names. The program interacts with objects through methods instead of changing the variables directly.
2- Inheritance — All detector classes inherit from BaseDetector. All logger classes inherit from BaseLogger. This means shared behaviour is written once and reused.
3- Polymorphism — PacketAnalyzer calls .detect() on a list of detector objects without knowing what type each one is. Each detector handles its own logic. Same method call, different behaviours.
4- Composition — The main class SecureMeshIPS is built using other objects like IPDatabase, Sniffer, and Dashboard inside it. This follows the “has-a” relationship instead of inheritance.



Class Hierarchy:
The project is built using three separate inheritance trees, each one starting from an abstract base class. The first and largest tree starts with BaseDetector, which is an abstract class that defines the basic structure that every detection class must follow. Directly inheriting from it is BlacklistDetector, which handles checking if an IP is on the blocked list, and IOCScoringDetector, which handles the threat scoring system. Also inheriting from BaseDetector is BaseFloodDetector, which is itself another abstract class that provides shared logic for flood-type attacks, and from it inherit two concrete classes — SYNFloodDetector, which detects SYN flood attacks, and ICMPFloodDetector, which detects ICMP flood attacks. The third child of BaseDetector is BaseImmediateBlockDetector, which is also an abstract class that serves as a parent for attacks that must be blocked instantly without needing a score, and from it inherit three concrete classes — MaliciousPortDetector, which blocks connections on known dangerous ports, BruteForceDetector, which blocks repeated login attempts, and PayloadDetector, which inspects the content of packets for dangerous data. The second inheritance tree starts with BaseLogger, which is an abstract class that defines how logging should work, and from it inherit two classes — AlertLogger, which saves alerts into the local SQLite database, and SyslogLogger, which optionally forwards alerts to the system's syslog server. The third and smallest tree starts with BaseInjector, which is an abstract class that defines how connection killing should work, and the only class that inherits from it is TCPRSTInjector, which is responsible for sending TCP reset packets to forcefully terminate malicious connections.


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

