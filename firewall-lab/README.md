# Web-Based Firewall Rule Configuration & Testing Lab (CyberGuard)

A modern, college-level cybersecurity lab and interactive web dashboard for visualizing, configuring, and testing Linux `iptables` packet filtering rules.

---

## ✅ Phase 3 Deliverable: Real iptables Integration

The Flask API now uses `iptables_backend.py` for validated, argument-list command execution. `LAB_MODE` and `DRY_RUN` both default to `True`; on Windows and other non-Linux hosts the backend stays in safe mode. The web server binds to `127.0.0.1` and changing API requests require the `X-API-Token` header. The dashboard receives that token from the Flask-rendered page.

### Safe local run

```bash
cd firewall-lab
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. Safe mode generates command previews and does not execute iptables. The `/api/health` response reports the mode and backend availability.

### Live Linux VM setup

Use an Ubuntu Server VM and take a snapshot before live testing. Install iptables and the Python requirements. Do not run Flask as root. Configure a restricted sudoers entry for the exact paths returned by `which iptables`, `which iptables-save`, and `which iptables-restore`:

```sudoers
mayank ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore
```

Replace `mayank` and the paths for your VM. This is a lab shortcut; production should use a dedicated service account and stricter command wrappers. Set a long token and explicitly disable both safe-mode flags only on the VM:

```bash
LAB_MODE=False DRY_RUN=False CYBERGUARD_TOKEN='use-a-long-random-secret' python3 app.py
```

Access the VM dashboard through an SSH tunnel, for example `ssh -L 5000:127.0.0.1:5000 user@vm-ip`. Never bind this API to `0.0.0.0` or expose it directly to a network.

When enabling, the backend validates the database rules, refuses an INPUT DROP policy without an SSH accept rule, backs up the current ruleset, applies loopback and established-connection baseline rules, and schedules rollback after 60 seconds. Click **Confirm Rules** to keep the new rules. `sync_all` rebuilds the filter chains from SQLite; it removes rules manually added to those chains. The app does not automatically synchronize at startup; use the dashboard enable action after a reboot.

IPv6 is not managed, and the backend only handles simple filter rules. Docker, ufw, and other firewall managers can conflict. For production, use nftables, authenticated users, and HTTPS.

### Backend unit tests

The supplied unit tests are safe to run on any OS because they create a backend in dry-run mode:

```bash
python -m unittest test_iptables_backend -v
```

### Phase 3 VM test plan

Use a second VM as the client and take screenshots for the report. Check `/api/health`, add an SSH ACCEPT rule, enable with INPUT DROP, and confirm within 60 seconds. Also check the lockout refusal with no SSH rule, automatic rollback when not confirmed, deletion from both the kernel and dashboard, counter changes after traffic, and rejection of malformed IPs and ports. Do not use the live commands on your laptop.

## ✅ Phase 2 Deliverable: Flask REST API + SQLite Persistent Backend

> **Phase 2 is now complete.** The project runs as a full-stack web application. The frontend communicates with a Python Flask REST API which stores all rules and logs in a persistent SQLite database (`firewall.db`).

### 🚀 How to Run Phase 2

**Prerequisites:** Python 3.9+ with Flask installed.

```bash
# 1. Install dependencies (one-time)
python -m pip install flask flask-cors

# 2. Start the backend server
cd d:/CS-Project/firewall-lab
python app.py
```

Then open your browser to:
```
http://127.0.0.1:5000
```

### 🔌 REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/rules` | List all firewall rules |
| `POST` | `/api/rules` | Add a new rule (JSON body) |
| `DELETE` | `/api/rules/<id>` | Delete a rule by ID |
| `POST` | `/api/simulate` | Simulate packet evaluation |
| `GET` | `/api/firewall/status` | Get firewall state & policies |
| `POST` | `/api/firewall/toggle` | Enable / disable firewall |
| `GET` | `/api/logs` | Fetch activity logs |
| `DELETE` | `/api/logs` | Clear all logs |
| `GET` | `/api/logs/export` | Download logs as JSON file |
| `GET` | `/api/health` | Backend health check |

### ⚙️ Configuration (in `app.py`)

```python
LAB_MODE = True    # True = safe mode, no real iptables execution
DRY_RUN  = True    # True = generate command but don't run it (Phase 2)
                   # Set both False in Phase 3 on a real Linux server
```

---

## 📌 Phase 1 Deliverable: Frontend & Interactive Simulation Lab

> **Notice:** As requested for **Phase 1**, this release delivers the complete **Cybersecurity Web Dashboard & Safe Packet Simulation Lab** (HTML5, CSS3, vanilla JavaScript). It operates in standalone mode without requiring root Linux privileges or backend servers, allowing you to showcase the complete UI/UX, packet simulation logic, rule management workflows, and security audit features during your project review.

---

## 🚀 Quick Start (How to Run Phase 1)

You can view and test the dashboard immediately using either of the two methods below:

### Method A: Direct Browser Launch (No server required)
Simply double-click:
```
firewall-lab/index.html
```
or right-click `index.html` → **Open with Google Chrome / Microsoft Edge / Firefox**.

### Method B: Python Local Server (Recommended for presentations)
Open a terminal in the project directory:
```bash
cd d:/CS-Project/firewall-lab
python -m http.server 5000
```
Then navigate to:
```
http://localhost:5000
```

---

## 🛡️ Key Features Implemented in Phase 1

### 1. Cybersecurity Dashboard Overview
- **Real-time Status Indicator:** Live glowing status beacon (`ACTIVE` / `INACTIVE`).
- **Telemetry Metric Cards:**
  - Firewall State & Netfilter hook enforcement.
  - Active rule count (dynamically updated).
  - Blocked source IPs count.
  - Allowed port count (SSH, HTTP, HTTPS, DNS).
- **iptables Chain Default Policies Bar:** Visual chips for `INPUT` (DROP), `OUTPUT` (ACCEPT), and `FORWARD` (DROP).

### 2. Interactive Firewall Rules Management
- Filterable and searchable table mirroring the Linux kernel `filter` table:
  - **Rule ID**, **Chain**, **Protocol**, **Source IP/CIDR**, **Destination IP/CIDR**, **Source Port**, **Destination Port**, **Action** (`ACCEPT`, `DROP`, `REJECT`), **Packet Counter**, **Byte Counter**, and **Status**.
- **Real-time Search & Multi-criteria Filtering:** Instant filtering by text, chain, or target action.
- **Prefill to Tester:** Click the play icon on any rule to automatically load its parameters into the packet tester.
- **Delete Protection:** Modal confirmation before purging a rule from the active ruleset.

### 3. Add Rule Modal with Live iptables Command Generator
- Input fields for Chain, Protocol, Source IP/CIDR, Destination IP/CIDR, Source Port, Destination Port, and Action.
- **Quick Preset Chips:** One-click shortcuts for `0.0.0.0/0 (Any)`, `192.168.1.0/24`, `198.51.100.45`, Port `22` (SSH), `80` (HTTP), and `443` (HTTPS).
- **Live Netfilter Syntax Preview:** Displays the exact shell command that would be passed to `iptables` in real-time as you type:
  ```bash
  iptables -A INPUT -p tcp -s 192.168.1.50 --dport 22 -j ACCEPT
  ```
- **Strict Client-Side Validation:** Validates IPv4 format, CIDR bitmasks (0–32), and valid port numbers (1–65535).

### 4. Safe Rule Testing Lab (Packet Simulation Engine)
- **Local Simulation:** Accurately replicates `iptables` first-match sequential evaluation without sending unprivileged or intrusive network traffic.
- **Comprehensive Output:**
  - **Verdict:** Prominent glowing **ALLOW** (green) or **BLOCK** (red) status.
  - **Logic Trace:** Human-readable explanation detailing why the packet was accepted, dropped, or rejected.
  - **Rule Resolution Card:** Displays exact matched rule ID or chain default policy fallback.

### 5. Safety Controls & Activity Audit Log
- **Disabling Safety Guard:** Confirmation modal warning against opening all network interfaces before disabling the firewall.
- **Security Activity Log:** Monospaced terminal recording timestamps, action tags (`RULE_ADD`, `RULE_DELETE`, `TEST_PACKET`, `STATUS_SYNC`), and verdicts.
- **Audit Export:** One-click button to export activity logs as formatted JSON.
- **Toast Notifications:** Dynamic slide-in alerts for system feedback.

---

## 🎯 Recommended Presentation Demonstration Script

When presenting Phase 1 to your professors or evaluators, follow this recommended walkthrough:

1. **Introduction (1 min):**
   - Present the dark cybersecurity UI theme designed for network defense operations.
   - Point out the status beacon, telemetry cards, and chain default policies (`INPUT: DROP`, `OUTPUT: ACCEPT`, `FORWARD: DROP`).
2. **Demonstrate Rule Creation (2 mins):**
   - Click **Add Rule**.
   - Select `INPUT`, protocol `TCP`, enter source IP `192.168.1.50`, destination port `22`, action `ACCEPT`.
   - Highlight the **Live iptables Command Preview box** at the bottom of the modal: show that it dynamically generates:
     `iptables -A INPUT -p tcp -s 192.168.1.50 --dport 22 -j ACCEPT`.
   - Submit the rule and show the instant addition to the table, updated metric counters, and toast notification.
3. **Demonstrate Packet Simulation Engine (2 mins):**
   - Navigate to the **Packet Tester** tab.
   - Test Case 1 (Allowed): Source `192.168.1.50`, Port `22`. Click **Run Simulation** → Verdict shows **ALLOW**, citing Rule `#101` SSH authorization.
   - Test Case 2 (Blocked): Change Source to `198.51.100.45` (malicious scanner). Click **Run Simulation** → Verdict shows **BLOCK**, explaining the rule match.
   - Test Case 3 (Default Fallback): Test an unconfigured port (e.g., `8080`). Show that the simulator falls back to the default `INPUT` chain policy (`DROP`).
4. **Demonstrate Activity Audit & Safety Features (1 min):**
   - Switch to **Activity Log** to display the audit trail of all tests and changes.
   - Click **Export JSON** to show audit logging capabilities.
   - Click **Disable Firewall** and highlight the safety confirmation dialog designed to prevent accidental lockouts.

---

## 🗺️ Planned Architecture for Phase 2 (Backend Integration)

In Phase 2, the Python Flask backend and SQLite database will connect directly to this frontend:

```
+-------------------------------------------------------------+
|             Web Browser (Vanilla JS / HTML5 / CSS3)         |
+-------------------------------------------------------------+
                              |
                     REST API | JSON (fetch)
                              v
+-------------------------------------------------------------+
|                     Flask Backend (app.py)                  |
|  - Input Validation (CIDR, IP, Port, Chain, Action)         |
|  - Subprocess Execution (Array-based, shell=False, timeouts) |
|  - LAB_MODE & DRY_RUN Safety Enforcers                      |
+-------------------------------------------------------------+
               |                               |
               v                               v
+-----------------------------+ +-----------------------------+
|    Linux iptables Engine    | |    SQLite DB (firewall.db)  |
|  (Netfilter Kernel Module)  | |  (Persistent rules & logs)  |
+-----------------------------+ +-----------------------------+
```

---

## 📁 Project Directory Layout

```
firewall-lab/
├── index.html            # Standalone direct browser entry point (Phase 1)
├── templates/
│   └── index.html        # Flask template version (Ready for Phase 2)
├── static/
│   ├── css/
│   │   └── style.css     # Dark cybersecurity responsive stylesheet
│   └── js/
│       └── app.js        # Rule state management & packet evaluation engine
└── README.md             # Project documentation & presentation guide
```
