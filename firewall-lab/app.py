"""
CyberGuard Firewall Lab - Phase 2 Backend
Flask REST API + SQLite persistent storage
Run: python app.py
"""

import re
import json
import sqlite3
import os
from functools import wraps
from datetime import datetime
from flask import Flask, jsonify, request, render_template
from iptables_backend import IptablesBackend, LockoutRisk, ValidationError, validate_rule

# ---------------------------------------------
# App & Config
# ---------------------------------------------
app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "firewall.db")

fw = IptablesBackend(ssh_port=22)
API_TOKEN = os.environ.get("CYBERGUARD_TOKEN", "change-me")
LAB_MODE = fw.lab_mode
DRY_RUN = fw.dry_run


def require_token(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.headers.get("X-API-Token") != API_TOKEN:
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------
# Database helpers
# ---------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            chain       TEXT    NOT NULL DEFAULT 'INPUT',
            protocol    TEXT    NOT NULL DEFAULT 'TCP',
            src_ip      TEXT    NOT NULL DEFAULT '0.0.0.0/0',
            dst_ip      TEXT    NOT NULL DEFAULT '0.0.0.0/0',
            src_port    TEXT    NOT NULL DEFAULT 'any',
            dst_port    TEXT    NOT NULL DEFAULT 'any',
            action      TEXT    NOT NULL DEFAULT 'DROP',
            packets     INTEGER NOT NULL DEFAULT 0,
            bytes       TEXT    NOT NULL DEFAULT '0 B',
            status      TEXT    NOT NULL DEFAULT 'ACTIVE',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            tag         TEXT NOT NULL,
            message     TEXT NOT NULL,
            result      TEXT NOT NULL DEFAULT 'OK',
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    defaults = {
        "firewall_active": "true",
        "policy_INPUT":    "DROP",
        "policy_OUTPUT":   "ACCEPT",
        "policy_FORWARD":  "DROP",
    }
    for k, v in defaults.items():
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    c.execute("SELECT COUNT(*) as cnt FROM rules")
    if c.fetchone()["cnt"] == 0:
        seed_rules = [
            ("INPUT",   "TCP",  "192.168.1.0/24", "0.0.0.0/0", "any", "22",  "ACCEPT", 342,  "28.4 KB"),
            ("INPUT",   "TCP",  "0.0.0.0/0",      "0.0.0.0/0", "any", "80",  "ACCEPT", 1845, "1.2 MB"),
            ("INPUT",   "TCP",  "0.0.0.0/0",      "0.0.0.0/0", "any", "443", "ACCEPT", 4920, "5.8 MB"),
            ("INPUT",   "UDP",  "0.0.0.0/0",      "0.0.0.0/0", "53",  "any", "ACCEPT", 890,  "68.2 KB"),
            ("INPUT",   "TCP",  "198.51.100.45",   "0.0.0.0/0", "any", "any", "DROP",   412,  "24.7 KB"),
            ("INPUT",   "TCP",  "0.0.0.0/0",      "0.0.0.0/0", "any", "23",  "REJECT", 67,   "4.1 KB"),
            ("INPUT",   "ICMP", "0.0.0.0/0",      "0.0.0.0/0", "any", "any", "DROP",   154,  "12.9 KB"),
        ]
        c.executemany("""
            INSERT INTO rules (chain, protocol, src_ip, dst_ip, src_port, dst_port, action, packets, bytes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, seed_rules)

        seed_logs = [
            ("RULE_ADD", "Added INPUT TCP rule: 198.51.100.45:* -> DROP", "SUCCESS"),
            ("TEST",     "Tested packet 198.51.100.45 -> 192.168.1.10:80", "BLOCKED"),
            ("DELETE",   "Deleted rule #100", "SUCCESS"),
            ("SYNC",     "iptables ruleset verified", "SYNCED"),
        ]
        c.executemany("INSERT INTO logs (tag, message, result) VALUES (?,?,?)", seed_logs)

    conn.commit()
    conn.close()


def setting_get(key):
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else None


def setting_set(key, value):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, str(value)))
    conn.commit()
    conn.close()


# ---------------------------------------------
# Validation
# ---------------------------------------------
_IP_RE   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$")

ALLOWED_CHAINS    = {"INPUT", "OUTPUT", "FORWARD"}
ALLOWED_PROTOCOLS = {"TCP", "UDP", "ICMP", "ALL"}
ALLOWED_ACTIONS   = {"ACCEPT", "DROP", "REJECT"}


def valid_ip(s):
    if not _IP_RE.match(s):
        return False
    return all(0 <= int(o) <= 255 for o in s.split("."))


def valid_ip_or_cidr(s):
    if not s or s in ("any", "0.0.0.0/0"):
        return True
    if "/" in s:
        if not _CIDR_RE.match(s):
            return False
        ip, prefix = s.rsplit("/", 1)
        return valid_ip(ip) and 0 <= int(prefix) <= 32
    return valid_ip(s)


def valid_port(s):
    if s in ("", "any"):
        return True
    if not s.isdigit():
        return False
    return 1 <= int(s) <= 65535


def sanitize_rule(data):
    chain    = str(data.get("chain", "")).upper()
    protocol = str(data.get("protocol", "")).upper()
    src_ip   = str(data.get("src_ip",  "0.0.0.0/0")).strip() or "0.0.0.0/0"
    dst_ip   = str(data.get("dst_ip",  "0.0.0.0/0")).strip() or "0.0.0.0/0"
    src_port = str(data.get("src_port","any")).strip() or "any"
    dst_port = str(data.get("dst_port","any")).strip() or "any"
    action   = str(data.get("action",  "DROP")).upper()

    if chain    not in ALLOWED_CHAINS:    return None, f"Invalid chain '{chain}'"
    if protocol not in ALLOWED_PROTOCOLS: return None, f"Invalid protocol '{protocol}'"
    if action   not in ALLOWED_ACTIONS:   return None, f"Invalid action '{action}'"
    if not valid_ip_or_cidr(src_ip):      return None, f"Invalid source IP/CIDR '{src_ip}'"
    if not valid_ip_or_cidr(dst_ip):      return None, f"Invalid destination IP/CIDR '{dst_ip}'"
    if not valid_port(src_port):          return None, f"Invalid source port '{src_port}'"
    if not valid_port(dst_port):          return None, f"Invalid destination port '{dst_port}'"

    return {
        "chain": chain, "protocol": protocol,
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port if src_port else "any",
        "dst_port": dst_port if dst_port else "any",
        "action": action,
    }, None


# ---------------------------------------------
# Packet simulation engine
# ---------------------------------------------
def ip_to_long(ip):
    result = 0
    for p in ip.split("."):
        result = (result << 8) + int(p)
    return result & 0xFFFFFFFF


def match_ip(test_ip, rule_ip):
    if not rule_ip or rule_ip in ("any", "0.0.0.0/0"):
        return True
    if rule_ip == test_ip:
        return True
    if "/" in rule_ip:
        net, m = rule_ip.rsplit("/", 1)
        mask = int(m)
        if mask == 0:
            return True
        bitmask = (0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF
        return (ip_to_long(test_ip) & bitmask) == (ip_to_long(net) & bitmask)
    return False


def server_evaluate(src_ip, dst_ip, protocol, dst_port, chain, rules, policies, fw_active):
    if not fw_active:
        return {
            "verdict": "ALLOW",
            "matched_rule": None,
            "explanation": "Firewall is DISABLED. All traffic is allowed (ACCEPT all)."
        }

    for rule in rules:
        if rule["status"] != "ACTIVE":
            continue
        if rule["chain"] != chain:
            continue
        if rule["protocol"] not in ("ALL", protocol.upper()):
            continue
        if not match_ip(src_ip, rule["src_ip"]):
            continue
        if not match_ip(dst_ip, rule["dst_ip"]):
            continue
        if protocol.upper() != "ICMP":
            if rule["dst_port"] not in ("any", dst_port):
                continue

        action = rule["action"]
        verdict = "ALLOW" if action == "ACCEPT" else "BLOCK"
        if action == "ACCEPT":
            explanation = (f"Packet ACCEPTED - matched Rule #{rule['id']} "
                           f"({rule['chain']} {rule['protocol']} from {rule['src_ip']} "
                           f"to port {rule['dst_port']}).")
        elif action == "DROP":
            explanation = (f"Packet DROPPED - matched Rule #{rule['id']} "
                           f"({rule['chain']} {rule['protocol']} from {rule['src_ip']}). "
                           f"Silently discarded, no response sent.")
        else:
            explanation = (f"Packet REJECTED - matched Rule #{rule['id']} "
                           f"({rule['chain']}). TCP RST / ICMP error sent back to {src_ip}.")
        return {"verdict": verdict, "matched_rule": dict(rule), "explanation": explanation}

    policy = policies.get(chain, "DROP")
    verdict = "ALLOW" if policy == "ACCEPT" else "BLOCK"
    return {
        "verdict": verdict,
        "matched_rule": None,
        "explanation": (f"No rule matched. Default {chain} chain policy: {policy}. "
                        f"Packet is {'ACCEPTED' if verdict == 'ALLOW' else 'BLOCKED'}.")
    }


def backend_rule(rule):
    """Map the SQLite/API naming to the backend's normalized rule shape."""
    return validate_rule({
        "id": rule.get("id"), "chain": rule.get("chain"),
        "protocol": str(rule.get("protocol", "ALL")).lower(),
        "src": rule.get("src_ip"), "dst": rule.get("dst_ip"),
        "sport": rule.get("src_port"), "dport": rule.get("dst_port"),
        "action": rule.get("action"),
    })


def policies_from_db(conn):
    return {chain: conn.execute("SELECT value FROM settings WHERE key=?", (f"policy_{chain}",)).fetchone()["value"]
            for chain in ("INPUT", "OUTPUT", "FORWARD")}


# ---------------------------------------------
# Internal log helper
# ---------------------------------------------
def _db_log(tag, message, result="OK"):
    conn = get_db()
    conn.execute("INSERT INTO logs (tag, message, result) VALUES (?,?,?)", (tag, message, result))
    conn.commit()
    conn.close()


# ---------------------------------------------
# Routes
# ---------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", api_token=API_TOKEN)


@app.route("/api/rules", methods=["GET"])
def api_get_rules():
    conn = get_db()
    rows = conn.execute("SELECT * FROM rules ORDER BY id ASC").fetchall()
    conn.close()
    return jsonify({"success": True, "rules": [dict(r) for r in rows]})


@app.route("/api/rules", methods=["POST"])
@require_token
def api_add_rule():
    if fw.status()["rollback_pending"]:
        return jsonify({"success": False, "error": "Confirm or wait for the pending firewall rollback before changing rules"}), 409
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data:
        return jsonify({"success": False, "error": "No JSON body received"}), 400

    try:
        normalized = backend_rule({
            "chain": data.get("chain", "INPUT"), "protocol": data.get("protocol", "TCP"),
            "src_ip": data.get("src_ip", "0.0.0.0/0"), "dst_ip": data.get("dst_ip", "0.0.0.0/0"),
            "src_port": data.get("src_port", "any"), "dst_port": data.get("dst_port", "any"),
            "action": data.get("action", "DROP"),
        })
    except ValidationError as err:
        return jsonify({"success": False, "error": str(err)}), 400
    clean = {
        "chain": normalized["chain"], "protocol": normalized["protocol"].upper(),
        "src_ip": normalized["src"] or "0.0.0.0/0", "dst_ip": normalized["dst"] or "0.0.0.0/0",
        "src_port": normalized["sport"] or "any", "dst_port": normalized["dport"] or "any",
        "action": normalized["action"],
    }

    conn = get_db()
    cursor = conn.execute("""
        INSERT INTO rules (chain, protocol, src_ip, dst_ip, src_port, dst_port, action)
        VALUES (:chain, :protocol, :src_ip, :dst_ip, :src_port, :dst_port, :action)
    """, clean)
    new_id = cursor.lastrowid
    conn.commit()
    new_rule = dict(conn.execute("SELECT * FROM rules WHERE id=?", (new_id,)).fetchone())
    conn.close()

    is_enabled = setting_get("firewall_active").lower() == "true"
    result = fw.apply_rule(backend_rule(new_rule)) if is_enabled else None
    if result is not None and not result.ok:
        conn = get_db()
        conn.execute("DELETE FROM rules WHERE id=?", (new_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": False, "error": result.stderr or "iptables failed",
                        "command": result.command}), 500

    _db_log("RULE_ADD", f"Added rule #{new_id}" + (f": {result.command}" if result else " (stored while firewall disabled)"), "SUCCESS")
    return jsonify({"success": True, "rule": new_rule,
                    "iptables": result.as_dict() if result else None}), 201


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@require_token
def api_delete_rule(rule_id):
    if fw.status()["rollback_pending"]:
        return jsonify({"success": False, "error": "Confirm or wait for the pending firewall rollback before changing rules"}), 409
    conn = get_db()
    rule = conn.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
    if not rule:
        conn.close()
        return jsonify({"success": False, "error": f"Rule #{rule_id} not found"}), 404

    rule_dict = dict(rule)
    conn.close()
    is_enabled = setting_get("firewall_active").lower() == "true"
    try:
        result = fw.remove_rule(backend_rule(rule_dict)) if is_enabled else None
    except ValidationError as err:
        return jsonify({"success": False, "error": str(err)}), 400
    if result is not None and not result.ok:
        return jsonify({"success": False, "error": result.stderr or "iptables failed",
                        "command": result.command}), 500
    conn = get_db()
    conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()
    _db_log("RULE_DELETE", f"Deleted rule #{rule_id}" + (f": {result.command}" if result else " (removed while firewall disabled)"), "SUCCESS")
    return jsonify({"success": True, "deleted_id": rule_id,
                    "iptables": result.as_dict() if result else None})


@app.route("/api/simulate", methods=["POST"])
@require_token
def api_simulate():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "No JSON body"}), 400

    src_ip   = str(data.get("src_ip",  "")).strip()
    dst_ip   = str(data.get("dst_ip",  "")).strip()
    protocol = str(data.get("protocol","TCP")).upper()
    dst_port = str(data.get("dst_port","any")).strip()
    chain    = str(data.get("chain",   "INPUT")).upper()

    if not valid_ip(src_ip):
        return jsonify({"success": False, "error": f"Invalid source IP '{src_ip}'"}), 422
    if not valid_ip(dst_ip):
        return jsonify({"success": False, "error": f"Invalid destination IP '{dst_ip}'"}), 422
    if chain not in ALLOWED_CHAINS:
        return jsonify({"success": False, "error": f"Invalid chain '{chain}'"}), 422

    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM rules WHERE status='ACTIVE' ORDER BY id").fetchall()]
    fw_raw = conn.execute("SELECT value FROM settings WHERE key='firewall_active'").fetchone()
    policies = {
        "INPUT":   conn.execute("SELECT value FROM settings WHERE key='policy_INPUT'").fetchone()["value"],
        "OUTPUT":  conn.execute("SELECT value FROM settings WHERE key='policy_OUTPUT'").fetchone()["value"],
        "FORWARD": conn.execute("SELECT value FROM settings WHERE key='policy_FORWARD'").fetchone()["value"],
    }
    conn.close()

    fw_active = fw_raw["value"].lower() == "true" if fw_raw else True
    result = server_evaluate(src_ip, dst_ip, protocol, dst_port, chain, rows, policies, fw_active)

    _db_log("TEST",
            f"Simulated {src_ip} -> {dst_ip}:{dst_port} [{protocol}] via {chain} = {result['verdict']}",
            result["verdict"])

    return jsonify({"success": True, **result})


@app.route("/api/firewall/status", methods=["GET"])
def api_firewall_status():
    conn = get_db()
    fw_active = conn.execute("SELECT value FROM settings WHERE key='firewall_active'").fetchone()["value"]
    policies = {
        "INPUT":   conn.execute("SELECT value FROM settings WHERE key='policy_INPUT'").fetchone()["value"],
        "OUTPUT":  conn.execute("SELECT value FROM settings WHERE key='policy_OUTPUT'").fetchone()["value"],
        "FORWARD": conn.execute("SELECT value FROM settings WHERE key='policy_FORWARD'").fetchone()["value"],
    }
    conn.close()
    return jsonify({
        "success": True,
        "firewall_active": fw_active.lower() == "true",
        "policies": policies,
        "lab_mode": LAB_MODE,
        "dry_run": DRY_RUN,
        **fw.status(),
    })


@app.route("/api/firewall/toggle", methods=["POST"])
@require_token
def api_firewall_toggle():
    data      = request.get_json(silent=True) or {}
    new_state = data.get("active")
    if not isinstance(new_state, bool):
        return jsonify({"success": False, "error": "active must be a boolean"}), 400
    conn = get_db()
    rules = [backend_rule(dict(row)) for row in conn.execute("SELECT * FROM rules WHERE status='ACTIVE' ORDER BY id").fetchall()]
    policies = policies_from_db(conn)
    conn.close()
    try:
        if new_state:
            info = fw.sync_all(rules, policies, rollback_seconds=60)
        else:
            fw.confirm()
            info = {"results": [result.as_dict() for result in fw.disable()], "rollback_seconds": None}
    except LockoutRisk as err:
        return jsonify({"success": False, "error": str(err)}), 409
    except ValidationError as err:
        return jsonify({"success": False, "error": str(err)}), 400
    failed = next((item for item in info["results"] if not item["ok"]), None)
    if failed:
        return jsonify({"success": False, "error": failed["stderr"] or "iptables failed",
                        "command": failed["command"]}), 500
    setting_set("firewall_active", "true" if new_state else "false")
    msg = "Firewall ACTIVATED - kernel filtering enforced" if new_state else "Firewall DISABLED - all traffic passing"
    _db_log("STATUS", msg, "SUCCESS")
    return jsonify({"success": True, "firewall_active": new_state, "message": msg, **info})


@app.route("/api/firewall/confirm", methods=["POST"])
@require_token
def api_firewall_confirm():
    return jsonify({"success": True, "confirmed": fw.confirm()})


@app.route("/api/live/counters", methods=["GET"])
def api_live_counters():
    return jsonify(fw.counters("INPUT"))


@app.route("/api/logs", methods=["GET"])
def api_get_logs():
    limit = min(int(request.args.get("limit", 100)), 500)
    conn = get_db()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return jsonify({"success": True, "logs": [dict(r) for r in rows]})


@app.route("/api/logs", methods=["DELETE"])
@require_token
def api_clear_logs():
    conn = get_db()
    conn.execute("DELETE FROM logs")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "All logs cleared"})


@app.route("/api/logs/export", methods=["GET"])
def api_export_logs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
    conn.close()
    data = [dict(r) for r in rows]
    return app.response_class(
        response=json.dumps(data, indent=2),
        status=200,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="cyberguard_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'}
    )


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "status": "ok",
        "lab_mode": LAB_MODE,
        "dry_run": DRY_RUN,
        "db": DB_PATH,
        "timestamp": datetime.now().isoformat(),
        **fw.status(),
    })


if __name__ == "__main__":
    init_db()
    print("=" * 55)
    print("  CyberGuard Firewall Lab - Phase 3 Backend")
    print("  Flask + SQLite  |  LAB_MODE =", LAB_MODE)
    print("  http://127.0.0.1:5000")
    print("=" * 55)
    app.run(debug=False, host="127.0.0.1", port=5000)
