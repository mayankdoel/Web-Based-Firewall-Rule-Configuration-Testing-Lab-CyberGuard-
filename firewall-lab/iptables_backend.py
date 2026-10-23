"""
iptables_backend.py - CyberGuard Phase 3
Applies validated firewall rules to the real Linux kernel via iptables.

Safety design
  1. LAB_MODE / DRY_RUN default to True: commands are only generated, never run.
  2. Every value is validated before it gets near a command (IP, CIDR, port, chain, action).
  3. subprocess is always called with an argument list and shell=False.
  4. Anti-lockout: refuses default-DROP on INPUT without an SSH accept rule, always keeps
     loopback + ESTABLISHED rules, and auto-rolls back unless you confirm in time.
  5. Runs as a normal user through a restricted sudoers entry (see PHASE3_SETUP.md).
"""
import ipaddress
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

CHAINS = ("INPUT", "OUTPUT", "FORWARD")
PROTOCOLS = ("tcp", "udp", "icmp", "all")
ACTIONS = ("ACCEPT", "DROP", "REJECT")
POLICIES = ("ACCEPT", "DROP")
SEARCH_PATH = "/usr/sbin:/sbin:/usr/bin:/bin"

# Rules that must always exist so the box keeps working
BASELINE = (
    ("INPUT", ["-i", "lo", "-j", "ACCEPT"]),
    ("INPUT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
    ("OUTPUT", ["-o", "lo", "-j", "ACCEPT"]),
)


class ValidationError(ValueError):
    """Raised when user input is not a safe, valid firewall rule."""


class LockoutRisk(RuntimeError):
    """Raised when a change could cut off remote administration."""


@dataclass
class Result:
    ok: bool
    command: str
    stdout: str = ""
    stderr: str = ""
    executed: bool = False  # False means dry run / lab mode

    def as_dict(self):
        return self.__dict__.copy()


def _flag(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------- validation
def _validate_ip(value, label):
    v = str(value or "").strip()
    if v.lower() in ("", "any", "0.0.0.0/0"):
        return None
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        raise ValidationError(f"Invalid {label}: {v!r}") from None
    if net.version != 4:
        raise ValidationError(f"{label} must be IPv4")
    return str(net)


def _validate_port(value, label):
    v = str(value if value is not None else "").strip()
    if v.lower() in ("", "any"):
        return None
    if not re.fullmatch(r"[0-9]{1,5}", v) or not 1 <= int(v) <= 65535:
        raise ValidationError(f"Invalid {label}: {v!r} (use 1-65535)")
    return int(v)


def validate_rule(data):
    """Return a clean rule dict or raise ValidationError."""
    chain = str(data.get("chain", "INPUT")).strip().upper()
    proto = str(data.get("protocol", "tcp")).strip().lower()
    action = str(data.get("action", "")).strip().upper()
    if chain not in CHAINS:
        raise ValidationError(f"Chain must be one of {CHAINS}")
    if proto not in PROTOCOLS:
        raise ValidationError(f"Protocol must be one of {PROTOCOLS}")
    if action not in ACTIONS:
        raise ValidationError(f"Action must be one of {ACTIONS}")
    rule = {
        "id": data.get("id"),
        "chain": chain,
        "protocol": proto,
        "src": _validate_ip(data.get("src"), "source IP"),
        "dst": _validate_ip(data.get("dst"), "destination IP"),
        "sport": _validate_port(data.get("sport"), "source port"),
        "dport": _validate_port(data.get("dport"), "destination port"),
        "action": action,
    }
    if rule["id"] is not None:
        if not re.fullmatch(r"[0-9]{1,9}", str(rule["id"])):
            raise ValidationError("Rule id must be numeric")
        rule["id"] = int(rule["id"])
    if (rule["sport"] or rule["dport"]) and proto not in ("tcp", "udp"):
        raise ValidationError("Ports only work with tcp or udp")
    return rule


def build_spec(rule):
    """Rule dict -> iptables argument list (without -A/-D and chain)."""
    spec = []
    if rule["protocol"] != "all":
        spec += ["-p", rule["protocol"]]
    if rule.get("src"):
        spec += ["-s", rule["src"]]
    if rule.get("dst"):
        spec += ["-d", rule["dst"]]
    if rule.get("sport"):
        spec += ["--sport", str(rule["sport"])]
    if rule.get("dport"):
        spec += ["--dport", str(rule["dport"])]
    if rule.get("id") is not None:
        spec += ["-m", "comment", "--comment", f"cyberguard-{rule['id']}"]
    return spec + ["-j", rule["action"]]


def parse_counters(text):
    """Parse `iptables -L CHAIN -n -v -x` into {rule_id: {packets, bytes}}."""
    out = {}
    for line in text.splitlines():
        m = re.search(r"/\*\s*cyberguard-(\d+)\s*\*/", line)
        parts = line.split()
        if m and len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            out[int(m.group(1))] = {"packets": int(parts[0]), "bytes": int(parts[1])}
    return out


# ------------------------------------------------------------------- backend
class IptablesBackend:
    def __init__(self, lab_mode=None, dry_run=None, backup_dir="backups", timeout=5, ssh_port=22):
        self.lab_mode = _flag("LAB_MODE", True) if lab_mode is None else lab_mode
        self.dry_run = _flag("DRY_RUN", True) if dry_run is None else dry_run
        self.timeout = timeout
        self.ssh_port = ssh_port  # set to None to skip the anti-lockout check
        self.backup_dir = Path(backup_dir)
        self._bin = {n: shutil.which(n, path=SEARCH_PATH) for n in ("iptables", "iptables-save", "iptables-restore")}
        self._lock = threading.Lock()
        self._pending = None  # {"backup": Path, "timer": Timer, "deadline": float}

    @property
    def live(self):
        """True only when commands will really run."""
        return (not self.lab_mode and not self.dry_run
                and sys.platform.startswith("linux") and all(self._bin.values()))

    def status(self):
        p = self._pending
        return {"lab_mode": self.lab_mode, "dry_run": self.dry_run, "live": self.live,
                "rollback_pending": bool(p), "rollback_deadline": p["deadline"] if p else None}

    # ---- low level
    def _exec(self, tool, args, stdin=None):
        shown = shlex.join([tool, *args])
        if not self.live:
            return Result(True, shown)
        cmd = ["sudo", "-n", self._bin[tool], *args]
        try:
            p = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                               timeout=self.timeout, shell=False)
        except subprocess.TimeoutExpired:
            return Result(False, shown, stderr="command timed out", executed=True)
        except OSError as exc:
            return Result(False, shown, stderr=str(exc), executed=True)
        return Result(p.returncode == 0, shown, p.stdout, p.stderr.strip(), True)

    def _ipt(self, args, stdin=None):
        return self._exec("iptables", ["-w", "5", *args], stdin)

    # ---- single rule operations
    def apply_rule(self, data):
        r = validate_rule(data)
        return self._ipt(["-A", r["chain"], *build_spec(r)])

    def remove_rule(self, data):
        r = validate_rule(data)
        return self._ipt(["-D", r["chain"], *build_spec(r)])

    def set_policy(self, chain, policy):
        chain, policy = str(chain).upper(), str(policy).upper()
        if chain not in CHAINS or policy not in POLICIES:
            raise ValidationError("Bad chain or policy")
        return self._ipt(["-P", chain, policy])

    def ensure_baseline(self):
        results = []
        for chain, spec in BASELINE:
            if self._ipt(["-C", chain, *spec]).ok and self.live:
                continue  # already present
            results.append(self._ipt(["-I", chain, "1", *spec]))
        return results

    def counters(self, chain="INPUT"):
        if chain not in CHAINS:
            raise ValidationError("Bad chain")
        res = self._ipt(["-L", chain, "-n", "-v", "-x"])
        return parse_counters(res.stdout) if res.ok else {}

    # ---- anti-lockout
    def lockout_risk(self, rules, policies):
        if self.ssh_port is None or policies.get("INPUT", "DROP") != "DROP":
            return None
        for r in rules:
            if (r["chain"] == "INPUT" and r["action"] == "ACCEPT"
                    and r["protocol"] in ("tcp", "all") and r["dport"] in (self.ssh_port, None)):
                return None
        return (f"INPUT policy DROP without an ACCEPT rule for tcp/{self.ssh_port} "
                "could lock you out. Add an SSH rule first.")

    def backup(self):
        res = self._exec("iptables-save", [])
        if not self.live or not res.ok:
            return None
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        path = self.backup_dir / f"iptables-{time.strftime('%Y%m%d-%H%M%S')}.rules"
        path.write_text(res.stdout)
        return path

    def _rollback(self):
        with self._lock:
            p, self._pending = self._pending, None
        if p:
            self._exec("iptables-restore", [], stdin=p["backup"].read_text())

    def confirm(self):
        """Keep the new rules: cancel the pending automatic rollback."""
        with self._lock:
            p, self._pending = self._pending, None
        if p:
            p["timer"].cancel()
        return bool(p)

    def apply_with_rollback(self, work, seconds=60):
        """Run work(); unless confirm() is called within `seconds`, restore the old rules."""
        snap = self.backup() if self.live else None
        results = work()
        info = {"results": [r.as_dict() for r in results], "rollback_seconds": None}
        if snap:
            timer = threading.Timer(seconds, self._rollback)
            timer.daemon = True
            with self._lock:
                self._pending = {"backup": snap, "timer": timer, "deadline": time.time() + seconds}
            timer.start()
            info["rollback_seconds"] = seconds
            info["backup_file"] = str(snap)
        return info

    def sync_all(self, rules, policies, rollback_seconds=60):
        """Rebuild the kernel ruleset from the database (rules ordered by id)."""
        clean = [validate_rule(r) for r in rules]
        problem = self.lockout_risk(clean, policies)
        if problem:
            raise LockoutRisk(problem)

        def work():
            out = []
            for ch in CHAINS:                      # open first so we never cut ourselves off
                out += [self._ipt(["-P", ch, "ACCEPT"]), self._ipt(["-F", ch])]
            out += self.ensure_baseline()
            for r in sorted(clean, key=lambda x: x["id"] or 0):
                out.append(self._ipt(["-A", r["chain"], *build_spec(r)]))
            for ch, pol in policies.items():       # default policies last
                out.append(self.set_policy(ch, pol))
            return out

        return self.apply_with_rollback(work, rollback_seconds)

    def disable(self):
        """Disable filtering while preserving rules in the source-of-truth database."""
        results = []
        for chain in CHAINS:
            results.append(self.set_policy(chain, "ACCEPT"))
            results.append(self._ipt(["-F", chain]))
        return results
