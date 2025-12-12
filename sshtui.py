#!/usr/bin/env python3

import curses
import os
import re
import shutil
import subprocess
import time
import pwd
from typing import List, Optional, Tuple

# ===================== Firewall =====================

def ipt_rule_exists(spec: str, chain: str = "INPUT") -> bool:
    return subprocess.run(f"sudo iptables -C {chain} {spec}", shell=True).returncode == 0

def ipt_add_once(spec: str, chain: str = "INPUT") -> None:
    if not ipt_rule_exists(spec, chain):
        subprocess.run(f"sudo iptables -A {chain} {spec}", shell=True, check=True)

def ipt_delete_rule(spec: str, chain: str = "INPUT") -> str:
    if ipt_rule_exists(spec, chain):
        r = subprocess.run(f"sudo iptables -D {chain} {spec}", shell=True)
        return "✔ Rule deleted" if r.returncode == 0 else "⚠ Delete failed"
    try:
        out = subprocess.check_output(f"sudo iptables -S {chain}", shell=True, text=True)
        lines = [l for l in out.splitlines() if l.startswith(f"-A {chain} ")]
        for idx, line in enumerate(lines, start=1):
            if spec in line:
                r = subprocess.run(f"sudo iptables -D {chain} {idx}", shell=True)
                return "✔ Rule deleted" if r.returncode == 0 else "⚠ Delete by index failed"
        return "ℹ Rule not found"
    except Exception as e:
        return f"⚠ List failed: {e}"

def get_firewall_status() -> str:
    try:
        output = subprocess.check_output("sudo iptables -L -n -v", shell=True, text=True)
        lines = output.splitlines()
        input_policy, output_policy = "UNKNOWN", "UNKNOWN"
        rules = 0
        for line in lines:
            if line.startswith("Chain INPUT"):
                input_policy = "ACCEPT" if "ACCEPT" in line else "DROP" if "DROP" in line else input_policy
            elif line.startswith("Chain OUTPUT"):
                output_policy = "ACCEPT" if "ACCEPT" in line else "DROP" if "DROP" in line else output_policy
            elif line.strip() and not line.startswith("pkts "):
                rules += 1
        return f"Incoming: {input_policy} | Outgoing: {output_policy} | Rules: {rules}"
    except Exception as e:
        return f"⚠ Error: {e}"

def list_open_ports() -> List[str]:
    try:
        output = subprocess.check_output("ss -tuln", shell=True, text=True)
        lines = output.strip().split("\n")[1:]
        ports = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                ports.append(parts[4])
        return ports if ports else ["No open ports detected"]
    except Exception as e:
        return [f"Error: {e}"]

def enable_lockdown(allowed_ports: List[int]) -> str:
    try:
        subprocess.run("sudo iptables -F", shell=True, check=True)
        subprocess.run("sudo iptables -P INPUT DROP", shell=True, check=True)
        subprocess.run("sudo iptables -P FORWARD DROP", shell=True, check=True)
        subprocess.run("sudo iptables -P OUTPUT ACCEPT", shell=True, check=True)
        subprocess.run("sudo iptables -A INPUT -i lo -j ACCEPT", shell=True, check=True)
        subprocess.run("sudo iptables -A OUTPUT -o lo -j ACCEPT", shell=True, check=True)
        subprocess.run("sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", shell=True, check=True)
        for port in allowed_ports:
            ipt_add_once(f"-p tcp --dport {port} -j ACCEPT")
        subprocess.run("sudo iptables -A INPUT -p icmp -j ACCEPT", shell=True, check=True)
        return f"✔ Lockdown enabled (allowed: {', '.join(map(str, allowed_ports))})" if allowed_ports else "✔ Full lockdown enabled"
    except Exception as e:
        return f"⚠ Error enabling lockdown: {e}"

def disable_lockdown() -> str:
    try:
        subprocess.run("sudo iptables -F", shell=True, check=True)
        subprocess.run("sudo iptables -P INPUT ACCEPT", shell=True, check=True)
        subprocess.run("sudo iptables -P OUTPUT ACCEPT", shell=True, check=True)
        subprocess.run("sudo iptables -P FORWARD ACCEPT", shell=True, check=True)
        return "✔ Lockdown mode disabled"
    except Exception as e:
        return f"⚠ Error disabling lockdown: {e}"

def block_ip(ip: str) -> str:
    try:
        ipt_add_once(f"-s {ip} -j DROP")
        return f"✔ Blocked IP: {ip}"
    except Exception as e:
        return f"⚠ Error blocking IP {ip}: {e}"

def unblock_ip(ip: str) -> str:
    return ipt_delete_rule(f"-s {ip} -j DROP")

# ===================== SSH security =====================

SSHD_CFG = "/etc/ssh/sshd_config"

def _detect_sshd_unit() -> str:
    try:
        out = subprocess.check_output("systemctl list-unit-files | awk '{print $1}'", shell=True, text=True)
        if "sshd.service" in out:
            return "sshd"
        if "ssh.service" in out:
            return "ssh"
    except Exception:
        pass
    return "sshd"

def restart_sshd() -> str:
    unit = _detect_sshd_unit()
    for cmd in (f"sudo systemctl restart {unit}", f"sudo service {unit} restart"):
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "✔ sshd restarted"
        except Exception:
            continue
    return "⚠ Could not restart sshd"

def get_current_ssh_port() -> int:
    try:
        with open(SSHD_CFG, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                m = re.match(r"Port\s+(\d+)", s, re.IGNORECASE)
                if m:
                    return int(m.group(1))
    except Exception:
        pass
    return 22

def _backup_sshd_config() -> str:
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = os.path.expanduser(f"~/sshd_config.bak.{ts}")
    shutil.copy2(SSHD_CFG, backup)
    return backup

def change_ssh_port(new_port: int, open_in_iptables: bool = True, close_old: bool = False) -> str:
    if not (1 <= new_port <= 65535):
        return "⚠ Invalid port"
    old_port = get_current_ssh_port()
    try:
        backup = _backup_sshd_config()
    except Exception as e:
        return f"⚠ Backup failed: {e}"
    try:
        lines, found = [], False
        with open(SSHD_CFG, "r", encoding="utf-8") as f:
            for line in f:
                if re.match(r"\s*#?\s*Port\s+\d+", line):
                    lines.append(f"Port {new_port}\n")
                    found = True
                else:
                    lines.append(line)
        if not found:
            lines.append(f"\nPort {new_port}\n")
        with open(SSHD_CFG, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        return f"⚠ Edit failed: {e}"
    try:
        if open_in_iptables:
            ipt_add_once(f"-p tcp --dport {new_port} -j ACCEPT")
        if close_old and old_port != new_port:
            _ = ipt_delete_rule(f"-p tcp --dport {old_port} -j ACCEPT")
    except Exception as e:
        return f"⚠ iptables update failed: {e}"
    return f"{restart_sshd()} | Port {old_port}→{new_port} | Backup: {backup}"

# ---- SSH key helpers ----

def ssh_key_paths(key_type: str) -> Tuple[str, str]:
    home = os.path.expanduser("~")
    if key_type == "rsa":
        priv = os.path.join(home, ".ssh", "id_rsa")
    else:
        priv = os.path.join(home, ".ssh", "id_ed25519")
    pub = priv + ".pub"
    return priv, pub

def ssh_key_present(path: Optional[str], key_type: str) -> Tuple[bool, str, str]:
    priv, pub = ssh_key_paths(key_type)
    if path:
        priv = path
        pub = path + ".pub"
    return (os.path.exists(priv) or os.path.exists(pub)), priv, pub

def read_public_key(path: Optional[str], key_type: str) -> List[str]:
    _, pub = ssh_key_paths(key_type)
    if path:
        pub = path + ".pub"
    if os.path.exists(pub):
        try:
            with open(pub, "r", encoding="utf-8") as f:
                return [f"Path: {pub}", f"Size: {os.path.getsize(pub)} bytes", "", f.read().strip()]
        except Exception as e:
            return [f"⚠ Read error: {e}"]
    return ["No public key found"]

def generate_ssh_key(path: Optional[str] = None, key_type: str = "ed25519", comment: str = "") -> str:
    if key_type not in ("ed25519", "rsa"):
        return "⚠ Invalid key type"
    exists, priv, pub = ssh_key_present(path, key_type)
    if exists:
        return f"ℹ Key already present: {priv} (.pub)"
    os.makedirs(os.path.dirname(priv), exist_ok=True)
    try:
        cmd = f'ssh-keygen -t {key_type} -f "{priv}" -N ""'
        if comment:
            cmd += f' -C "{comment}"'
        subprocess.run(cmd, shell=True, check=True)
        return f"✔ Key created: {priv} (.pub available)"
    except subprocess.CalledProcessError as e:
        return f"⚠ ssh-keygen failed: {e.returncode}"
    except Exception as e:
        return f"⚠ Error: {e}"

# ---- SSH logs and sessions ----

def view_ssh_login_attempts(max_lines: int = 300) -> List[str]:
    import collections
    rgx = re.compile(r"(Failed|Accepted).*(password|publickey)", re.IGNORECASE)
    env = dict(os.environ, SYSTEMD_COLORS="0", LC_ALL="C")
    try:
        r = subprocess.run(
            ['journalctl','-u','ssh','-u','sshd','--since','24 hours ago','-n','1200','--output','short-iso','--no-pager'],
            text=True, capture_output=True, timeout=3, env=env
        )
        if r.returncode == 0 and r.stdout:
            dq = collections.deque(maxlen=max_lines)
            for line in r.stdout.splitlines():
                if 'sshd' in line and rgx.search(line):
                    dq.append(line)
            if dq:
                return list(dq)
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    try:
        path = "/var/log/auth.log"
        if os.path.exists(path) and os.access(path, os.R_OK):
            dq = collections.deque(maxlen=max_lines)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if 'sshd' in line and rgx.search(line):
                        dq.append(line.rstrip())
            if dq:
                return list(dq)
        return ["No matching login events in last 24h"]
    except Exception:
        return ["No data (permission denied or no journal)"]

def _pid_to_user(pid: int) -> str:
    try:
        st = os.stat(f"/proc/{pid}")
        return pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        return "unknown"

def view_current_ssh_sessions() -> List[str]:
    port = get_current_ssh_port()
    cmds = [
        f"sudo ss -tnp state established sport = :{port}",
        f"ss -tnp state established sport = :{port}",
    ]
    lines: List[str] = []
    for cmd in cmds:
        try:
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=2)
            if out.strip():
                lines = out.strip().splitlines()
                break
        except Exception:
            continue
    sessions: List[str] = []
    rgx_pid = re.compile(r"pid=(\d+)")
    for ln in lines[1:]:
        if "sshd" not in ln:
            continue
        parts = ln.split()
        if len(parts) < 5:
            continue
        local = parts[3]
        peer = parts[4]
        pids = [int(m) for m in rgx_pid.findall(ln)]
        if not pids:
            sessions.append(f"{peer} -> {local} (sshd)")
            continue
        for pid in sorted(set(pids)):
            user = _pid_to_user(pid)
            sessions.append(f"{peer} -> {local} pid={pid} user={user}")
    return sessions if sessions else ["No active SSH sessions detected"]

def get_ssh_fw_rules(port: int) -> List[str]:
    lines = [f"Current SSH port: {port}", ""]
    try:
        out = subprocess.check_output("sudo iptables -S INPUT", shell=True, text=True)
        matches = [l for l in out.splitlines() if f"--dport {port}" in l]
        if matches:
            lines.append("iptables INPUT rules for SSH port:")
            lines.extend(matches)
        else:
            lines.append("No explicit iptables ACCEPT/DROP rules for this port found in INPUT.")
    except Exception as e:
        lines.append(f"⚠ iptables query failed: {e}")
    return lines

# ===================== UI helpers =====================

MENU = [
    "View Open Ports",
    "Enable Lockdown",
    "Disable Lockdown",
    "Block IP",
    "Unblock IP",
    "SSH: Change Port",
    "SSH: View Current Port & Rules",
    "SSH: Generate Key",
    "SSH: View Public Key",
    "SSH: View Login Attempts",
    "SSH: View Current Sessions",
    "Quit",
]

def draw_header(stdscr, title: str):
    h, w = stdscr.getmaxyx()
    stdscr.addstr(1, 2, title, curses.A_BOLD)
    bar = "─" * max(0, w - 4 - len(title))
    stdscr.addstr(1, 2 + len(title), bar)

def prompt(stdscr, y: int, x: int, label: str) -> str:
    curses.echo()
    stdscr.addstr(y, x, label)
    stdscr.clrtoeol()
    val = stdscr.getstr().decode().strip()
    curses.noecho()
    return val

def show_scroller(stdscr, title: str, lines: List[str]):
    idx = 0
    while True:
        stdscr.erase()
        draw_header(stdscr, title)
        h, w = stdscr.getmaxyx()
        view = lines[idx: idx + h - 5]
        for i, l in enumerate(view):
            stdscr.addstr(3 + i, 2, l[: w - 4])
        stdscr.addstr(h - 2, 2, "[↑/↓] Scroll  [Q] Back")
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q")):
            break
        elif ch == curses.KEY_UP and idx > 0:
            idx -= 1
        elif ch == curses.KEY_DOWN and idx < max(0, len(lines) - (h - 5)):
            idx += 1

# ===================== Unified Dashboard =====================

def unified_dashboard(stdscr) -> None:
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)

    idx = 0
    message = ""

    while True:
        stdscr.erase()
        draw_header(stdscr, "Simple-SSH-Hardening-Tool")
        h, w = stdscr.getmaxyx()
        stdscr.addstr(2, 2, get_firewall_status()[: w - 4])

        for i, opt in enumerate(MENU):
            if i == idx:
                stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
                stdscr.addstr(4 + i, 4, f"> {opt}")
                stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
            else:
                stdscr.addstr(4 + i, 4, f"  {opt}")

        if message:
            stdscr.addstr(h - 4, 2, message[: w - 4])
        stdscr.addstr(h - 2, 2, "[↑↓] Move  [Enter] Select  [Q] Exit")
        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q")):
            break
        elif ch == curses.KEY_UP:
            idx = (idx - 1) % len(MENU)
        elif ch == curses.KEY_DOWN:
            idx = (idx + 1) % len(MENU)
        elif ch in (10, 13):
            choice = MENU[idx]
            if choice == "Quit":
                break
            elif choice == "View Open Ports":
                ports = list_open_ports()
                show_scroller(stdscr, "Open Ports", ports)
            elif choice == "Enable Lockdown":
                ports_str = prompt(stdscr, h - 6, 2, "Allow TCP ports (comma-separated, blank=none): ")
                ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()] if ports_str else []
                message = enable_lockdown(ports)
            elif choice == "Disable Lockdown":
                message = disable_lockdown()
            elif choice == "Block IP":
                ip = prompt(stdscr, h - 6, 2, "IP to block: ")
                if ip:
                    message = block_ip(ip)
            elif choice == "Unblock IP":
                ip = prompt(stdscr, h - 6, 2, "IP to unblock: ")
                if ip:
                    message = unblock_ip(ip)
            elif choice == "SSH: Change Port":
                curr = get_current_ssh_port()
                p = prompt(stdscr, h - 6, 2, f"New SSH port (current {curr}): ")
                newp = int(p) if p.isdigit() else curr
                open_fw = prompt(stdscr, h - 5, 2, "Open new port in iptables? [y/N]: ").lower().startswith("y")
                close_old = prompt(stdscr, h - 4, 2, "Close old port in iptables? [y/N]: ").lower().startswith("y")
                message = change_ssh_port(newp, open_in_iptables=open_fw, close_old=close_old)
            elif choice == "SSH: View Current Port & Rules":
                port = get_current_ssh_port()
                lines = get_ssh_fw_rules(port)
                show_scroller(stdscr, "SSH Current Port & iptables Rules", lines)
            elif choice == "SSH: Generate Key":
                kt = prompt(stdscr, h - 8, 2, "Key type [ed25519|rsa] (default ed25519): ") or "ed25519"
                path = prompt(stdscr, h - 7, 2, "Key path base (blank=~/.ssh/id_<type>): ")
                comment = prompt(stdscr, h - 6, 2, "Key comment (optional): ")
                present, priv, _ = ssh_key_present(path or None, kt)
                if present:
                    message = f"ℹ Key already present: {priv} (.pub)"
                else:
                    message = generate_ssh_key(path or None, kt, comment)
            elif choice == "SSH: View Public Key":
                kt = prompt(stdscr, h - 6, 2, "Key type to view [ed25519|rsa] (default ed25519): ") or "ed25519"
                path = prompt(stdscr, h - 5, 2, "Key path base (blank=default): ")
                lines = read_public_key(path or None, kt)
                show_scroller(stdscr, "Public Key", lines)
            elif choice == "SSH: View Login Attempts":
                lines = view_ssh_login_attempts(300)
                show_scroller(stdscr, "SSH Login Attempts (24h)", lines)
            elif choice == "SSH: View Current Sessions":
                lines = view_current_ssh_sessions()
                show_scroller(stdscr, "Current SSH Sessions (true sshd only)", lines)

# ===================== Entry =====================

if __name__ == "__main__":
    curses.wrapper(unified_dashboard)
