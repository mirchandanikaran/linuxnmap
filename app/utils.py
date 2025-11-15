# app/utils.py
import socket
import subprocess
import re

def get_local_ip():
    """Return the best-effort local IP on the LAN (e.g. 192.168.x.x)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def _extract_ip_from_nmap_report_line(line):
    """
    Extract IPv4 address from a line such as:
      'Nmap scan report for hostname (192.168.29.1)'
    or
      'Nmap scan report for 192.168.29.1'
    """
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
    return m.group(1) if m else None

def discover_alive_hosts(local_ip):
    """
    Run 'nmap -sn <local_subnet>' and return sorted unique list of IP strings.
    If nmap is missing or errors out, return an empty list.
    """
    try:
        subnet = local_ip.rsplit('.', 1)[0] + '.0/24'
        cmd = ['nmap', '-sn', subnet]
        out = subprocess.check_output(cmd, text=True)
        alive = []
        for line in out.splitlines():
            if 'Nmap scan report for' in line:
                ip = _extract_ip_from_nmap_report_line(line)
                if ip:
                    alive.append(ip)
        # dedupe & sort
        return sorted(list(dict.fromkeys(alive)))
    except subprocess.CalledProcessError:
        return []
    except FileNotFoundError:
        # nmap not installed
        return []
    except Exception:
        return []

def safe_target_check(target):
    """
    Allow only loopback and RFC1918 private addresses by default.
    Accepts input that may contain a hostname + ip like "host (192.168.0.5)".
    Returns (True, reason) on allowed targets, (False, message) otherwise.
    """
    try:
        import ipaddress
        # extract embedded IPv4 if present
        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', str(target))
        if m:
            target_ip = m.group(1)
        else:
            target_ip = socket.gethostbyname(str(target))

        addr = ipaddress.ip_address(target_ip)
        if addr.is_loopback:
            return True, "loopback"
        if addr.is_private:
            return True, "private"
        return False, "public addresses are blocked by safety policy"
    except socket.gaierror as e:
        return False, f"could not resolve target: {e}"
    except ValueError as e:
        return False, f"invalid IP: {e}"
    except Exception as e:
        return False, f"error checking target: {e}"
