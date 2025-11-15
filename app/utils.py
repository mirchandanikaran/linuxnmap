# app/utils.py
import socket
import subprocess
import re

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    finally:
        s.close()

def _extract_ip_from_nmap_report_line(line):
    """
    Extract IP from line like:
    'Nmap scan report for hostname (192.168.29.1)'
    or 'Nmap scan report for 192.168.29.1'
    Return IP string or None.
    """
    # attempt to find an IPv4 address in the line
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
    if m:
        return m.group(1)
    return None

def discover_alive_hosts(local_ip):
    """
    Return list of alive host IP strings on the /24 subnet.
    This function returns IPs only (not hostnames) to avoid resolution issues.
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
        # dedupe and sort
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
    Basic safety: allow localhost, 127.0.0.1, and RFC1918 private ranges.
    Block public IPv4 addresses by default (you can modify).
    """
    try:
        import ipaddress
        # If user supplied a string with spaces (e.g., "name (ip)"), attempt to extract IP
        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', target)
        if m:
            target_ip = m.group(1)
        else:
            target_ip = socket.gethostbyname(target)

        addr = ipaddress.ip_address(target_ip)
        if addr.is_loopback:
            return True, 'loopback'
        if addr.is_private:
            return True, 'private'
        return False, 'public addresses are blocked by safety policy'
    except socket.gaierror as e:
        return False, f'could not resolve target: {e}'
    except ValueError as e:
        return False, f'invalid IP: {e}'
    except Exception as e:
        return False, f'error checking target: {e}'
