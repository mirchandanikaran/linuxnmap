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
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
    if m:
        return m.group(1)
    return None

def discover_alive_hosts(local_ip):
    """
    Run 'nmap -sn <subnet>' and return a sorted, unique list of IP strings.
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
        return sorted(list(dict.fromkeys(alive)))
    except subprocess.CalledProcessError:
        return []
    except FileNotFoundError:
        return []
    except Exception:
        return []

def safe_target_check(target):
    """
    Allow only loopback and private addresses; block public addresses by default.
    Accept inputs that might contain a hostname plus IP by extracting any IPv4 present.
    """
    try:
        import ipaddress
        # extract ip if present like "host (192.168.1.5)"
        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', str(target))
        if m:
            target_ip = m.group(1)
        else:
            target_ip = socket.gethostbyname(str(target))

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
