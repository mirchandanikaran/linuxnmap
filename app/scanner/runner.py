# app/scanner/runner.py
import subprocess
import shutil

def stream_nmap_scan(target, args):
    """
    Runs nmap with args and yields stdout lines as they appear.
    Emits helpful [ERROR] lines when nmap is missing or fails.
    """
    if not shutil.which("nmap"):
        yield "[ERROR] nmap is not installed or not in PATH. Install nmap and retry."
        return

    cmd = ["nmap"] + args + [target]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        yield f"[ERROR] Failed to start nmap: {e}"
        return

    try:
        for line in proc.stdout:
            yield line.rstrip("\n")
        proc.wait()
        if proc.returncode != 0:
            yield f"[ERROR] nmap exited with code {proc.returncode}"
    except Exception as e:
        yield f"[ERROR] Runtime exception while streaming nmap: {e}"
    finally:
        try:
            if proc and proc.poll() is None:
                proc.kill()
        except Exception:
            pass
