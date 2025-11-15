# app/routes/scans.py
from flask import Blueprint, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from ..models import db, ScanResult
import datetime
import threading
from ..scanner.runner import stream_nmap_scan
from ..utils import safe_target_check

scans_bp = Blueprint('scans', __name__, template_folder='../templates', url_prefix='')

@scans_bp.route('/start-scan', methods=['POST'])
@login_required
def start_scan():
    target = (request.form.get('target') or '').strip()
    scan_type = (request.form.get('scan_type') or '').strip()

    if not target:
        flash('Please provide a target.', 'danger')
        return redirect(url_for('dashboard.index'))

    ok, msg = safe_target_check(target)
    if not ok:
        flash(f'Target blocked by safety policy: {msg}', 'danger')
        return redirect(url_for('dashboard.index'))

    scan_map = {
        'ping_scan': ['-sn'],
        'fast_scan': ['-F'],
        'top_ports': ['--top-ports', '20'],
        'full_port_scan': ['-p-', '-T4'],
        'service_version': ['-sV'],
        'os_detection': ['-O'],
        'vuln_scan': ['--script', 'vuln']
    }
    args = scan_map.get(scan_type, ['-sn'])

    sr = ScanResult(user_id=current_user.id, target=target, scan_type=scan_type, started_at=datetime.datetime.utcnow())
    db.session.add(sr)
    db.session.commit()

    room = f"scan-{sr.id}"
    socketio = getattr(current_app, 'socketio', None)
    if socketio is None:
        flash('Internal server error: realtime socket not available.', 'danger')
        return redirect(url_for('dashboard.index'))

    def run_and_emit():
        output_lines = []
        for line in stream_nmap_scan(target, args):
            try:
                socketio.emit('scan_output', {'line': line}, room=room)
            except Exception:
                pass
            output_lines.append(line)
        sr.output = '\n'.join(output_lines)
        sr.completed_at = datetime.datetime.utcnow()
        db.session.commit()
        try:
            socketio.emit('scan_complete', {'scan_id': sr.id}, room=room)
        except Exception:
            pass

    thread = threading.Thread(target=run_and_emit, daemon=True)
    thread.start()

    return redirect(url_for('terminal.view_terminal') + f'?room={room}')
