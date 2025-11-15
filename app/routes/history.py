from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from ..models import ScanResult

history_bp = Blueprint('history', __name__, template_folder='../templates', url_prefix='')

@history_bp.route('/history')
@login_required
def view_history():
    scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.started_at.desc()).all()
    return render_template('history.html', scans=scans)

@history_bp.route('/api/scan-output/<int:scan_id>')
@login_required
def api_scan_output(scan_id):
    sr = ScanResult.query.get_or_404(scan_id)
    if sr.user_id != current_user.id:
        return 'forbidden', 403
    return sr.output or ''
