from flask import Blueprint, render_template
from flask_login import login_required, current_user
from ..utils import get_local_ip, discover_alive_hosts

dashboard_bp = Blueprint('dashboard', __name__, template_folder='../templates', url_prefix='')

@dashboard_bp.route('/')
@login_required
def index():
    local_ip = get_local_ip()
    alive = discover_alive_hosts(local_ip)
    return render_template('dashboard.html', local_ip=local_ip, alive_hosts=alive, current_user=current_user)
