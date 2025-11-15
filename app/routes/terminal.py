from flask import Blueprint, render_template, request, current_app
from flask_login import login_required

terminal_bp = Blueprint('terminal', __name__, template_folder='../templates', url_prefix='')

@terminal_bp.route('/terminal')
@login_required
def view_terminal():
    room = request.args.get('room', '')
    return render_template('terminal.html', room=room)
