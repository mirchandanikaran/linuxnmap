from flask import Flask
from flask_socketio import SocketIO
from flask_login import LoginManager
from .models import db
from .routes.auth import auth_bp
from .routes.dashboard import dashboard_bp
from .routes.scans import scans_bp
from .routes.terminal import terminal_bp
from .routes.history import history_bp

socketio = SocketIO(async_mode='eventlet')

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config.from_object('config.Config')

    db.init_app(app)

    with app.app_context():
        db.create_all()

    # Login manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        return User.query.get(int(user_id))

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(terminal_bp)
    app.register_blueprint(history_bp)

    # attach socketio to app
    socketio.init_app(app)
    app.socketio = socketio

    return app
