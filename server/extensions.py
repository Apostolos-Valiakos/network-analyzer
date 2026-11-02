"""Flask extensions, created unbound so blueprints can import them; bound to the
app in app.create_app()."""
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO

jwt = JWTManager()
socketio = SocketIO(async_mode="threading")
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300 per minute"],
    storage_uri="memory://",
)
