"""
Network Traffic Analysis and PCAP Generation Service
====================================================
Application factory and the development entry point (`python app.py`).
Production uses wsgi.py. Routes live in server/blueprints/.

This module must stay cheap and free of side effects at import time: a pipeline
child process re-imports the main module when it starts.
"""

import os

from dotenv import load_dotenv

load_dotenv()  # Load variables from .env before any os.getenv() calls

_DEFAULT_ORIGINS = (
    "http://localhost,http://127.0.0.1,http://localhost:3000,http://127.0.0.1:3000"
)

_SWAGGER_TEMPLATE = {
    "swagger": "2.0",
    "info": {
        "title": "Network Traffic Analysis API",
        "description": "API documentation for the Network Traffic Analysis and PCAP Generation Service.",
        "version": "1.0.0",
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": 'JWT Authorization header using the Bearer scheme. Example: "Bearer {token}"',
        }
    },
}


def create_app(init_database: bool = True):
    """Builds the application. init_database=False skips migrations, TimescaleDB,
    admin seeding and cache cleanup, for callers that manage the schema themselves."""
    import faulthandler
    from datetime import timedelta

    from flasgger import Swagger
    from flask import Flask, Response, request
    from flask_cors import CORS
    from flask_migrate import Migrate

    import db_setup
    import settings
    from analysis_service import cleanup_packet_caches
    from blueprints import ALL_BLUEPRINTS
    from extensions import jwt, limiter, socketio
    from models import db

    faulthandler.enable()
    settings.configure_logging()
    for directory in settings.OUTPUT_DIRS:
        os.makedirs(directory, exist_ok=True)

    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
    if not app.config["JWT_SECRET_KEY"]:
        raise RuntimeError("JWT_SECRET_KEY environment variable must be set")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)

    allowed_origins = os.getenv("ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",")

    Swagger(app, template=_SWAGGER_TEMPLATE)
    jwt.init_app(app)
    socketio.init_app(app, cors_allowed_origins=allowed_origins)
    CORS(
        app,
        resources={r"/*": {"origins": allowed_origins}},
        supports_credentials=False,
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    )
    limiter.init_app(app)

    @app.before_request
    def handle_preflight():
        """Return 200 immediately for CORS preflight requests so @jwt_required()
        never sees them. Flask-CORS adds the required headers via after_request."""
        if request.method == "OPTIONS":
            return Response(status=200)

    db_setup.configure_database(app)
    Migrate(app, db, directory=db_setup.MIGRATIONS_DIR)

    for blueprint in ALL_BLUEPRINTS:
        app.register_blueprint(blueprint)

    if init_database:
        db_setup.init_database(app)
        # Clear any caches left from a previous run
        cleanup_packet_caches()

    return app


if __name__ == "__main__":
    from extensions import socketio
    from snapshot_scheduler import start_scheduler

    application = create_app()
    start_scheduler(application)
    socketio.run(
        application,
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5555")),
        debug=os.getenv("FLASK_DEBUG") == "1",
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
