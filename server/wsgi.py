"""Production entry point: gunicorn -w 1 --threads 100 wsgi:app

One worker, because Socket.IO clients and the rate limiter live in process
memory; threads serve concurrent requests and websockets.
"""
from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402
from snapshot_scheduler import start_scheduler  # noqa: E402

app = create_app()
start_scheduler(app)
