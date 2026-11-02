"""
Paths and external-service settings shared by the backend modules.

Every directory is absolute and resolved from this file's location, so output
lands in the same place whether the server starts from the repository root,
from server/, or in Docker (WORKDIR /app, where /app/results is a volume).
"""
import logging
import os

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(SERVER_DIR, "uploads")
PCAP_GEN_OUTPUT_DIR = os.path.join(SERVER_DIR, "generated_pcaps")
CLUSTERING_OUTPUT_DIR = os.path.join(SERVER_DIR, "cluster_analysis")
RESULTS_OUTPUT_DIR = os.path.join(SERVER_DIR, "results")

OUTPUT_DIRS = (UPLOAD_FOLDER, PCAP_GEN_OUTPUT_DIR, CLUSTERING_OUTPUT_DIR, RESULTS_OUTPUT_DIR)

_DEFAULT_SENSOR_URL = "http://172.18.0.1:5005"


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def doc(filename: str) -> str:
    """Absolute path of a Swagger file in server/docs, for @swag_from."""
    return os.path.join(SERVER_DIR, "docs", filename)


def sensor_url(path: str = "") -> str:
    """Base URL of the sensor's pcap_server.py, read on each call."""
    return os.getenv("SENSOR_URL", _DEFAULT_SENSOR_URL) + path


def secret_token() -> str:
    """Shared secret for sensor <-> backend calls, read on each call."""
    return os.getenv("SECRET_TOKEN", "")


def sensor_headers(**extra) -> dict:
    return {"X-Internal-Token": secret_token(), **extra}
