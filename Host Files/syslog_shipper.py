"""
Ships alerts to R13's remote syslog collector — the alert-collection
mechanism R13/SMTEC confirmed (previously an open question in
INTEGRATION_GUIDE.md / README.md "points to confirm").

Tails two independent sources and forwards each JSON line as one syslog
message, unmodified:
  - Zeek's own notice.log   (Scan::*, SSH::Password_Guessing,
                             SSL::Invalid_Server_Cert — see tuning.zeek)
  - wp5_notices.log         (this analyzer's own PENM::* alerts)

Each source keeps its own syslog APP-NAME (zeek-notice / wp5-notice) so
R13 can tell them apart without having to parse the JSON payload first.

Transport: UDP, plain TCP, or TLS/TCP (RFC 5425 "TLS Transport Mapping for
Syslog") — R13's Logger listens on TLS-enabled TCP port 6514, so real
deployments set SYSLOG_PROTO=tcp SYSLOG_TLS=true SYSLOG_PORT=6514. Messages
are RFC 5424 formatted; TCP/TLS framing uses RFC 5425 octet-counting
("MSGLEN SP SYSLOG-MSG"), since a TCP byte stream has no message
boundaries of its own — this is why stdlib logging.handlers.SysLogHandler
(no framing, no TLS support at all) isn't used here.
"""

import json
import logging
import os
import socket
import ssl
import threading
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

ZEEK_NOTICE_LOG = os.environ.get("ZEEK_NOTICE_LOG", "notice.log")
WP5_NOTICE_LOG = os.environ.get("WP5_NOTICE_LOG", "wp5_notices.log")
NODE_HOSTNAME = os.environ.get("NODE_HOSTNAME") or socket.gethostname()

SYSLOG_HOST = os.environ.get("SYSLOG_HOST", "")
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "514"))
SYSLOG_PROTO = os.environ.get("SYSLOG_PROTO", "udp").lower()  # udp | tcp
SYSLOG_TLS = os.environ.get("SYSLOG_TLS", "false").strip().lower() in ("1", "true", "yes")
# Optional custom CA bundle to verify the Logger's cert against (PEM file).
# Leave unset to use the system trust store.
SYSLOG_TLS_CA_FILE = os.environ.get("SYSLOG_TLS_CA_FILE", "").strip()
# Skips certificate verification entirely. Lab/testing only — never use
# this against a real collector; it defeats the point of TLS.
SYSLOG_TLS_INSECURE = os.environ.get("SYSLOG_TLS_INSECURE", "false").strip().lower() in ("1", "true", "yes")

# PRI = facility*8 + severity. local0 (16) / info (6) -> 16*8+6 = 134.
_PRI = 134
_RECONNECT_DELAY = 3.0


def _rfc5424(app_name, msg):
    """Formats one RFC 5424 syslog message. MSG is the raw JSON alert line,
    passed through unmodified — R13 parses that JSON on its side."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
    return f"<{_PRI}>1 {ts} {NODE_HOSTNAME} {app_name} - - - {msg}"


class _SyslogSender:
    """One instance per source (zeek-notice / wp5-notice). UDP sends are
    fire-and-forget, one datagram per message. TCP/TLS keeps a persistent,
    auto-reconnecting connection and frames each message with RFC 5425
    octet-counting so the collector can split the stream correctly."""

    def __init__(self, app_name):
        self.app_name = app_name
        self._lock = threading.Lock()
        self._sock = None
        if SYSLOG_PROTO not in ("udp", "tcp"):
            raise ValueError(f"SYSLOG_PROTO must be 'udp' or 'tcp', got {SYSLOG_PROTO!r}")

    def send(self, line):
        message = _rfc5424(self.app_name, line)
        if SYSLOG_PROTO == "udp":
            self._send_udp(message)
        else:
            self._send_tcp(message)

    def _send_udp(self, message):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(message.encode("utf-8"), (SYSLOG_HOST, SYSLOG_PORT))
        except OSError as e:
            logger.warning("[%s] UDP send failed: %s", self.app_name, e)

    def _connect(self):
        raw = socket.create_connection((SYSLOG_HOST, SYSLOG_PORT), timeout=10)
        if not SYSLOG_TLS:
            return raw
        if SYSLOG_TLS_INSECURE:
            logger.warning(
                "[%s] SYSLOG_TLS_INSECURE=true — certificate verification "
                "disabled. Testing only; never use this against a real "
                "collector.", self.app_name,
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context(cafile=SYSLOG_TLS_CA_FILE or None)
        return ctx.wrap_socket(raw, server_hostname=SYSLOG_HOST)

    def _send_tcp(self, message):
        payload = message.encode("utf-8")
        framed = f"{len(payload)} ".encode("utf-8") + payload  # RFC 5425 octet-counting
        with self._lock:
            for attempt in (1, 2):  # one reconnect-and-retry
                try:
                    if self._sock is None:
                        self._sock = self._connect()
                    self._sock.sendall(framed)
                    return
                except (OSError, ssl.SSLError) as e:
                    proto_label = "TLS/TCP" if SYSLOG_TLS else "TCP"
                    logger.warning(
                        "[%s] %s send failed (attempt %d): %s",
                        self.app_name, proto_label, attempt, e,
                    )
                    self._close_socket()
                    if attempt == 1:
                        time.sleep(_RECONNECT_DELAY)
            logger.error("[%s] dropping message after failed retry", self.app_name)

    def _close_socket(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


def _tail(path, sender, label):
    """Waits for the file to appear, then ships each new line as-is."""
    while not os.path.exists(path):
        logger.info("Waiting for %s (%s)...", path, label)
        time.sleep(2)

    proto_label = f"{SYSLOG_PROTO}{'+tls' if SYSLOG_TLS else ''}"
    logger.info(
        "Found %s — shipping new %s lines to %s:%s/%s",
        path, label, SYSLOG_HOST, SYSLOG_PORT, proto_label,
    )

    with open(path, "r") as f:
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                json.loads(line)  # validate only; forward the original text
            except json.JSONDecodeError:
                continue  # Zeek/wp5_notices was mid-write; skip, don't ship partial JSON
            sender.send(line)


def main():
    zeek_thread = threading.Thread(
        target=_tail, args=(ZEEK_NOTICE_LOG, _SyslogSender("zeek-notice"), "Zeek notice.log"),
        daemon=True,
    )
    wp5_thread = threading.Thread(
        target=_tail, args=(WP5_NOTICE_LOG, _SyslogSender("wp5-notice"), "wp5_notices.log"),
        daemon=True,
    )
    zeek_thread.start()
    wp5_thread.start()
    zeek_thread.join()
    wp5_thread.join()


if __name__ == "__main__":
    if not SYSLOG_HOST:
        logger.error("SYSLOG_HOST is not set — nothing to ship. Exiting.")
        raise SystemExit(1)
    if SYSLOG_PROTO not in ("udp", "tcp"):
        logger.error("SYSLOG_PROTO must be 'udp' or 'tcp', got %r. Exiting.", SYSLOG_PROTO)
        raise SystemExit(1)
    if SYSLOG_TLS and SYSLOG_PROTO != "tcp":
        logger.error("SYSLOG_TLS=true requires SYSLOG_PROTO=tcp (TLS has no UDP equivalent here). Exiting.")
        raise SystemExit(1)
    logger.info(
        "Starting syslog shipper -> %s:%s/%s%s",
        SYSLOG_HOST, SYSLOG_PORT, SYSLOG_PROTO, " (TLS)" if SYSLOG_TLS else "",
    )
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down syslog shipper...")
