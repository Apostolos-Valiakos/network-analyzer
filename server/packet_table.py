"""
One cached tshark pass per capture, shared by every analysis module.

Role detection, privacy records, the traffic graph, clustering features and UE
extraction all read header fields of the same packets. Instead of each running
its own pass (or a much slower Python dissector), one `tshark -T fields` run
extracts the union of their fields into `<pcap>.packets.tsv`, and each module
reads the columns it needs.

Every occurrence of a field is kept, comma-joined: ip.src is "outer,inner" on a
GTP-U frame. The cache header records the capture's size and modification time
and the field list, so a replaced capture or a changed field list re-extracts.
"""
import logging
import os
import subprocess
from typing import Dict, Iterator, List, NamedTuple, Optional, Sequence, Tuple

import tshark

logger = logging.getLogger(__name__)

CACHE_SUFFIX = ".packets.tsv"
_TIMEOUT = 300

FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "_ws.col.Protocol",
    "eth.src",
    "eth.src.oui_resolved",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "sctp.srcport",
    "sctp.dstport",
    "gtp.teid",
    "ngap.procedureCode",
    "ngap.RAN_UE_NGAP_ID",
    "e2ap.procedureCode",
    "pfcp.msg_type",
    "http2.headers.path",
    "e212.imsi",
    "e212.mcc",
    "e212.mnc",
    "nas-5gs.mm.suci.supi_fmt",
    "nas-5gs.mm.suci.scheme_id",
    "nas-5gs.mm.suci.msin",
    "nas-5gs.5g_tmsi",
    "nas-5gs.pdu_session_id",
]
_INDEX = {name: i for i, name in enumerate(FIELDS)}


class TsharkFailed(RuntimeError):
    """tshark could not read the capture at all."""


def _cache_header(pcap: str) -> str:
    st = os.stat(pcap)
    return f"#{st.st_size}\t{st.st_mtime_ns}\t{','.join(FIELDS)}"


def _extract(pcap: str) -> str:
    cmd = tshark.fields_command(
        pcap,
        FIELDS,
        read_options=["-n"],
        extra=["-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"],
    )
    result = tshark.run(cmd, timeout=_TIMEOUT)
    if result.returncode != 0:
        if not result.stdout:
            raise TsharkFailed(f"tshark failed (exit {result.returncode}): {result.stderr.strip()[:300]}")
        # e.g. exit 14 "cut short in the middle of a packet": every complete
        # packet was still read, so the output is usable.
        logger.warning(
            "tshark exit %d on %s, using partial output: %s",
            result.returncode, pcap, result.stderr.strip()[:300],
        )
    return result.stdout


def _load(pcap: str) -> str:
    """The tab-separated table for `pcap`, one line per frame."""
    cache_path = pcap + CACHE_SUFFIX
    header = _cache_header(pcap)
    try:
        with open(cache_path, encoding="utf-8", newline="\n") as f:
            if f.readline().rstrip("\n") == header:
                return f.read()
    except OSError:
        pass  # no cache yet

    text = _extract(pcap)
    # Atomic, because the web process and the pipeline child can both get here.
    tmp_path = f"{cache_path}.{os.getpid()}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(header + "\n" + text)
        os.replace(tmp_path, cache_path)
    except OSError:
        logger.warning("Could not write packet cache %s", cache_path)
    return text


def ensure(pcap: str) -> None:
    """Extracts the table if needed. Raises when tshark cannot read the capture:
    FileNotFoundError (tshark missing), TimeoutExpired or TsharkFailed."""
    _load(pcap)


def columns(pcap: str, fields: Sequence[str]) -> Iterator[List[str]]:
    """Yields, for every frame, the values of `fields` in that order."""
    indexes = [_INDEX[f] for f in fields]
    width = len(FIELDS)
    for line in _load(pcap).split("\n"):
        if not line:
            continue
        cols = line.split("\t")
        if len(cols) < width:
            cols += [""] * (width - len(cols))
        yield [cols[i] for i in indexes]


def lines(pcap: str, fields: Sequence[str], require: Optional[str] = None) -> str:
    """The same columns as tab-separated text, in the layout `tshark -T fields
    -e ...` would print. `require` keeps only frames where that field is set."""
    selected = list(fields)
    if require is None:
        rows = columns(pcap, selected)
    else:
        rows = (
            row[:-1]
            for row in columns(pcap, selected + [require])
            if row[-1]
        )
    return "\n".join("\t".join(row) for row in rows) + "\n"


def first(value: str) -> str:
    """First occurrence of a comma-joined field value (the outermost header)."""
    return value.split(",", 1)[0]


class OuterPacket(NamedTuple):
    """One IPv4 frame as seen through its outermost IP header."""

    time: float
    length: int  # bytes captured
    src: str
    dst: str
    ports: Optional[Tuple[int, int]]  # outermost TCP/UDP header, if any


_OUTER_FIELDS = [
    "frame.time_epoch", "frame.cap_len", "frame.protocols", "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
]


def _outer_ports(layers: List[str], tcp_src, tcp_dst, udp_src, udp_dst):
    """Ports of the first TCP/UDP header after the outer IP. A transport header
    quoted inside an ICMP error describes another packet and does not count."""
    start = layers.index("ip") + 1 if "ip" in layers else 0
    for layer in layers[start:]:
        if layer == "icmp":
            return None
        if layer == "tcp":
            return (int(first(tcp_src)), int(first(tcp_dst))) if tcp_src else None
        if layer == "udp":
            return (int(first(udp_src)), int(first(udp_dst))) if udp_src else None
    return None


def outer_packets(pcap: str) -> Iterator[Optional[OuterPacket]]:
    """Yields one item per frame: an OuterPacket, or None for non-IPv4 frames."""
    for t, length, protocols, src, dst, tsp, tdp, usp, udp in columns(pcap, _OUTER_FIELDS):
        if not src:
            yield None
            continue
        yield OuterPacket(
            float(t),
            int(length),
            first(src),
            first(dst),
            _outer_ports(protocols.split(":"), tsp, tdp, usp, udp),
        )


def row_dicts(pcap: str, fields: Sequence[str]) -> Iterator[Dict[str, str]]:
    """Like columns(), as {field: value} dictionaries."""
    names = list(fields)
    for row in columns(pcap, names):
        yield dict(zip(names, row))
