"""
Finds and runs tshark for every analysis module.

Lookup order: the TSHARK_PATH environment variable, then PATH, then (on
Windows) the install folder Wireshark registers, then its default folders.
"""
import logging
import os
import shutil
import subprocess
import sys
from functools import lru_cache
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)

_WINDOWS_DEFAULTS = (
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
)


class TsharkNotFound(FileNotFoundError):
    """Subclass of FileNotFoundError, so existing except-clauses still match."""


def _windows_install_dir() -> Optional[str]:
    try:
        import winreg

        key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
            folder = winreg.QueryValueEx(k, "Path")[0]
    except OSError:
        return None
    exe = os.path.join(folder, "tshark.exe")
    return exe if os.path.isfile(exe) else None


@lru_cache(maxsize=1)
def tshark_path() -> Optional[str]:
    """Absolute path of the tshark executable, or None if it cannot be found."""
    configured = os.getenv("TSHARK_PATH")
    if configured:
        if os.path.isfile(configured):
            return configured
        logger.error("TSHARK_PATH=%s does not exist; looking elsewhere", configured)
    found = shutil.which("tshark")
    if found:
        return found
    if sys.platform == "win32":
        return _windows_install_dir() or next(
            (p for p in _WINDOWS_DEFAULTS if os.path.isfile(p)), None
        )
    return None


def fields_command(
    pcap: str,
    fields: Sequence[str],
    *,
    extra: Sequence[str] = (),
    read_options: Sequence[str] = (),
    display_filter: Optional[str] = None,
) -> List[str]:
    """`tshark -r <pcap> [read_options] -T fields [-Y filter] -e f1 -e f2 ... [extra]`."""
    exe = tshark_path()
    if exe is None:
        raise TsharkNotFound(
            "tshark not found: set TSHARK_PATH or add Wireshark to PATH"
        )
    cmd = [exe, "-r", pcap, *read_options, "-T", "fields"]
    if display_filter:
        cmd += ["-Y", display_filter]
    for field in fields:
        cmd += ["-e", field]
    return cmd + list(extra)


def run(cmd: Sequence[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Never raises on a non-zero exit: callers decide what a partial result means."""
    return subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
