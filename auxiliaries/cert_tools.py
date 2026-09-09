"""Self-signed TLS certificate tooling for the OOB collaborator.

The collaborator listener (``listeners/collaborator.py``) serves HTTPS on
TCP 443 using a self-signed cert loaded from ``utils/plugins/certs/``.  These
tools own the 'generate cert' and 'clear cert' vocabulary so the secretary
model can stand up or tear down the certs without shell access.  Both tools
operate only on ``cert.pem`` and ``key.pem`` inside the certs directory and
never touch the directory itself (the collaborator expects it to exist).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Dict

from constants import framework_tool


def _cert_dir() -> Path:
    """Resolve the certs directory the same way the collaborator does."""
    return Path(os.getenv("WORKSPACE_ROOT", ".")) / "utils" / "plugins" / "certs"


@framework_tool(
    "Generate a fresh self-signed TLS certificate (cert.pem + key.pem) for "
    "the OOB collaborator's HTTPS listener on TCP 443. Writes the files into "
    "utils/plugins/certs/ and overwrites any existing cert there. Use this "
    "when the collaborator is skipping HTTPS because the certs are missing, "
    "or when you want to rotate the cert.",
    next_hints=["framework_health"],
)
def generate_certs(common_name: str = "localhost", days: int = 365) -> Dict[str, Any]:
    """Generate a self-signed cert + key pair via ``openssl``.

    Runs ``openssl req -x509 -newkey rsa:2048`` with no passphrase
    (``-nodes``) so the collaborator can load it unattended.  Overwrites
    any existing ``cert.pem`` / ``key.pem`` in the certs directory.

    Args:
        common_name: Subject CN for the cert (default ``"localhost"``).
        days: Validity period in days (default ``365``).

    Returns a dict with ``status`` (``"ok"`` / ``"error"``), the resolved
    certs directory, and the generated file paths on success.
    """
    import subprocess

    cert_dir = _cert_dir()
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"

    if shutil.which("openssl") is None:
        return {
            "status": "error",
            "error": "openssl not found on PATH; install openssl-cli to generate certs",
            "certs_dir": str(cert_dir),
        }

    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key_path), "-out", str(cert_path),
        "-days", str(days), "-nodes",
        "-subj", f"/CN={common_name}",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        return {
            "status": "error",
            "error": f"openssl invocation failed: {exc}",
            "certs_dir": str(cert_dir),
        }

    if proc.returncode != 0:
        return {
            "status": "error",
            "error": f"openssl exited {proc.returncode}",
            "stderr": proc.stderr.strip(),
            "certs_dir": str(cert_dir),
        }

    return {
        "status": "ok",
        "certs_dir": str(cert_dir),
        "cert": str(cert_path),
        "key": str(key_path),
        "common_name": common_name,
        "days": days,
    }


@framework_tool(
    "Clear the OOB collaborator's TLS certificate by removing cert.pem and "
    "key.pem from utils/plugins/certs/. After this, the collaborator's HTTPS "
    "listener on TCP 443 will be skipped on next startup (HTTP on 80 and DNS "
    "on UDP 53 keep working). The certs directory itself is preserved.",
    next_hints=["framework_health"],
)
def clear_certs() -> Dict[str, Any]:
    """Remove ``cert.pem`` and ``key.pem`` from the certs directory.

    Idempotent: missing files are not an error.  The directory itself is
    never removed so the collaborator's path resolution stays valid.

    Returns a dict with ``status`` (always ``"ok"``), the certs directory,
    and a list of the files that were removed.
    """
    cert_dir = _cert_dir()
    removed: list[str] = []
    for name in ("cert.pem", "key.pem"):
        target = cert_dir / name
        if target.is_file():
            target.unlink()
            removed.append(name)
    return {
        "status": "ok",
        "certs_dir": str(cert_dir),
        "removed": removed,
    }
