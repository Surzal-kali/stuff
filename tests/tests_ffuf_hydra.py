"""Tests for payloads/ffuf.py + payloads/hydra.py parsers and version gating.

Regression tests for the Sept 9 review findings:
- ffuf table rows are path-FIRST ("admin [Status: 301, ...]") in real output
  (captured from ffuf 1.1.0 on Debian Trixie); the old bracket-first regex
  never matched -> silent empty findings.
- ffuf redirects ANSI \x1b[2K prefixes into redirected output; rows parsed
  after stripping.
- ffuf -of json -o <file> writes ONE object with a top-level "results" key;
  stdout stays human-table. Parse the file.
- -noninteractive is fatal on ffuf < 2.0 (Trixie ships 1.1.0): inject only
  when the installed binary supports it.
- hydra success-line regex matches the real "host: .. login: .. password: .."
  format (verified against the same live session).
"""

import functools
import http.server
import json
import re
import shutil
import subprocess
import threading

import pytest

from payloads.ffuf import (
    _FFUF_ROW_RE,
    _ffuf_supports_noninteractive,
    _inject_noninteractive,
    _parse_ffuf_output_file,
    _parse_ffuf_verdict,
    _path_from_record,
    ffuf_status,
    run_ffuf,
)
from payloads.hydra import _HYDRA_FOUND_RE, _parse_hydra_verdict


# --- fixtures ---------------------------------------------------------------

@pytest.fixture
def www_server(tmp_path):
    """In-process HTTP server: /admin -> 301, /backup.txt -> 200, else 404."""
    root = tmp_path / "www"
    (root / "admin").mkdir(parents=True)
    (root / "admin" / "index.html").write_text("ok")
    (root / "backup.txt").write_text("ok")
    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(root)
    )
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", root
    srv.shutdown()


# --- ffuf table-mode regex ---------------------------------------------------

def test_row_regex_matches_real_ffuf_output():
    """Real captured row format: path BEFORE the bracket block."""
    line = "admin                   [Status: 301, Size: 0, Words: 1, Lines: 1]"
    m = _FFUF_ROW_RE.search(line)
    assert m, "row regex must match real ffuf 1.1.0 table output"
    assert m.group("path") == "admin"
    assert m.group("status") == "301"


def test_row_regex_survives_ansi_prefixes():
    """ffuf writes \x1b[2K before rows in redirected output; verdict parser strips."""
    raw = "\x1b[2Kadmin     [Status: 301, Size: 0, Words: 1, Lines: 1]"
    verdict = _parse_ffuf_verdict(raw)
    assert verdict["findings_count"] == 1
    assert verdict["findings"][0]["path"] == "admin"
    assert verdict["findings"][0]["status"] == 301


def test_verdict_parses_multiple_rows_and_dedups():
    log = "\n".join([
        "\x1b[2Kadmin      [Status: 301, Size: 0, Words: 1, Lines: 1]",
        "\x1b[2Kbackup.txt [Status: 200, Size: 3, Words: 1, Lines: 2]",
        "\x1b[2Kadmin      [Status: 301, Size: 0, Words: 1, Lines: 1]",  # dup
        ":: URL              : http://127.0.0.1:8977/FUZZ",
    ])
    v = _parse_ffuf_verdict(log)
    assert v["findings_count"] == 2
    paths = {f["path"] for f in v["findings"]}
    assert paths == {"admin", "backup.txt"}
    assert v["meta"].get("URL") == "http://127.0.0.1:8977/FUZZ"


def test_row_regex_ignores_unmatched_noise():
    assert _parse_ffuf_verdict("no findings here")["findings_count"] == 0


# --- ffuf JSON file parsing ---------------------------------------------------

def test_output_file_parser_captured_shape(tmp_path):
    """One JSON object, top-level 'results', input as {'FUZZ': value} dict —
    shape captured from real ffuf 1.1.0 (-of json -o)."""
    captured = {
        "commandline": "ffuf -u http://127.0.0.1:8977/FUZZ -w wl.txt",
        "results": [
            {"input": {"FUZZ": "admin"}, "position": 1, "status": 301,
             "length": 0, "words": 1, "lines": 1,
             "redirectlocation": "/admin/", "url": "http://127.0.0.1:8977/admin"},
            {"input": {"FUZZ": "backup.txt"}, "position": 2, "status": 200,
             "length": 3, "words": 1, "lines": 2,
             "redirectlocation": "", "url": "http://127.0.0.1:8977/backup.txt"},
        ],
    }
    p = tmp_path / "out.json"
    p.write_text(json.dumps(captured))
    v = _parse_ffuf_output_file(str(p))
    assert v["findings_count"] == 2
    assert v["findings"][0]["path"] == "admin"
    assert v["findings"][0]["redirect"] == "/admin/"
    assert v["findings"][1]["path"] == "backup.txt"
    assert v["findings"][1]["status"] == 200


def test_output_file_parser_missing_or_garbage(tmp_path):
    assert _parse_ffuf_output_file(str(tmp_path / "nope.json")) is None
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    assert _parse_ffuf_output_file(str(p)) is None


def test_path_from_record_variants():
    assert _path_from_record({"input": {"FUZZ": "admin"}}) == "admin"
    assert _path_from_record({"input": ["a", "b"]}) == "a/b"
    assert _path_from_record({"url": "http://h/x"}) == "http://h/x"


# --- -noninteractive version gate ---------------------------------------------

def test_version_gate_matches_installed_ffuf():
    """Gate result must equal the installed ffuf's actual capability."""
    if shutil.which("ffuf") is None:
        pytest.skip("ffuf not installed")
    out = subprocess.run(["ffuf", "-V"], capture_output=True, text=True).stdout
    m = re.search(r"v?(\d+)\.(\d+)", out)
    ver = (int(m.group(1)), int(m.group(2)))
    assert _ffuf_supports_noninteractive() == (ver >= (2, 0))


def test_injection_disabled_on_old_ffuf(monkeypatch):
    """On Trixie's 1.1.0 the flag must NOT be injected (it is fatal there)."""
    monkeypatch.setattr("payloads.ffuf._noninteractive_supported", False)
    assert _inject_noninteractive([]) == []


def test_injection_when_supported_or_caller_supplied(monkeypatch):
    monkeypatch.setattr("payloads.ffuf._noninteractive_supported", True)
    assert _inject_noninteractive([]) == ["-noninteractive"]
    assert _inject_noninteractive(["-noninteractive"]) == ["-noninteractive"]


# --- end-to-end: real ffuf via run_ffuf/ffuf_status ----------------------------

@pytest.mark.skipif(shutil.which("ffuf") is None, reason="ffuf not installed")
def test_run_ffuf_end_to_end_finds_paths(www_server, tmp_path):
    """Launch a REAL run_ffuf against a live local server and poll to done.
    Proves the launch survives the version gate AND findings parse."""
    base, root = www_server
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nbackup.txt\nnope\n")
    launch = run_ffuf(url=f"{base}/FUZZ", wordlist=str(wl))
    assert launch["status"] == "running"
    job_id = launch["job_id"]

    result = None
    for _ in range(50):
        result = ffuf_status(job_id)
        if result["status"] == "done":
            break
        threading.Event().wait(0.2)
    assert result is not None and result["status"] == "done"
    assert result["findings_count"] == 2, result
    got = {f["path"]: f["status"] for f in result["findings"]}
    assert got == {"admin": 301, "backup.txt": 200}


# --- hydra ---------------------------------------------------------------------

def test_hydra_found_regex_real_format():
    line = "host: 192.168.90.114   login: root   password: toor"
    m = _HYDRA_FOUND_RE.match(line)
    assert m
    assert m.group("login") == "root"
    assert m.group("password") == "toor"


def test_hydra_parser_credentials_and_attempts():
    log = "\n".join([
        '[ATTEMPT] target ssh://192.168.90.114 - login "root" - pass "a" - 5 of 100',
        '[ATTEMPT] target ssh://192.168.90.114 - login "root" - pass "b" - 12 of 100',
        "host: 192.168.90.114   login: root   password: toor",
        "1 of 1 target successfully completed, 1 valid password found",
    ])
    v = _parse_hydra_verdict(log)
    assert v["credentials_found"] == 1
    assert v["credentials"][0] == {
        "host": "192.168.90.114", "login": "root", "password": "toor"}
    assert v["attempts"] == {"done": 12, "total": 100}
    assert v["status_line"] and "successfully completed" in v["status_line"]
