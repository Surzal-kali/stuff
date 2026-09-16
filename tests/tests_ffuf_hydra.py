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
# Import program_scope BEFORE any test runs so its module-level
# load_dotenv(override=True) fires here, not inside a lazy import during a
# test (which would clobber a monkeypatched WORKSPACE_ROOT).
import auxiliaries.program_scope  # noqa: F401

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


# --- default wordlist fallback (ffuf) ----------------------------------------

def test_run_ffuf_uses_default_wordlist_when_empty(monkeypatch):
    """Empty wordlist falls back to the framework default and flags it."""
    import payloads.ffuf as ffuf_mod
    from utils.wordlists import resolve_default_wordlist

    default = resolve_default_wordlist("ffuf")
    if not default:
        pytest.skip("default ffuf wordlist not installed")

    captured = {}

    def fake_launch(cmd, *, tool_name, timeout, verdict_parser):
        captured["cmd"] = cmd
        return {"job_id": "j1", "status": "running", "tool": tool_name}

    monkeypatch.setattr(ffuf_mod, "launch_job", fake_launch)

    r = ffuf_mod.run_ffuf(url="http://127.0.0.1/FUZZ", wordlist="")
    assert r["status"] == "running"
    assert r["default_wordlist_used"] is True
    assert r["wordlist"] == default
    # the default must actually be on the command line via -w
    assert "-w" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("-w") + 1] == default


def test_run_ffuf_explicit_wordlist_not_flagged_default(monkeypatch):
    import payloads.ffuf as ffuf_mod
    captured = {}

    def fake_launch(cmd, *, tool_name, timeout, verdict_parser):
        captured["cmd"] = cmd
        return {"job_id": "j2", "status": "running", "tool": tool_name}

    # resolve_wordlist does a real file-existence check; the test wordlist
    # doesn't exist on disk, so mock it to return the path as-is so we
    # reach the launch_job call (which is what this test exercises).
    monkeypatch.setattr(ffuf_mod, "resolve_wordlist", lambda wl: wl)
    monkeypatch.setattr(ffuf_mod, "launch_job", fake_launch)
    r = ffuf_mod.run_ffuf(url="http://127.0.0.1/FUZZ", wordlist="/tmp/custom.txt")
    assert r["default_wordlist_used"] is False
    assert r["wordlist"] == "/tmp/custom.txt"
    assert captured["cmd"][captured["cmd"].index("-w") + 1] == "/tmp/custom.txt"


def test_run_ffuf_errors_when_no_default_available(monkeypatch, tmp_path):
    import payloads.ffuf as ffuf_mod
    monkeypatch.setattr(
        "utils.wordlists.DEFAULT_FFUF_WORDLIST", "no/such/list.txt"
    )
    monkeypatch.setattr("utils.wordlists.WORDLISTS_ROOT", tmp_path)
    r = ffuf_mod.run_ffuf(url="http://127.0.0.1/FUZZ", wordlist="")
    assert r["status"] == "error"
    assert "list_wordlists" in r["error"]


# --- scan-config auto-injection (Intigriti RoE) -------------------------------

def test_inject_scan_config_adds_headers_and_rate(monkeypatch, tmp_path):
    """When scope_handle+scope_platform point to an intigriti program with
    mandated UA/header/rate, _inject_scan_config adds -H and -rate flags."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("INTIGRITI_USERNAME", "surzvtr5h")
    import json as _json
    cache_dir = tmp_path / "scope"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "intigriti_test.json").write_text(_json.dumps({
        "platform": "intigriti", "handle": "test",
        "testing_requirements": {
            "user_agent": "User-Agent: <standard browser/tool user agent> <intigriti:{Username}>",
            "request_header": "X-Intigriti-Username: {Username}",
            "max_requests_per_second": 20,
        },
    }))
    from payloads.ffuf import _inject_scan_config
    extra, cfg = _inject_scan_config([], "http://test.com/FUZZ", "test", "intigriti")
    assert cfg is not None
    assert "-H" in extra
    # User-Agent header injected
    ua_flags = [extra[i+1] for i, a in enumerate(extra) if a == "-H" and "User-Agent" in extra[i+1]]
    assert len(ua_flags) == 1
    assert "surzvtr5h" in ua_flags[0]
    assert "Mozilla" in ua_flags[0]
    # X-Intigriti-Username header injected
    inti_flags = [extra[i+1] for i, a in enumerate(extra) if a == "-H" and "Intigriti" in extra[i+1]]
    assert len(inti_flags) == 1
    assert "surzvtr5h" in inti_flags[0]
    # Rate cap injected
    assert "-rate" in extra
    assert "20" in extra


def test_inject_scan_config_caller_header_wins(monkeypatch, tmp_path):
    """If the caller already set a header in options, it is NOT overridden."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("INTIGRITI_USERNAME", "surzvtr5h")
    import json as _json
    cache_dir = tmp_path / "scope"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "intigriti_test.json").write_text(_json.dumps({
        "platform": "intigriti", "handle": "test",
        "testing_requirements": {
            "user_agent": "researcher-intigriti",
            "request_header": "X-Intigriti: true",
            "max_requests_per_second": 20,
        },
    }))
    from payloads.ffuf import _inject_scan_config
    # Caller already set User-Agent and -rate
    extra, cfg = _inject_scan_config(
        ["-H", "User-Agent: my-custom-ua", "-rate", "5"],
        "http://test.com/FUZZ", "test", "intigriti")
    # Only the X-Intigriti header should be added (UA and rate already present)
    ua_count = sum(1 for a in extra if "User-Agent" in a)
    assert ua_count == 1  # only the caller's
    assert "-rate" in extra
    rate_idx = extra.index("-rate")
    assert extra[rate_idx + 1] == "5"  # caller's rate wins
    # X-Intigriti header was still injected
    assert any("X-Intigriti" in a for a in extra)


def test_inject_scan_config_h1_default_header(monkeypatch, tmp_path):
    """H1 programs get the X-HackerOne-Research identification header
    auto-injected (H1's recommended traffic-identification mechanism)."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("H1_API_USERNAME", "surzvtr5h")
    import json as _json
    cache_dir = tmp_path / "scope"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "crypto.json").write_text(_json.dumps({
        "handle": "crypto", "platform": "h1",
        "policy": "", "in_scope": [], "out_of_scope_assets": [],
    }))
    from payloads.ffuf import _inject_scan_config
    extra, cfg = _inject_scan_config([], "http://test.com/FUZZ", "crypto", "h1")
    assert cfg is not None
    assert cfg["headers"]["X-HackerOne-Research"] == "surzvtr5h"
    # The header is injected as -H
    assert "-H" in extra
    assert any("X-HackerOne-Research" in a and "surzvtr5h" in a for a in extra)


def test_inject_scan_config_none_without_scope():
    """No scope_handle → no injection."""
    from payloads.ffuf import _inject_scan_config
    extra, cfg = _inject_scan_config([], "http://test.com/FUZZ", None, None)
    assert cfg is None
    assert extra == []

def test_inject_scan_config_rate_only_no_headers(monkeypatch, tmp_path):
    """Finding 1: a program mandating ONLY a rate cap (no custom UA/header)
    must still get -rate injected — not silently dropped by the old
    `if not cfg.get("headers")` guard."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    import json as _json
    cache_dir = tmp_path / "scope"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "intigriti_test.json").write_text(_json.dumps({
        "platform": "intigriti", "handle": "test",
        "testing_requirements": {
            "max_requests_per_second": 12,
            # no user_agent, no request_header
        },
    }))
    from payloads.ffuf import _inject_scan_config
    extra, cfg = _inject_scan_config([], "http://test.com/FUZZ", "test", "intigriti")
    assert cfg is not None
    assert cfg["max_requests_per_second"] == 12
    assert cfg["headers"] == {}  # no headers mandated
    # Rate must be injected even though no headers exist
    assert "-rate" in extra
    rate_idx = extra.index("-rate")
    assert extra[rate_idx + 1] == "12"
    # No -H flags should be present
    assert "-H" not in extra


def test_run_ffuf_surfaces_scan_config_applied(monkeypatch, tmp_path):
    """run_ffuf includes scan_config_applied in the job envelope when scope
    params are provided and the manifest has testing requirements."""
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("INTIGRITI_USERNAME", "surzvtr5h")
    import json as _json
    cache_dir = tmp_path / "scope"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "intigriti_test.json").write_text(_json.dumps({
        "platform": "intigriti", "handle": "test",
        "testing_requirements": {
            "user_agent": "researcher-ua",
            "request_header": "X-Intigriti-Username: {Username}",
            "max_requests_per_second": 10,
        },
    }))

    captured = {}

    def fake_launch(cmd, *, tool_name, timeout, verdict_parser):
        captured["cmd"] = cmd
        return {"job_id": "fake", "tool": "ffuf", "status": "launched"}

    monkeypatch.setattr("payloads.ffuf.launch_job", fake_launch)
    monkeypatch.setattr("payloads.ffuf.resolve_default_wordlist", lambda _: None)
    monkeypatch.setattr("payloads.ffuf.resolve_wordlist", lambda w: w if "test.txt" in w else None)

    import payloads.ffuf as ffuf_mod
    r = ffuf_mod.run_ffuf(
        url="http://test.com/FUZZ", wordlist="/usr/share/wordlists/test.txt",
        scope_handle="test", scope_platform="intigriti")
    assert r["status"] == "launched"
    assert "scan_config_applied" in r
    assert r["scan_config_applied"]["max_requests_per_second"] == 10
    # Verify the command actually includes the injected headers
    cmd = captured["cmd"]
    assert "-H" in cmd
    assert any("researcher-ua" in c for c in cmd)
    assert any("surzvtr5h" in c for c in cmd)
    assert "-rate" in cmd
    assert "10" in cmd


# --- default credential fallback (hydra) --------------------------------------

def test_hydra_injects_default_credentials_when_absent(monkeypatch):
    import payloads.hydra as hydra_mod
    from utils.wordlists import resolve_default_wordlist

    if not (resolve_default_wordlist("hydra_logins") and
            resolve_default_wordlist("hydra_passwords")):
        pytest.skip("default hydra lists not installed")

    captured = {}

    def fake_launch(cmd, *, tool_name, timeout, verdict_parser):
        captured["cmd"] = cmd
        return {"job_id": "h1", "status": "running", "tool": tool_name}

    monkeypatch.setattr(hydra_mod, "launch_job", fake_launch)
    r = hydra_mod.run_hydra(target="ssh://127.0.0.1", options="-t 4 -f")
    assert r["status"] == "running"
    assert r["default_creds_used"] is True
    # -L and -P with the default paths must be on the command line
    assert "-L" in captured["cmd"] and "-P" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("-L") + 1] == r["default_login_list"]
    assert captured["cmd"][captured["cmd"].index("-P") + 1] == r["default_password_list"]


@pytest.mark.parametrize("opts", [
    "-L /tmp/u.txt -P /tmp/p.txt",
    "-C /tmp/creds.txt",
    "-l admin -p secret",
    "-x my:generator",
])
def test_hydra_does_not_inject_when_cred_source_present(monkeypatch, opts):
    import payloads.hydra as hydra_mod
    captured = {}

    def fake_launch(cmd, *, tool_name, timeout, verdict_parser):
        captured["cmd"] = cmd
        return {"job_id": "h2", "status": "running", "tool": tool_name}

    monkeypatch.setattr(hydra_mod, "launch_job", fake_launch)
    r = hydra_mod.run_hydra(target="ssh://127.0.0.1", options=opts)
    assert r["status"] == "running"
    assert r["default_creds_used"] is False
    # No second -L/-P injected beyond what the caller supplied.
    l_count = captured["cmd"].count("-L")
    p_count = captured["cmd"].count("-P")
    assert l_count == (1 if "-L" in opts else 0)
    assert p_count == (1 if "-P" in opts else 0)


def test_hydra_errors_when_no_default_available(monkeypatch, tmp_path):
    import payloads.hydra as hydra_mod
    monkeypatch.setattr("utils.wordlists.DEFAULT_HYDRA_LOGIN_LIST", "no/such.txt")
    monkeypatch.setattr("utils.wordlists.DEFAULT_HYDRA_PASSWORD_LIST", "no/such2.txt")
    monkeypatch.setattr("utils.wordlists.WORDLISTS_ROOT", tmp_path)
    r = hydra_mod.run_hydra(target="ssh://127.0.0.1", options="")
    assert r["status"] == "error"
    assert "list_wordlists" in r["error"]
