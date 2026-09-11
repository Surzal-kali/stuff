"""Tests for auxiliaries/masscan.py — JSON parser + denylist + arg assembly.

Regression focus (per the masscan schema hand-off):
- masscan -oJ streams a JSON array and only appends the closing "]" on
  clean exit; a killed/interrupted job (reaper, gateway restart, timeout)
  leaves a truncated file. The parser must yield every fully-written host
  record and tolerate a missing "]" and a trailing partial record — it
  must NOT json.load blind.
- The operational-plumbing denylist strips --conf/--resume/--shards/
  --echo/--regress/-sL/--pfring/--pcap-payloads/--nmap-payloads/
  --http-user-agent/--nmap and the rotate/offset/dir knobs, plus the
  wrapper-owned flags (-p/--rate/--wait/--exclude/-oJ/--adapter-ip/-e),
  from both ``flags`` and ``options``.
- run_masscan assembles argv in the documented order (target, -p, --rate,
  --exclude, --adapter-ip, -e, free flags, --wait -oJ, escape hatch).
"""

import json
import os
import shlex
import socket
from unittest import mock

import pytest

from auxiliaries.masscan import (
    _parse_masscan_json,
    _scan_json_objects,
    _strip_denied,
    run_masscan,
)


# --- fixtures ----------------------------------------------------------------

MASSCAN_JSON_CLEAN = """[
{
  "ip": "10.0.0.1",
  "timestamp": "1694400000",
  "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ]
}
,
{
  "ip": "10.0.0.2",
  "timestamp": "1694400001",
  "ports": [
    {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64},
    {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}
  ]
}
]
"""

# Same data but interrupted mid-third-record and no closing "]"
MASSCAN_JSON_TRUNCATED = """[
{
  "ip": "10.0.0.1",
  "timestamp": "1694400000",
  "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ]
}
,
{
  "ip": "10.0.0.2",
  "timestamp": "1694400001",
  "ports": [ {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ]
}
,
{
  "ip": "10.0.0.3",
  "timestamp": "1694400002",
  "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-a
"""


@pytest.fixture
def clean_json_file(tmp_path):
    p = tmp_path / "out.json"
    p.write_text(MASSCAN_JSON_CLEAN)
    return str(p)


@pytest.fixture
def truncated_json_file(tmp_path):
    p = tmp_path / "out_trunc.json"
    p.write_text(MASSCAN_JSON_TRUNCATED)
    return str(p)


# --- brace scanner ----------------------------------------------------------

def test_scan_json_objects_extracts_balanced_only():
    objs = _scan_json_objects(MASSCAN_JSON_TRUNCATED)
    assert len(objs) == 2  # third record is truncated -> dropped
    assert objs[0]["ip"] == "10.0.0.1"
    assert objs[1]["ip"] == "10.0.0.2"


def test_scan_json_objects_handles_braces_inside_strings():
    # A banner string containing a literal "}" must not break depth tracking.
    text = '[\n{"ip":"1.2.3.4","ports":[{"port":80,"banner":"HTTP/1.1 200 OK}"}]}\n]'
    objs = _scan_json_objects(text)
    assert len(objs) == 1
    assert objs[0]["ports"][0]["banner"] == "HTTP/1.1 200 OK}"


def test_scan_json_objects_empty_and_garbage():
    assert _scan_json_objects("") == []
    assert _scan_json_objects("not json at all") == []
    assert _scan_json_objects("[\n") == []


# --- file parser ------------------------------------------------------------

def test_parse_clean_json(clean_json_file):
    res = _parse_masscan_json(clean_json_file)
    assert res is not None
    assert res["open_port_count"] == 3
    assert res["hosts_with_open"] == 2
    assert res["meta"]["truncated"] is False
    assert res["meta"]["records"] == 2
    h2 = next(h for h in res["hosts"] if h["ip"] == "10.0.0.2")
    assert h2["open_count"] == 2
    assert {p["port"] for p in h2["ports"]} == {22, 443}


def test_parse_truncated_json_yields_partial(truncated_json_file):
    res = _parse_masscan_json(truncated_json_file)
    assert res is not None
    # Two complete records survive; the third (mid-write) is dropped.
    assert res["meta"]["truncated"] is True
    assert res["meta"]["records"] == 2
    assert res["open_port_count"] == 2  # 80 + 22
    assert {h["ip"] for h in res["hosts"]} == {"10.0.0.1", "10.0.0.2"}


def test_parse_missing_file_returns_none(tmp_path):
    assert _parse_masscan_json(str(tmp_path / "nope.json")) is None


def test_parse_empty_file_returns_none(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("")
    assert _parse_masscan_json(str(p)) is None


def test_parse_banner_field(clean_json_file):
    # Inject a banner record to confirm the banner is surfaced.
    text = '[\n{"ip":"5.5.5.5","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":64,"banner":"nginx/1.25"}]}\n]'
    import tempfile, os as _os
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(text)
        path = f.name
    try:
        res = _parse_masscan_json(path)
        entry = res["hosts"][0]["ports"][0]
        assert entry["banner"] == "nginx/1.25"
    finally:
        _os.unlink(path)


# --- denylist ---------------------------------------------------------------

def test_strip_denied_removes_plumbing_and_owned():
    tokens = shlex.split(
        "--banners --open-only --conf /etc/x --resume --shards 1/4 "
        "--rate 9999 -p 443 --exclude 1.1.1.1 -oJ /tmp/x --nmap"
    )
    clean, dropped = _strip_denied(tokens)
    assert clean == ["--banners", "--open-only"]
    # every dangerous/owned flag + its value should be in dropped
    assert "--conf" in dropped and "/etc/x" in dropped
    assert "--resume" in dropped
    assert "--shards" in dropped and "1/4" in dropped
    assert "--rate" in dropped and "9999" in dropped
    assert "-p" in dropped and "443" in dropped
    assert "--exclude" in dropped and "1.1.1.1" in dropped
    assert "-oJ" in dropped and "/tmp/x" in dropped
    assert "--nmap" in dropped


def test_strip_denied_preserves_safe_flags():
    clean, dropped = _strip_denied(
        ["--banners", "--open-only", "--ping", "--retries", "3", "--seed", "42"]
    )
    assert clean == ["--banners", "--open-only", "--ping", "--retries", "3", "--seed", "42"]
    assert dropped == []


# --- run_masscan argv assembly (no real scan) -------------------------------

def test_run_masscan_argv_order(monkeypatch, tmp_path):
    """Verify the assembled argv without launching a real process."""
    monkeypatch.setenv("BG_JOB_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("MASSCAN_ADAPTER_IP", "10.99.0.1")
    monkeypatch.setenv("MASSCAN_ADAPTER", "eth0")
    monkeypatch.delenv("MASSCAN_MAX_RATE", raising=False)
    monkeypatch.delenv("MASSCAN_SELF_EXCLUDE", raising=False)

    captured = {}

    def fake_launch(command, *, tool_name, timeout, verdict_parser, env=None):
        captured["command"] = command
        captured["timeout"] = timeout
        return {
            "job_id": "deadbeef",
            "status": "running",
            "log_file": str(tmp_path / "masscan_deadbeef.log"),
            "tool": tool_name,
            "started": 0,
            "message": "ok",
        }

    with mock.patch("auxiliaries.masscan.launch_job", side_effect=fake_launch):
        job = run_masscan(
            target="10.0.0.0/24",
            ports="80,443",
            rate=2000,
            flags="--banners --open-only",
            exclude="10.0.0.5",
            options="--retries 2",
        )

    cmd = captured["command"]
    assert cmd[0] == "masscan"
    assert cmd[1] == "10.0.0.0/24"
    # owned flags in documented order
    assert cmd[2:4] == ["-p", "80,443"]
    assert "--rate" in cmd and "2000" in cmd
    assert "--exclude" in cmd and "10.0.0.5" in cmd
    assert "--adapter-ip" in cmd and "10.99.0.1" in cmd
    assert "-e" in cmd and "eth0" in cmd
    # free flags preserved
    assert "--banners" in cmd and "--open-only" in cmd
    # escape-hatch --retries 2 preserved (not denylisted, not owned)
    assert "--retries" in cmd and "2" in cmd
    # fixed output last-ish
    assert "--wait" in cmd and "10" in cmd
    assert "-oJ" in cmd
    # output file path under BG_JOB_LOG_DIR
    out_idx = cmd.index("-oJ")
    assert cmd[out_idx + 1].startswith(str(tmp_path))
    # escaped config surfaced on the returned job
    assert job["ports"] == "80,443"
    assert job["rate"] == 2000
    assert job["exclude"] == "10.0.0.5"
    assert job["adapter_ip"] == "10.99.0.1"
    assert job["adapter_iface"] == "eth0"


def test_run_masscan_rate_clamp(monkeypatch, tmp_path):
    monkeypatch.setenv("BG_JOB_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("MASSCAN_MAX_RATE", "500")
    monkeypatch.setenv("MASSCAN_ADAPTER_IP", "10.99.0.1")
    monkeypatch.delenv("MASSCAN_SELF_EXCLUDE", raising=False)

    captured = {}

    def fake_launch(command, *, tool_name, timeout, verdict_parser, env=None):
        captured["command"] = command
        return {"job_id": "x", "status": "running", "log_file": "",
                "tool": tool_name, "started": 0, "message": "ok"}

    with mock.patch("auxiliaries.masscan.launch_job", side_effect=fake_launch):
        job = run_masscan(target="10.0.0.1", rate=5000)

    cmd = captured["command"]
    idx = cmd.index("--rate")
    assert cmd[idx + 1] == "500"  # clamped
    assert any("clamped" in n for n in job.get("notes", []))


def test_run_masscan_default_ports_and_self_exclude(monkeypatch, tmp_path):
    monkeypatch.setenv("BG_JOB_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("MASSCAN_ADAPTER_IP", "10.99.0.1")
    monkeypatch.setenv("MASSCAN_SELF_EXCLUDE", "192.168.90.113")

    captured = {}

    def fake_launch(command, *, tool_name, timeout, verdict_parser, env=None):
        captured["command"] = command
        return {"job_id": "y", "status": "running", "log_file": "",
                "tool": tool_name, "started": 0, "message": "ok"}

    with mock.patch("auxiliaries.masscan.launch_job", side_effect=fake_launch):
        # rate=None, ports=None, exclude=None -> defaults
        job = run_masscan(target="192.168.90.0/24")

    cmd = captured["command"]
    assert "-p" in cmd and cmd[cmd.index("-p") + 1] == "80"
    assert "--rate" not in cmd  # not passed -> binary default 100
    assert "--exclude" in cmd and "192.168.90.113" in cmd[cmd.index("--exclude") + 1]


def test_run_masscan_exclude_opt_out(monkeypatch, tmp_path):
    monkeypatch.setenv("BG_JOB_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("MASSCAN_ADAPTER_IP", "10.99.0.1")
    monkeypatch.setenv("MASSCAN_SELF_EXCLUDE", "192.168.90.113")

    captured = {}

    def fake_launch(command, *, tool_name, timeout, verdict_parser, env=None):
        captured["command"] = command
        return {"job_id": "z", "status": "running", "log_file": "",
                "tool": tool_name, "started": 0, "message": "ok"}

    with mock.patch("auxiliaries.masscan.launch_job", side_effect=fake_launch):
        job = run_masscan(target="10.0.0.1", exclude="")

    assert "--exclude" not in captured["command"]
    assert job["exclude"] is None


def test_run_masscan_strips_dangerous_options(monkeypatch, tmp_path):
    monkeypatch.setenv("BG_JOB_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("MASSCAN_ADAPTER_IP", "10.99.0.1")
    monkeypatch.delenv("MASSCAN_SELF_EXCLUDE", raising=False)

    captured = {}

    def fake_launch(command, *, tool_name, timeout, verdict_parser, env=None):
        captured["command"] = command
        return {"job_id": "w", "status": "running", "log_file": "",
                "tool": tool_name, "started": 0, "message": "ok"}

    with mock.patch("auxiliaries.masscan.launch_job", side_effect=fake_launch):
        job = run_masscan(
            target="10.0.0.1",
            flags="--conf /etc/masscan/masscan.conf --resume",
            options="--shards 1/4 -oJ /tmp/evil.json",
        )

    cmd = captured["command"]
    # none of the dangerous/owned flags should reach argv (except the
    # wrapper's own -oJ pointing at its own file)
    assert "--conf" not in cmd and "/etc/masscan/masscan.conf" not in cmd
    assert "--resume" not in cmd
    assert "--shards" not in cmd
    assert "/tmp/evil.json" not in cmd
    assert any("stripped" in n for n in job.get("notes", []))


def test_run_masscan_missing_target():
    res = run_masscan(target="")
    assert res["status"] == "error"
    assert res["job_id"] is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
