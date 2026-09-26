"""Unit tests for payloads/hash_crack.py — tmp-hashfile lifecycle + argv order.

pytest-compatible (plain ``test_*`` functions, self-contained patches - no
pytest fixtures) AND directly runnable with ``python3 tests/test_hash_crack.py``
from any CWD (mirrors tests/test_db_client.py's runner).

Root-cause regression (operator bug report 2026-09-26: ``Hash
'/tmp/hashes_*.txt': Separator unmatched`` + ``No hashes loaded.``):
operator commit a1fae22 unlinked the per-job hashfile in a ``finally``
immediately after ``launch_job`` returned — but launch_job returns the
instant the child is SPAWNED.  hashcat 6.2.6 (src/hashes.c:
hashes_init_filename) treats a hashfile path that no longer exists as a
single literal hash (HL_MODE_ARG) and parses the path string itself ->
"Separator unmatched" for hash:salt modes + "No hashes loaded.".  The
fix: the hashfile is dropped by a watcher thread AFTER the cracker
process exits (_launch_hash_crack).

All tests are OFFLINE: the "crackers" are shell shims injected via
$HASHCAT_BIN / $JOHN_BIN (the module's _preflight honors the env
override first).  No hashcat/john binary is required or contacted.
"""

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# BG_JOB_LOG_DIR must be set BEFORE utils.background_job is imported
# (module-level _LOG_DIR is read at import time).
_TEST_LOG_DIR = tempfile.mkdtemp(prefix="hashcrack_test_logs_")
os.environ["BG_JOB_LOG_DIR"] = _TEST_LOG_DIR

import payloads.hash_crack as HC  # noqa: E402
import utils.background_job as BGJ  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _write_shim(script: str) -> str:
    fd, path = tempfile.mkstemp(prefix="hcshim_", suffix=".sh", dir=_TEST_LOG_DIR)
    with os.fdopen(fd, "w") as fh:
        fh.write(script)
    os.chmod(path, 0o755)
    return path


def _mk_file(prefix: str, content: str) -> str:
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".txt", dir="/tmp")
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    return path


def _wait_done(job_id: str, tool: str, timeout: float = 25.0):
    res = {}
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = BGJ.poll_job(job_id, tool_name=tool)
        if res.get("status") == "done":
            return res
        time.sleep(0.25)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s: {res}")


def _wait_gone(path: str, timeout: float = 6.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not os.path.exists(path):
            return True
        time.sleep(0.2)
    return False


def _env_restore(name: str, saved):
    if saved is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = saved


# ---------------------------------------------------------------------------
# _write_hashfile
# ---------------------------------------------------------------------------

def test_write_hashfile_split_strip_trailing_newline_and_mode():
    path = HC._write_hashfile(
        "5f4dcc3b5aa765d61d8327deb882cf99 ,\n"
        " 0d107d09f5bbe40cade3de5c71e9e9b7 ;\n"
        "  5d41402abc4b2a76b9719d911017c592,"
    )
    try:
        with open(path) as fh:
            assert fh.read() == (
                "5f4dcc3b5aa765d61d8327deb882cf99\n"
                "0d107d09f5bbe40cade3de5c71e9e9b7\n"
                "5d41402abc4b2a76b9719d911017c592\n"
            )
        assert os.stat(path).st_mode & 0o777 == 0o600
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_write_hashfile_empty_input_raises():
    try:
        HC._write_hashfile(" , ;  \n ")
    except ValueError as exc:
        assert "no hashes parsed" in str(exc)
    else:
        raise AssertionError("expected ValueError for empty hash input")


# ---------------------------------------------------------------------------
# THE regression: hashfile must survive until the background cracker reads it
# ---------------------------------------------------------------------------

def test_hashcat_hashfile_survives_until_child_reads_it():
    # shim emulates cracker startup: 1.5s BEFORE touching the hashfile.
    # The old (a1fae22) code unlinked the file microseconds after spawn ->
    # the child saw a MISSING file (hashcat: path parsed as literal hash).
    shim = _write_shim(
        "#!/bin/sh\n"
        "sleep 1.5\n"
        'if [ -r "$5" ]; then echo "READABLE:$5"; else echo "MISSING:$5"; fi\n'
    )
    wl = _mk_file("wl_", "password\n123456\n")
    saved_wl = HC._default_wordlist
    saved_env = os.environ.get("HASHCAT_BIN")
    hfile = None
    try:
        HC._default_wordlist = lambda: wl  # type: ignore[assignment]
        os.environ["HASHCAT_BIN"] = shim
        res = HC.run_hashcat("5f4dcc3b5aa765d61d8327deb882cf99", 0)
        assert res.get("status") in ("running", "done"), res
        job_id = res["job_id"]
        with open(os.path.join(_TEST_LOG_DIR, f"hashcat_{job_id}.meta")) as fh:
            cmd = json.load(fh)["command"]
        assert cmd[0] == shim and cmd[1:5] == ["-m", "0", "-a", "0"], cmd
        hfile = cmd[5]
        assert cmd[6] == wl, cmd  # wordlist still last in -a 0
        # THE assertion: file must still exist well past the old unlink point
        time.sleep(0.4)
        assert os.path.exists(hfile), (
            "hashfile was deleted before the cracker could read it "
            "(a1fae22 unlink race)"
        )
        done = _wait_done(job_id, "hashcat")
        text = done.get("full_output") or ""
        assert "READABLE:" in text, done
        assert "MISSING:" not in text, done
        assert _wait_gone(hfile), "hashfile not dropped after the cracker exited"
    finally:
        HC._default_wordlist = saved_wl
        _env_restore("HASHCAT_BIN", saved_env)
        if hfile and os.path.exists(hfile):
            os.unlink(hfile)
        os.unlink(wl)


def test_john_hashfile_survives_until_child_reads_it():
    shim = _write_shim(
        "#!/bin/sh\n"
        "sleep 1.5\n"
        'if [ -r "$2" ]; then echo "READABLE:$2"; else echo "MISSING:$2"; fi\n'
    )
    wl = _mk_file("wl_", "password\n123456\n")
    saved_wl = HC._default_wordlist
    saved_env = os.environ.get("JOHN_BIN")
    hfile = None
    try:
        HC._default_wordlist = lambda: wl  # type: ignore[assignment]
        os.environ["JOHN_BIN"] = shim
        res = HC.run_john("5f4dcc3b5aa765d61d8327deb882cf99")
        assert res.get("status") in ("running", "done"), res
        job_id = res["job_id"]
        with open(os.path.join(_TEST_LOG_DIR, f"john_{job_id}.meta")) as fh:
            cmd = json.load(fh)["command"]
        assert cmd[0] == shim and cmd[1].startswith("--wordlist="), cmd
        hfile = cmd[2]
        time.sleep(0.4)
        assert os.path.exists(hfile), (
            "hashfile was deleted before the cracker could read it "
            "(a1fae22 unlink race)"
        )
        done = _wait_done(job_id, "john")
        text = done.get("full_output") or ""
        assert "READABLE:" in text, done
        assert "MISSING:" not in text, done
        assert _wait_gone(hfile), "hashfile not dropped after the cracker exited"
    finally:
        HC._default_wordlist = saved_wl
        _env_restore("JOHN_BIN", saved_env)
        if hfile and os.path.exists(hfile):
            os.unlink(hfile)
        os.unlink(wl)


def test_eager_unlink_after_launch_reproduces_missing_hashfile():
    """Negative control documenting the a1fae22 mechanism: unlinking right
    after launch_job loses the race — the (still-starting) child sees the
    file GONE.  This is exactly what hashcat saw before the fix."""
    shim = _write_shim(
        "#!/bin/sh\n"
        "sleep 1.2\n"
        'if [ -r "$1" ]; then echo READABLE; else echo MISSING; fi\n'
    )
    hfile = _mk_file("hashes_", "5f4dcc3b5aa765d61d8327deb882cf99\n")
    try:
        res = BGJ.launch_job([shim, hfile], tool_name="hashcat", timeout=60)
        os.unlink(hfile)  # the buggy a1fae22 behaviour, verbatim
        done = _wait_done(res["job_id"], "hashcat")
        text = done.get("full_output") or ""
        assert "MISSING" in text, done
        assert "READABLE" not in text, done
    finally:
        if os.path.exists(hfile):
            os.unlink(hfile)


# ---------------------------------------------------------------------------
# hashcat argv order: positionals (mask/dicts) must come AFTER the hashfile
# ---------------------------------------------------------------------------

def test_hashcat_mask_positional_comes_after_hashfile():
    shim = _write_shim('#!/bin/sh\necho "ARGV: $*"\n')
    saved_wl = HC._default_wordlist
    saved_env = os.environ.get("HASHCAT_BIN")
    hfile = None
    try:
        HC._default_wordlist = lambda: None  # type: ignore[assignment]
        os.environ["HASHCAT_BIN"] = shim
        res = HC.run_hashcat(
            "5f4dcc3b5aa765d61d8327deb882cf99", 0,
            options="-a 3 ?u?l?l?l?l?d?d",
        )
        job_id = res["job_id"]
        done = _wait_done(job_id, "hashcat")
        line = next(
            (ln for ln in done.get("recent_lines", []) if ln.startswith("ARGV: ")),
            None,
        )
        assert line, done
        argv = line[len("ARGV: "):].split()
        hfile = next(a for a in argv if "/tmp/hashes_" in a and a.endswith(".txt"))
        assert argv[:3] == ["-m", "0", "-a"], argv
        assert argv[3] == "3", argv
        i_hf, i_mask = argv.index(hfile), argv.index("?u?l?l?l?l?d?d")
        assert i_hf < i_mask, argv  # hashfile BEFORE the mask
        assert i_mask == len(argv) - 1, argv  # no wordlist appended in -a 3
        assert _wait_gone(hfile), "hashfile not dropped after the run"
    finally:
        HC._default_wordlist = saved_wl
        _env_restore("HASHCAT_BIN", saved_env)
        if hfile and os.path.exists(hfile):
            os.unlink(hfile)


def test_split_hashcat_positionals():
    opts, pos = HC._split_hashcat_positionals([
        "-a", "3", "?u?l?l?l?l?d?d",
        "-r", "rules/best64.rule",
        "-O", "--increment", "--increment-min", "3",
        "--potfile-path=/tmp/pot",
    ])
    assert opts == [
        "-a", "3", "-r", "rules/best64.rule", "-O",
        "--increment", "--increment-min", "3", "--potfile-path=/tmp/pot",
    ], opts
    assert pos == ["?u?l?l?l?l?d?d"], pos
    opts, pos = HC._split_hashcat_positionals(["-a", "0"])
    assert opts == ["-a", "0"] and pos == []
    opts, pos = HC._split_hashcat_positionals(["--attack-mode=3", "?d?d?d?d"])
    assert opts == ["--attack-mode=3"] and pos == ["?d?d?d?d"]


# ---------------------------------------------------------------------------
# blocking *_show paths: synchronous, file fully consumed, dropped in finally
# ---------------------------------------------------------------------------

def test_hashcat_show_reads_then_drops_hashfile():
    shim = _write_shim('#!/bin/sh\necho "SHOW:$(cat "$4")"\n')
    saved_env = os.environ.get("HASHCAT_BIN")
    calls = []
    orig_drop = HC._drop_hashfile
    try:
        os.environ["HASHCAT_BIN"] = shim
        HC._drop_hashfile = lambda p: (calls.append(p), orig_drop(p))  # type: ignore[assignment]
        res = HC.hashcat_show("5f4dcc3b5aa765d61d8327deb882cf99", 0)
        assert res.get("status") == "Success", res
        assert "SHOW:5f4dcc3b5aa765d61d8327deb882cf99" in res.get("raw", ""), res
        assert len(calls) == 1 and calls[0].startswith("/tmp/hashes_"), calls
        assert not os.path.exists(calls[0])
    finally:
        HC._drop_hashfile = orig_drop
        _env_restore("HASHCAT_BIN", saved_env)


def test_john_show_reads_then_drops_hashfile():
    shim = _write_shim('#!/bin/sh\necho "SHOW:$(cat "$2")"\n')
    saved_env = os.environ.get("JOHN_BIN")
    calls = []
    orig_drop = HC._drop_hashfile
    try:
        os.environ["JOHN_BIN"] = shim
        HC._drop_hashfile = lambda p: (calls.append(p), orig_drop(p))  # type: ignore[assignment]
        res = HC.john_show("5f4dcc3b5aa765d61d8327deb882cf99")
        assert res.get("status") == "Success", res
        assert "SHOW:5f4dcc3b5aa765d61d8327deb882cf99" in res.get("raw", ""), res
        assert len(calls) == 1 and calls[0].startswith("/tmp/hashes_"), calls
        assert not os.path.exists(calls[0])
    finally:
        HC._drop_hashfile = orig_drop
        _env_restore("JOHN_BIN", saved_env)


# ---------------------------------------------------------------------------
# verdict parsing sanity (unchanged behaviour)
# ---------------------------------------------------------------------------

def test_parse_hashcat_pairs_and_recovered():
    log = (
        "hashcat (v6.2.6) starting\n"
        "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
        "Recovered.: 1/1 (100.00%) Digests\n"
    )
    verdict = HC._parse_hashcat(log)
    assert verdict["cracked_pairs"] == [
        {"hash": "5f4dcc3b5aa765d61d8327deb882cf99", "plaintext": "password"}
    ], verdict
    assert verdict["recovered"] == "1/1", verdict


# ---------------------------------------------------------------------------
# plain-python runner (pytest-compatible: each test_* is standalone)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    failures = 0
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in tests:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)