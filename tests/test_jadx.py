"""Unit tests for the run_jadx / list_apk_targets tools (auxiliaries/jadx.py).

pytest-compatible (plain ``test_*`` functions, self-contained tmp dirs — no
pytest fixtures) AND directly runnable with ``python3 tests/test_jadx.py``
from any CWD (agent-seat box has no pytest; see agent_ledger 2026-09-21).

All tests are OFFLINE: the jadx binary is either absent (preflight envelopes)
or replaced by a fake shim via the JADX_BIN env seam (full plumbing, the same
technique the hash_crack tests used with a fake john).  No network, no
subprocess besides the shim.  The real apk/ drop folder is never touched —
every test patches ``APK_TARGETS_ROOT`` to its own tmp root.
"""

import json
import os
import shutil
import sys
import tempfile

# Neutral-CWD bootstrap (this module imports only constants, but keep the
# explicit path insertion so `python3 tests/test_jadx.py` works standalone).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auxiliaries.jadx as J  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class _Restore:
    """Multi-attribute patch/restore with context-manager syntax."""

    def __init__(self):
        self._saved = []

    def patch(self, obj, attr, value):
        self._saved.append((obj, attr, getattr(obj, attr)))
        setattr(obj, attr, value)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        for obj, attr, old in reversed(self._saved):
            setattr(obj, attr, old)
        return False


def _tmp_root():
    """Patch the module onto a fresh tmp drop folder; return (restore, root)."""
    root = tempfile.mkdtemp(prefix="jadx_test_apk_")
    r = _Restore()
    r.patch(J, "APK_TARGETS_ROOT", root)
    os.makedirs(root, exist_ok=True)
    return r, root


def _fake_apk(root, name="app.apk", magic=b"PK\x03\x04"):
    path = os.path.join(root, name)
    with open(path, "wb") as fh:
        fh.write(magic + b"placeholder-bytes-for-magic-sniffing-only")
    return path


def _fresh_workspace(root, name="app.apk", sources=2):
    """Build a workspace that looks freshly decompiled by a previous run."""
    src = os.path.join(root, name)
    if not os.path.isfile(src):
        _fake_apk(root, name)
    ws = os.path.join(root, "decompiled", name)
    os.makedirs(os.path.join(ws, "sources", "com", "example"), exist_ok=True)
    os.makedirs(os.path.join(ws, "resources"), exist_ok=True)
    for i in range(sources):
        with open(os.path.join(ws, "sources", "com", "example", f"C{i}.java"), "w") as fh:
            fh.write(f'package com.example;\npublic class C{i} {{ String TOKEN = "t{i}"; }}\n')
    with open(os.path.join(ws, "resources", "AndroidManifest.xml"), "w") as fh:
        fh.write('<manifest package="com.example"/>\n')
    st = os.stat(src)
    with open(os.path.join(ws, J._META_NAME), "w") as fh:
        json.dump({
            "source_mtime_ns": st.st_mtime_ns,
            "source_size": st.st_size,
            "jadx_version": "1.5.6-test",
            "source": name,
        }, fh)
    return src, ws, sources


_JAVA_SRC = (
    "package com.example;\n"
    "public class MainActivity {\n"
    "    String API_KEY = \"hunter2\";\n"
    "}\n"
)


def _write_shim(path):
    """Write a fake jadx binary: creates the expected decompile output tree.

    - `-d DIR` runs: create sources/com/example/MainActivity.java +
      resources/AndroidManifest.xml, then bump $JADX_SHIM_COUNTER.
    - `--single-class CLS [--single-class-output DIR]`: write <cls>.java.
    """
    shim = """#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
out = None
if "-d" in args:
    out = args[args.index("-d") + 1]
single = None
if "--single-class" in args:
    single = args[args.index("--single-class") + 1]
if single is not None:
    sco = args[args.index("--single-class-output") + 1] if "--single-class-output" in args else "."
    os.makedirs(sco, exist_ok=True)
    with open(os.path.join(sco, single + ".java"), "w") as fh:
        fh.write("package com.example;\\npublic class {cls} {{ String API_KEY = \\"hunter2\\"; }}\\n".format(cls=single.replace(".", "_")))
    sys.exit(0)
if not out:
    sys.exit(3)
os.makedirs(os.path.join(out, "sources", "com", "example"), exist_ok=True)
os.makedirs(os.path.join(out, "resources"), exist_ok=True)
with open(os.path.join(out, "sources", "com", "example", "MainActivity.java"), "w") as fh:
    fh.write("package com.example;\\npublic class MainActivity {\\n    String API_KEY = \\"hunter2\\";\\n}\\n")
with open(os.path.join(out, "resources", "AndroidManifest.xml"), "w") as fh:
    fh.write('<manifest package="com.example">\\n  <application android:debuggable="true"/>\\n</manifest>\\n')
cnt = os.environ.get("JADX_SHIM_COUNTER")
if cnt:
    try:
        n = int(open(cnt).read().strip() or "0")
    except Exception:
        n = 0
    with open(cnt, "w") as fh:
        fh.write(str(n + 1))
sys.exit(0)
"""
    with open(path, "w") as fh:
        fh.write(shim)
    os.chmod(path, 0o755)
    return path


# ---------------------------------------------------------------------------
# validation-layer tests (no jadx needed)
# ---------------------------------------------------------------------------
def test_verb_allowlist_rejects_junk():
    r, root = _tmp_root()
    try:
        res = J.run_jadx("app.apk", "rm_rf_slash")
        assert res["status"] == "error"
        assert "not in the allowlist" in res["error"]
        assert "decompile" in res["error"]  # self-correcting message
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_mode_and_threads_validation():
    r, root = _tmp_root()
    try:
        res = J.run_jadx("app.apk", "decompile", mode="bogus")
        assert res["status"] == "error" and "mode" in res["error"]
        res = J.run_jadx("app.apk", "decompile", threads="many")
        assert res["status"] == "error" and "threads" in res["error"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_target_resolution_failure():
    r, root = _tmp_root()
    try:
        res = J.run_jadx("ghost_target.apk", "manifest")
        assert res["status"] == "error"
        assert "list_apk_targets" in res["error"]
        assert root in res["error"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_missing_binary_preflight_envelope():
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        with _Restore() as p:
            p.patch(J, "resolve_jadx_bin", lambda: None)
            res = J.run_jadx("app.apk", "decompile")
        assert res["status"] == "error"
        assert "JADX_BIN" in res["error"] and "reindex" in res["error"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_missing_java_preflight_envelope():
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        with _Restore() as p:
            p.patch(J, "resolve_jadx_bin", lambda: "/fake/jadx")
            p.patch(J, "_java_available", lambda: False)
            res = J.run_jadx("app.apk", "decompile")
        assert res["status"] == "error" and "Java 11+" in res["error"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_class_charset_refusal():
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        for evil in ("com.example; rm -rf", "com example", "../Evil", ""):
            res = J.run_jadx("app.apk", "class", single_class=evil)
            assert res["status"] == "error", evil
            assert "FQN" in res["error"], evil
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# drop-folder discovery
# ---------------------------------------------------------------------------
def test_list_apk_targets_discovers_synthetic():
    r, root = _tmp_root()
    try:
        _fake_apk(root, "app.apk")
        _fake_apk(root, "split.xapk")
        with open(os.path.join(root, "classes.dex"), "wb") as fh:
            fh.write(b"dex\n035\x00" + b"\x00" * 16)
        with open(os.path.join(root, "notes.txt"), "w") as fh:
            fh.write("plain text junk")
        stray = os.path.join(root, "decompiled", "app.apk")
        os.makedirs(stray)
        with open(os.path.join(stray, "leak.apk"), "wb") as fh:
            fh.write(b"PK\x03\x04stray")  # must be excluded from listing
        res = J.list_apk_targets()
        assert res["status"] == "ok"
        assert res["count"] == 3, res["targets"]
        fmts = {t["name"]: t["format"] for t in res["targets"]}
        assert (
            fmts["app.apk"] == "APK"
            and fmts["split.xapk"] == "XAPK"
            and fmts["classes.dex"] == "DEX"
        )
        assert all("decompiled" not in t["rel_path"] for t in res["targets"])
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# workspace cache semantics
# ---------------------------------------------------------------------------
def test_decompile_reuse_without_subprocess():
    r, root = _tmp_root()
    try:
        src, ws, java_n = _fresh_workspace(root)
        with _Restore() as p:
            p.patch(J, "resolve_jadx_bin", lambda: None)  # reuse must not need jadx
            res = J.run_jadx("app.apk", "decompile")
        assert res["status"] == "ok" and res["cached"] is True
        assert res["java_source_count"] == java_n
        assert res["workspace"] == ws
        assert os.path.isdir(ws)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_stale_fingerprint_preflight_before_wipe():
    """Stale workspace + missing jadx: cached tree must survive the refusal."""
    r, root = _tmp_root()
    try:
        src, ws, _ = _fresh_workspace(root)
        with open(src, "ab") as fh:
            fh.write(b"changed")  # fingerprint now mismatched
        with _Restore() as p:
            p.patch(J, "resolve_jadx_bin", lambda: None)
            res = J.run_jadx("app.apk", "decompile")
        assert res["status"] == "error" and "jadx not found" in res["error"]
        assert os.path.isdir(ws), "refusal must not wipe the cached tree"
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# full plumbing via fake jadx shim (hash_crack technique)
# ---------------------------------------------------------------------------
def test_full_plumbing_fake_jadx():
    r, root = _tmp_root()
    tmpdirs = [tempfile.mkdtemp(prefix="jadx_test_run_")]
    try:
        _fake_apk(root)
        counter = os.path.join(tmpdirs[0], "count")
        shim = _write_shim(os.path.join(tmpdirs[0], "jadx"))
        with _Restore() as p:
            p.patch(J, "resolve_jadx_bin", lambda: shim)
            p.patch(J, "_java_available", lambda: True)
            os.environ["JADX_SHIM_COUNTER"] = counter
            try:
                res = J.run_jadx("app.apk", "decompile")
                assert res["status"] == "ok", res
                assert res["cached"] is False
                assert res["java_source_count"] == 1, res
                assert open(counter).read() == "1"  # exactly one shim invocation

                # decompile again → cache reuse, shim NOT re-invoked
                res2 = J.run_jadx("app.apk", "decompile")
                assert res2["status"] == "ok" and res2["cached"] is True
                assert open(counter).read() == "1"

                # force re-run → shim invoked again
                res3 = J.run_jadx("app.apk", "decompile", force=True)
                assert res3["status"] == "ok" and res3["cached"] is False
                assert open(counter).read() == "2"

                # grep over the shim-written tree
                rg = J.run_jadx("app.apk", "grep", pattern=r"API_KEY\s*=")
                assert rg["status"] == "ok" and len(rg["matches"]) == 1
                assert rg["matches"][0]["file"].endswith("MainActivity.java")
                assert rg["matches"][0]["line"] == 3

                # read a shim-written file
                rr = J.run_jadx(
                    "app.apk", "read", path="sources/com/example/MainActivity.java"
                )
                assert rr["status"] == "ok" and "API_KEY" in rr["output"]

                # tree listing
                rt = J.run_jadx("app.apk", "tree")
                assert rt["status"] == "ok" and rt["total_files"] >= 3
                assert any(f.endswith("AndroidManifest.xml") for f in rt["files"])

                # manifest from the cached workspace (no new shim call)
                rm_ = J.run_jadx("app.apk", "manifest")
                assert rm_["status"] == "ok" and "com.example" in rm_["output"]
                assert open(counter).read() == "2"

                # single-class pull via the shim (--single-class branch)
                rc = J.run_jadx(
                    "app.apk", "class", single_class="com.example.MainActivity"
                )
                assert rc["status"] == "ok", rc
                assert "API_KEY" in rc["output"]
            finally:
                os.environ.pop("JADX_SHIM_COUNTER", None)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        for d in tmpdirs:
            shutil.rmtree(d, ignore_errors=True)


def test_manifest_topup_via_fake_jadx():
    """resources-only top-up when the workspace has sources but no manifest."""
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        ws = os.path.join(root, "decompiled", "app.apk")
        os.makedirs(os.path.join(ws, "sources", "com", "example"))
        with open(os.path.join(ws, "sources", "com", "example", "A.java"), "w") as fh:
            fh.write(_JAVA_SRC)
        st = os.stat(os.path.join(root, "app.apk"))
        with open(os.path.join(ws, J._META_NAME), "w") as fh:
            json.dump({"source_mtime_ns": st.st_mtime_ns, "source_size": st.st_size}, fh)
        shim = _write_shim(os.path.join(tempfile.mkdtemp(), "jadx"))
        with _Restore() as p:
            p.patch(J, "resolve_jadx_bin", lambda: shim)
            p.patch(J, "_java_available", lambda: True)
            res = J.run_jadx("app.apk", "manifest")
        assert res["status"] == "ok", res
        assert "com.example" in res["output"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# grep / read / tree guards & caps
# ---------------------------------------------------------------------------
def test_read_traversal_refused():
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        _fresh_workspace(root)
        for evil in ("../../etc/passwd", "/etc/passwd", "sources/../../x", "..\\..\\x", ""):
            res = J.run_jadx("app.apk", "read", path=evil)
            assert res["status"] == "error", evil
            assert "containment" in res["error"], evil
        good = J.run_jadx("app.apk", "read", path="sources/com/example/C0.java")
        assert good["status"] == "ok", good
        assert "TOKEN" in good["output"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_grep_requires_workspace_and_validates_pattern():
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        res = J.run_jadx("app.apk", "grep", pattern="x")
        assert res["status"] == "error" and "decompile" in res["error"]
        _fresh_workspace(root)
        res = J.run_jadx("app.apk", "grep", pattern="(unclosed")
        assert res["status"] == "error" and "invalid regex" in res["error"]
        res = J.run_jadx("app.apk", "grep", pattern="x" * 300)
        assert res["status"] == "error" and "256" in res["error"]
        res = J.run_jadx("app.apk", "grep", pattern="t0", glob="bad glob!")
        assert res["status"] == "error" and "glob" in res["error"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_grep_caps_and_binary_skip():
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        src, ws, _ = _fresh_workspace(root, sources=4)  # 4 text files, 1 TOKEN each
        with _Restore() as p:
            p.patch(J, "_GREP_MAX_MATCHES", 3)
            res = J.run_jadx("app.apk", "grep", pattern="TOKEN")
        assert res["status"] == "ok"
        assert res["truncated"] is True and len(res["matches"]) == 3
        assert res["truncation_policy"]
        # binary file with NUL byte is skipped, not regexed
        binp = os.path.join(ws, "sources", "com", "example", "blob.java")
        with open(binp, "wb") as fh:
            fh.write(b"TOKEN\x00TOKEN")
        res2 = J.run_jadx("app.apk", "grep", pattern="TOKEN")
        assert res2["status"] == "ok" and res2["files_skipped"] >= 1
        # case-insensitive flag
        res3 = J.run_jadx("app.apk", "grep", pattern="token", case_insensitive=True)
        assert res3["status"] == "ok" and res3["matches"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_read_output_cap_truncation():
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        src, ws, _ = _fresh_workspace(root)
        big = os.path.join(ws, "sources", "com", "example", "big.java")
        with open(big, "w") as fh:
            fh.write("A" * 5000)
        with _Restore() as p:
            p.patch(J, "_OUTPUT_CAP", 100)
            res = J.run_jadx("app.apk", "read", path="sources/com/example/big.java")
        assert res["status"] == "ok"
        assert res["truncated"] is True and res["truncation_policy"]
        assert len(res["output"]) == 100
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_tree_cap_and_glob():
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        src, ws, _ = _fresh_workspace(root)
        for i in range(12):
            with open(os.path.join(ws, "sources", "f%02d.txt" % i), "w") as fh:
                fh.write("x")
        with _Restore() as p:
            p.patch(J, "_TREE_LIST_CAP", 10)
            res = J.run_jadx("app.apk", "tree")
        assert res["status"] == "ok" and res["truncated"] is True
        assert res["total_files"] >= 12 and len(res["files"]) == 10
        res2 = J.run_jadx("app.apk", "tree", glob="sources/*.java")
        assert res2["status"] == "ok" and res2["files"]
        assert all(f.endswith(".java") for f in res2["files"])
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_grep_paging_offset_and_max_matches():
    """max_matches raises the cap; offset pages — the two fixes for the
    '200-match wall' gap (agent_ledger 2026-09-22)."""
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        src, ws, _ = _fresh_workspace(root, sources=6)  # 6 files, 1 TOKEN each
        with _Restore() as p:
            p.patch(J, "_GREP_MAX_MATCHES", 3)
            # default cap: only _GREP_MAX_MATCHES of the 6
            res0 = J.run_jadx("app.apk", "grep", pattern="TOKEN")
            assert res0["status"] == "ok" and len(res0["matches"]) == 3
            # total_matches is a lower bound — the walk stops at the page
            # window (3), it never sees matches 4-6 to count them
            assert res0["total_matches"] == 3
            assert res0["total_is_lower_bound"] is True
            assert res0["truncated"] is True and res0["next_offset"] == 3
            # offset pages to the rest; the next page comes back empty and
            # settles truncation (exactly-at-cap stays conservative)
            res1 = J.run_jadx("app.apk", "grep", pattern="TOKEN", offset=3)
            assert res1["status"] == "ok" and res1["offset"] == 3
            assert len(res1["matches"]) == 3
            res1b = J.run_jadx("app.apk", "grep", pattern="TOKEN", offset=6)
            assert res1b["status"] == "ok" and res1b["matches"] == []
            assert res1b["truncated"] is False and res1b["next_offset"] is None
            # pages are disjoint and contiguous
            first = {(m["file"], m["line"]) for m in res0["matches"]}
            second = {(m["file"], m["line"]) for m in res1["matches"]}
            assert not (first & second)
            # raise the cap past the default — everything fits in one page
            res2 = J.run_jadx("app.apk", "grep", pattern="TOKEN", max_matches=10)
            assert res2["status"] == "ok" and len(res2["matches"]) == 6
            assert res2["truncated"] is False
            # hard ceiling clamps an absurd raise, and says so
            res3 = J.run_jadx(
                "app.apk", "grep", pattern="TOKEN",
                max_matches=J._GREP_MATCHES_CEILING + 1,
            )
            assert res3["status"] == "ok"
            assert "ceiling" in (res3["truncation_policy"] or "")
            # validation: junk offset / max_matches / negative
            res4 = J.run_jadx("app.apk", "grep", pattern="TOKEN", offset=-1)
            assert res4["status"] == "error" and "offset" in res4["error"]
            res5 = J.run_jadx("app.apk", "grep", pattern="TOKEN", max_matches=0)
            assert res5["status"] == "error" and "max_matches" in res5["error"]
            res6 = J.run_jadx("app.apk", "grep", pattern="TOKEN", offset="nope")
            assert res6["status"] == "error" and "offset" in res6["error"]
            # max_files raises the file-scan cap; ceiling clamps and says so
            res7 = J.run_jadx("app.apk", "grep", pattern="TOKEN", max_files=2)
            assert res7["status"] == "ok" and res7["files_scanned"] == 2
            assert res7["files_capped"] is True
            assert "max_files" in (res7["truncation_policy"] or "")
            res8 = J.run_jadx(
                "app.apk", "grep", pattern="TOKEN",
                max_files=J._GREP_FILES_CEILING + 1,
            )
            assert res8["status"] == "ok"
            assert "max_files" in (res8["truncation_policy"] or "")
            res9 = J.run_jadx("app.apk", "grep", pattern="TOKEN", max_files=0)
            assert res9["status"] == "error" and "max_files" in res9["error"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_tree_dirs_mode_and_paging():
    """tree_mode='dirs' rollup + offset/limit paging — the fix for the flat
    500-path wall that pushed models into read+glob combos."""
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        src, ws, _ = _fresh_workspace(root)
        # nested package tree: sources/com/example/{a,b}, each with 2 files
        for pkg in ("a", "b"):
            d = os.path.join(ws, "sources", "com", "example", pkg)
            os.makedirs(d, exist_ok=True)
            for i in range(2):
                with open(os.path.join(d, f"X{i}.java"), "w") as fh:
                    fh.write("x")
        res = J.run_jadx("app.apk", "tree", tree_mode="dirs")
        assert res["status"] == "ok" and res["tree_mode"] == "dirs"
        by_dir = {e["dir"]: e for e in res["dirs"]}
        assert "sources/com/example" in by_dir
        # rollup counts descendants: example holds C0,C1 + a/2 + b/2
        assert by_dir["sources/com/example"]["total_files"] == 6
        assert by_dir["sources/com/example"]["files"] == 2
        assert set(by_dir["sources/com/example"]["subdirs"]) == {"a", "b"}
        # glob filters dir rollups by the files inside them
        res_g = J.run_jadx("app.apk", "tree", tree_mode="dirs", glob="sources/*")
        assert res_g["status"] == "ok"
        assert all(e["dir"].startswith("sources") for e in res_g["dirs"])
        # files mode: offset/limit paging, disjoint pages
        with _Restore() as p:
            p.patch(J, "_TREE_LIST_CAP", 4)
            f1 = J.run_jadx("app.apk", "tree", limit=4)
            assert f1["status"] == "ok" and len(f1["files"]) == 4
            assert f1["truncated"] is True and f1["next_offset"] == 4
            f2 = J.run_jadx("app.apk", "tree", limit=4, offset=4)
            assert f2["status"] == "ok" and f2["offset"] == 4
            assert not set(f1["files"]) & set(f2["files"])
        # validation: junk mode / limit / offset
        bad = J.run_jadx("app.apk", "tree", tree_mode="json")
        assert bad["status"] == "error" and "tree_mode" in bad["error"]
        bad2 = J.run_jadx("app.apk", "tree", limit=0)
        assert bad2["status"] == "error" and "limit" in bad2["error"]
        bad3 = J.run_jadx("app.apk", "tree", offset=-2)
        assert bad3["status"] == "error" and "offset" in bad3["error"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_class_pull_missing_binary_clean_error():
    r, root = _tmp_root()
    try:
        _fake_apk(root)
        with _Restore() as p:
            p.patch(J, "resolve_jadx_bin", lambda: None)
            res = J.run_jadx("app.apk", "class", single_class="com.example.Foo")
        assert res["status"] == "error" and "jadx not found" in res["error"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


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