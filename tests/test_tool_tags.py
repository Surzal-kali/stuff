"""Unit tests for the tool-category tagging system (daharness/tool_tags.py).

pytest-compatible (plain ``test_*`` functions, no fixtures) AND directly
runnable with ``python3 tests/test_tool_tags.py`` from any CWD (system python
has no pytest; the framework venv does — ledger 09/21 re-verified 09/22: venv
pytest 9.1.1 present).

All tests are OFFLINE: no chroma connection, no embeddings, no network.  The
discovery integration test calls ``discover_local_tools`` on a bare
``__new__`` instance (no ChromaDB client is constructed) and patches
WORKSPACE_ROOT / ALLOWED_TOOL_ROOTS to the repo — the same code path a
reindex runs, minus the live vector store.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from constants import framework_tool, TransportType  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
from daharness.tool_tags import (  # noqa: E402
    CANONICAL_TAGS,
    TOOL_TAGS,
    resolve_tags,
    tagged_doc,
    unknown_tags,
)

# The 27 tools tagged net.services (operator decision 2026-09-22: 13th bucket
# added as the landing zone for non-HTTP network-service tooling — SSH/SMB/FTP
# access, remote exec, secrets dump, callback listeners — and the default
# category for future tool-nursery candidates from model suggestions).
NET_SERVICES_IDS = (
    # SSH session lane
    "auxiliaries.ssh_exec.ssh_exec_batch",
    "utils.paramiko_client.ssh_connect",
    "utils.paramiko_client.ssh_exec",
    "utils.paramiko_client.ssh_shell",
    "utils.paramiko_client.ssh_close",
    "utils.paramiko_client.paramiko_client",
    # Impacket lane
    "auxiliaries.impacket_suite.smb_enum_shares",
    "auxiliaries.impacket_suite.smb_read_file",
    "auxiliaries.impacket_suite.secretsdump",
    "auxiliaries.impacket_suite.psexec_exec",
    "auxiliaries.impacket_suite.wmiexec_exec",
    "auxiliaries.impacket_suite.atexec_exec",
    # SMB null-session recon
    "auxiliaries.smb_scanner.SMBScanner.check_null_session",
    "auxiliaries.smb_scanner.run_smb_recon",
    # FTP/SFTP lane
    "auxiliaries.ftp_recon.ftp_banner",
    "auxiliaries.ftp_recon.ftp_anon_check",
    "auxiliaries.ftp_recon.ftp_list",
    "auxiliaries.ftp_recon.ftp_get",
    "auxiliaries.ftp_recon.ftp_put",
    "auxiliaries.ftp_recon.sftp_list",
    "auxiliaries.ftp_recon.sftp_get",
    "auxiliaries.ftp_recon.sftp_put",
    # Reverse-shell listeners
    "listeners.listening.TCPListener.open_listener",
    "listeners.listening.TCPListener.close_listener",
    "listeners.listening.TCPListener.read_listener",
    "listeners.listening.TCPListener.send_to_listener",
    "listeners.listening.TCPListener.clear_listener_data",
)

# Currently EMPTY: future fit-gaps land here (left untagged pending operator
# decision) and in the tool_tags.py docstring together.
PENDING_IDS = ()


# ---------------------------------------------------------------------------
# decorator (constants.py)
# ---------------------------------------------------------------------------
def test_decorator_tags_param_stored():
    @framework_tool(doc="Fuzz hidden directories.", tags=["web.fuzz"])
    def _t():
        return None

    assert getattr(_t, "_tool_tags", None) == ("web.fuzz",)
    assert _t._is_framework_tool is True


def test_decorator_tags_default_empty():
    @framework_tool(doc="No tags here.")
    def _t2():
        return None

    assert getattr(_t2, "_tool_tags", None) == ()


def test_decorator_transport_untouched_by_tags():
    @framework_tool(
        "x", transport=TransportType.LOCAL_FILE, tags=["net.raw"]
    )
    def _t3():
        return None

    assert _t3._transport == TransportType.LOCAL_FILE


# ---------------------------------------------------------------------------
# resolve_tags / tagged_doc / unknown_tags
# ---------------------------------------------------------------------------
def test_resolve_map_fallback():
    assert resolve_tags("auxiliaries.amass.run_amass") == ("recon.subdomain",)


def test_resolve_unknown_tool_empty():
    assert resolve_tags("no.such.tool") == ()


def test_resolve_decorator_wins_over_map():
    assert resolve_tags("auxiliaries.amass.run_amass", ("web.fuzz",)) == (
        "web.fuzz",
    )


def test_resolve_normalizes_and_drops_empty():
    got = resolve_tags("no.such.tool", (" web.fuzz ", "", None))
    assert got == ("web.fuzz",)


def test_resolve_warns_on_noncanonical_but_keeps():
    seen = []

    def warn(msg):
        seen.append(msg)

    got = resolve_tags("some.tool", ("recon.subdomian",), warn=warn)
    assert got == ("recon.subdomian",)  # warn-and-keep, never silent-drop
    assert len(seen) == 1 and "non-canonical" in seen[0]
    assert "recon.subdomian" in seen[0]


def test_resolve_no_warn_on_canonical():
    seen = []
    resolve_tags("auxiliaries.amass.run_amass", warn=seen.append)
    assert seen == []


def test_tagged_doc_format():
    doc = tagged_doc("Craft an ICMP echo.", ("net.raw",))
    assert doc == "Craft an ICMP echo.\n\nCategories: net.raw"


def test_tagged_doc_multi_and_unchanged():
    assert tagged_doc("d", ("a.b", "c.d")).endswith("\n\nCategories: a.b, c.d")
    assert tagged_doc("d", ()) == "d"


def test_unknown_tags():
    assert unknown_tags(("web.fuzz", "brute.crack")) == ()
    assert unknown_tags(("web.fuzz", "recon.subdomian")) == ("recon.subdomian",)


# ---------------------------------------------------------------------------
# the map itself (self-consistency)
# ---------------------------------------------------------------------------
def test_map_values_canonical():
    bad = {tid: t for tid, ts in TOOL_TAGS.items() for t in ts if t not in CANONICAL_TAGS}
    assert not bad, f"non-canonical tags in TOOL_TAGS: {bad}"


def test_map_values_nonempty_and_unique_per_tool():
    for tid, ts in TOOL_TAGS.items():
        assert isinstance(ts, tuple) and ts, f"empty tag tuple for {tid}"
        assert len(set(ts)) == len(ts), f"duplicate tags for {tid}"


def test_map_keys_are_tool_ids():
    for tid in TOOL_TAGS:
        assert tid.count(".") >= 2, f"malformed tool_id: {tid}"
        assert not tid.startswith("daharness."), f"internal module tagged: {tid}"


def test_net_services_tools_tagged():
    for tid in NET_SERVICES_IDS:
        assert TOOL_TAGS.get(tid) == ("net.services",), (
            f"{tid} should be tagged ('net.services',), got {TOOL_TAGS.get(tid)}"
        )


def test_pending_tools_untagged():
    tagged_but_pending = [tid for tid in PENDING_IDS if tid in TOOL_TAGS]
    assert not tagged_but_pending, (
        f"pending tools got tags without an operator decision: "
        f"{tagged_but_pending} — update PENDING_IDS + the tool_tags.py "
        f"docstring together"
    )


def test_ids_shape():
    assert len(NET_SERVICES_IDS) == 27
    assert PENDING_IDS == ()
    for tid in NET_SERVICES_IDS:
        assert tid.count(".") >= 2, f"malformed id: {tid}"


# ---------------------------------------------------------------------------
# ToolManifest carries tags (pydantic roundtrip)
# ---------------------------------------------------------------------------
def test_tool_manifest_tags_field():
    from daharness.models import ToolManifest
    from constants import TransportType

    m = ToolManifest(
        module_id="x.y.z",
        internal_semantic_capability="cap",
        external_sanitized_description="cap",
        implementation_path="x.y.z",
        internal_semantics="s",
        transport=TransportType.BRAIN_DISPATCH,
        tags=("web.fuzz", "brute.crack"),
    )
    assert m.tags == ("web.fuzz", "brute.crack")
    # from_output passthrough
    m2 = ToolManifest.from_output(m.model_dump())
    assert m2.tags == ("web.fuzz", "brute.crack")


# ---------------------------------------------------------------------------
# discovery integration (real code path, no chroma connection)
# ---------------------------------------------------------------------------
def _run_discovery():
    """discover_local_tools on a bare ToolRegistry (no __init__, no chroma).

    dotenv is stubbed first (same pattern as test_scope_gate._load_msf_isolated):
    several payloads modules call ``load_dotenv`` at module import, which
    PermissionErrors for a non-root caller against the root-0600 .env.  The
    live gateway runs as root and imports them fine — the stub only makes the
    OFFLINE non-root run see the same module set.
    """
    import sys as _sys
    import types as _types
    import daharness.registry as reg

    real_dotenv = _sys.modules.get("dotenv")
    saved_root, saved_roots = reg.WORKSPACE_ROOT, reg.ALLOWED_TOOL_ROOTS
    try:
        stub = _types.ModuleType("dotenv")
        stub.load_dotenv = lambda *a, **k: None
        stub.dotenv_values = lambda *a, **k: {}
        _sys.modules["dotenv"] = stub
        reg.WORKSPACE_ROOT = ROOT
        reg.ALLOWED_TOOL_ROOTS = [
            (ROOT / b).resolve()
            for b in ("auxiliaries", "payloads", "listeners", "utils", "encoders")
        ]
        shim = reg.ToolRegistry.__new__(reg.ToolRegistry)
        return shim.discover_local_tools(root=ROOT)
    finally:
        reg.WORKSPACE_ROOT, reg.ALLOWED_TOOL_ROOTS = saved_root, saved_roots
        if real_dotenv is not None:
            _sys.modules["dotenv"] = real_dotenv
        else:
            _sys.modules.pop("dotenv", None)


def test_discovery_tags_every_mapped_tool():
    manifests = {m.module_id: m for m in _run_discovery()}
    # Every map key must exist in the real discovery output (typo guard).
    missing = [tid for tid in TOOL_TAGS if tid not in manifests]
    assert not missing, f"TOOL_TAGS keys not discoverable: {missing}"
    # Tagged manifests: tags on the manifest + Categories line in the doc.
    for tid, ts in TOOL_TAGS.items():
        m = manifests[tid]
        assert m.tags == ts, f"{tid}: {m.tags} != {ts}"
        line = f"\n\nCategories: {', '.join(ts)}"
        assert m.internal_semantic_capability.endswith(line), (
            f"{tid} capability missing Categories line"
        )


def test_discovery_untagged_tools_stay_clean():
    manifests = {m.module_id: m for m in _run_discovery()}
    for tid in PENDING_IDS:
        m = manifests[tid]
        assert m.tags == (), f"{tid} unexpectedly tagged: {m.tags}"
        assert "Categories:" not in m.internal_semantic_capability
    # The operator-decided net.services set must carry the line.
    m = manifests["auxiliaries.ssh_exec.ssh_exec_batch"]
    assert m.tags == ("net.services",)
    assert m.internal_semantic_capability.endswith("Categories: net.services")


def test_discovery_spot_capabilities():
    manifests = {m.module_id: m for m in _run_discovery()}
    cap = manifests["auxiliaries.amass.run_amass"].internal_semantic_capability
    assert cap.endswith("Categories: recon.subdomain")
    cap2 = manifests["utils.packetcraft.send_packet"].internal_semantic_capability
    assert cap2.endswith("Categories: net.raw")
    cap3 = manifests["auxiliaries.impacket_suite.secretsdump"].internal_semantic_capability
    assert cap3.endswith("Categories: net.services")
    assert len(manifests) >= 150
    # 154/154 tagged now: every discovered tool carries at least one tag.
    untagged = [m.module_id for m in manifests.values() if not m.tags]
    assert not untagged, f"discovered tools with no tags: {untagged}"


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