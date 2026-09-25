"""Unit tests for auxiliaries/db_client.py (direct-database client tools).

pytest-compatible (plain ``test_*`` functions, self-contained patches - no
pytest fixtures) AND directly runnable with ``python3 tests/test_db_client.py``
from any CWD (mirrors tests/test_jadx.py's runner).

All tests are OFFLINE: no database server is contacted.  The connection layer
is replaced at the module seam (``_open_mssql`` / ``_open_mysql`` /
``_open_postgres`` module attributes - _open_connection looks them up at call
time) and the scope gate is patched at utils.scope_gate.check_scan.  The real
SessionManager singleton is used but every session created is closed in the
test body.  No network, no subprocesses.
"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auxiliaries.db_client as DB  # noqa: E402
import utils.scope_gate as SG  # noqa: E402
import utils.handles as H  # noqa: E402


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


def _fake_conn(plan=None):
    """Fake adapter INSTANCE: query() dispatches on SQL substring -> (rows, error)."""
    plan = plan or {}

    class FakeConn:
        def __init__(self):
            self.queries = []
            self.closed = False

        def query(self, sql):
            self.queries.append(sql)
            for needle, rows in plan.items():
                if needle.lower() in sql.lower():
                    return rows, None
            return [], None

        def close(self):
            self.closed = True

    return FakeConn()


def _allow_gate():
    r = _Restore()
    r.patch(SG, "check_scan", lambda *_a, **k: (True, "test: allowed"))
    return r


def _deny_gate():
    r = _Restore()
    r.patch(SG, "check_scan", lambda *_a, **k: (False, "test refusal"))
    return r


def _cleanup_sessions():
    for s in DB._sm.list_sessions():
        if s["kind"] == "db":
            DB._sm.close(s["sid"])


def _fake_mssql_open(plan=None):
    """Patch DB._open_mssql with a factory returning a FakeConn; returns
    (restore, fake_instance_holder)."""
    holder = {}

    def fake_open(host, port, username, password, database, domain, hashes, timeout):
        holder["args"] = (host, port, username, database, domain, hashes)
        conn = _fake_conn(plan)
        holder["conn"] = conn
        return conn

    r = _Restore()
    r.patch(DB, "_open_mssql", fake_open)
    return r, holder


# ---------------------------------------------------------------------------
# gate matrix
# ---------------------------------------------------------------------------


def test_gate_blocks_connect():
    with _deny_gate():
        try:
            DB.db_connect("192.168.56.30", "sa", "pw")
            raise AssertionError("db_connect should have raised ScopeGateError")
        except DB.ScopeGateError as exc:
            assert "test refusal" in str(exc)


def test_gate_blocks_batch_and_farm():
    with _deny_gate():
        for call in (
            lambda: DB.db_exec_batch("192.168.56.30", "sa", "pw", ["SELECT 1"]),
            lambda: DB.db_schema_farm("192.168.56.30", "sa", "pw"),
        ):
            try:
                call()
                raise AssertionError("expected ScopeGateError")
            except DB.ScopeGateError as exc:
                assert "test refusal" in str(exc)


def test_exec_regate_after_scope_change():
    """A db: session opened in lab mode must not survive a scope arming."""
    r, holder = _fake_mssql_open()
    with r, _allow_gate():
        env = DB.db_connect("192.168.56.30", "sa", "pw")
        assert env["status"] == "Success", env
        handle = env["handle"]
        try:
            with _deny_gate():
                try:
                    DB.db_exec(handle, "SELECT 1")
                    raise AssertionError("db_exec should have re-gated")
                except DB.ScopeGateError as exc:
                    assert "test refusal" in str(exc)
        finally:
            DB._sm.close(handle.split(":", 1)[1])


# ---------------------------------------------------------------------------
# handle lifecycle
# ---------------------------------------------------------------------------


def test_connect_exec_close_lifecycle():
    plan = {"SELECT 1": [{"": 1}]}
    r, holder = _fake_mssql_open(plan)
    with r, _allow_gate():
        env = DB.db_connect("192.168.56.30", "sa", "s3cret")
        assert env["status"] == "Success", env
        assert env["handle"].startswith("db:sess-"), env
        assert "s3cret" not in str(env)  # no password echo
        handle = env["handle"]
        try:
            res = DB.db_exec(handle, "SELECT 1")
            assert res["status"] == "Success", res
            assert res["rows"] == [{"": 1}]
            # query went through the adapter seam
            assert holder["conn"].queries == ["SELECT 1"]
        finally:
            closed = DB.db_close(handle)
            assert closed["status"] == "Success"
            # second close = not found
            assert DB.db_close(handle)["status"] == "Failed"
            assert holder["conn"].closed, "db_close must close the adapter"


def test_exec_unknown_handle():
    res = DB.db_exec("db:sess-9999", "SELECT 1")
    assert res["status"] == "Failed" and "not found" in res["error"]


def test_handle_kind_db_registered():
    """'db' is a first-class typed handle kind now."""
    assert "db" in H.VALID_KINDS
    h = H.format_handle("db", "sess-0001")
    assert h == "db:sess-0001"
    assert H.parse_handle(h) == ("db", "sess-0001")
    reason = H.validate_handle_for_tool("ssh:sess-0001", ["db"])
    assert reason and "'db'" in reason and "ssh" in reason, reason


# ---------------------------------------------------------------------------
# read-only seatbelt
# ---------------------------------------------------------------------------


def test_read_only_guard_matrix():
    with _allow_gate():
        for bad in (
            "INSERT INTO t VALUES (1)",
            "EXEC xp_cmdshell 'whoami'",
            "execute sp_adduser",
            "UPDATE users SET pw='x'",
            "DELETE FROM logs",
            "SELECT * INTO outfile FROM t",
            "SELECT 1;",  # multi-statement: only last result set survives
            "-- comment\nDROP TABLE t",
        ):
            res = DB.db_exec_batch("192.168.56.30", "sa", "pw", [bad])
            assert res["status"] == "Failed", (bad, res)
            assert "read_only=True" in res["error"], (bad, res)
        for good in (
            "SELECT 1",
            "with cte as (select 1) select * from cte",
            "USE master",
            "SET nocount ON",
            "DECLARE @a int",
        ):
            r2, _h = _fake_mssql_open()
            with r2, _allow_gate():
                res = DB.db_exec_batch("192.168.56.30", "sa", "pw", [good])
                assert res["status"] == "Success", (good, res)


def test_read_only_bypass_executes():
    """read_only=False is the explicit write lane; query passes through."""
    plan = {"insert": [{"ok": 1}]}
    r, holder = _fake_mssql_open(plan)
    with r, _allow_gate():
        res = DB.db_exec_batch(
            "192.168.56.30", "sa", "pw", ["INSERT t VALUES (1)"], read_only=False
        )
        assert res["status"] == "Success", res
        assert res["results"][0]["rows"] == [{"ok": 1}]
        assert holder["conn"].queries == ["INSERT t VALUES (1)"]


def test_exec_read_only_single_query():
    r, _h = _fake_mssql_open()
    with r, _allow_gate():
        env = DB.db_connect("192.168.56.30", "sa", "pw")
        handle = env["handle"]
        try:
            res = DB.db_exec(handle, "UPDATE users SET pw='x'")
            assert res["status"] == "Failed" and "read_only=True" in res["error"]
            res2 = DB.db_exec(handle, "SELECT 1", read_only=False)
            assert res2["status"] == "Success"
        finally:
            DB.db_close(handle)


# ---------------------------------------------------------------------------
# envelopes + caps
# ---------------------------------------------------------------------------


def test_batch_caps_rows_and_cells():
    plan = {"SELECT 1": [{"c": "x" * 700} for _ in range(210)]}
    r, _h = _fake_mssql_open(plan)
    with r, _allow_gate():
        res = DB.db_exec_batch("192.168.56.30", "sa", "pw", ["SELECT 1"])
        assert res["status"] == "Success"
        entry = res["results"][0]
        assert entry["row_count"] == 210
        assert entry.get("rows_truncated") is True
        assert len(entry["rows"]) == DB.MAX_ROWS_EXEC
        cell = entry["rows"][0]["c"]
        assert len(cell) < 700 and "..." in cell and cell.endswith("chars]")


def test_batch_query_caps_and_normalization():
    with _allow_gate():
        r, _h = _fake_mssql_open()
        with r:
            res = DB.db_exec_batch(
                "192.168.56.30", "sa", "pw", ["SELECT 1"] * (DB.MAX_QUERIES_BATCH + 1)
            )
            assert res["status"] == "Failed" and "capped at" in res["error"]
            res2 = DB.db_exec_batch("192.168.56.30", "sa", "pw", "SELECT 1")
            assert res2["status"] == "Success" and res2["queries_run"] == 1
            res3 = DB.db_exec_batch("192.168.56.30", "sa", "pw", ["SELECT 1", 5])
            assert res2["status"] == "Success" and res3["status"] == "Failed"


def test_unsupported_dbms():
    with _allow_gate():
        res = DB.db_connect("192.168.56.30", "sa", "pw", dbms="oracle")
        assert res["status"] == "Failed" and "mssql" in res["error"]


def test_farm_rejects_non_mssql_with_pointer():
    with _allow_gate():
        res = DB.db_schema_farm("192.168.56.30", "root", "", dbms="mysql")
        assert res["status"] == "Failed"
        assert "db_exec_batch" in res["error"]


# ---------------------------------------------------------------------------
# schema farm against a fake server
# ---------------------------------------------------------------------------


def _farm_plan(sample_rows):
    return {
        # order matters: most specific needles first
        "SELECT TOP": sample_rows,
        "INFORMATION_SCHEMA.COLUMNS": [
            {"TABLE_SCHEMA": "dbo", "TABLE_NAME": "users", "COLUMN_NAME": "uname", "DATA_TYPE": "nvarchar"},
            {"TABLE_SCHEMA": "dbo", "TABLE_NAME": "users", "COLUMN_NAME": "passw", "DATA_TYPE": "nvarchar"},
            {"TABLE_SCHEMA": "dbo", "TABLE_NAME": "audit_log", "COLUMN_NAME": "ts", "DATA_TYPE": "datetime"},
        ],
        "sys.tables AS t": [
            {"schema_name": "dbo", "table_name": "audit_log", "row_count": 7},
            {"schema_name": "dbo", "table_name": "users", "row_count": 42},
        ],
        "sys.databases": [{"name": "appdb"}],
    }


def test_farm_full_plan():
    r, holder = _fake_mssql_open(
        _farm_plan([{"uname": "admin", "passw": "hunter2"}])
    )
    with r, _allow_gate():
        res = DB.db_schema_farm("192.168.56.30", "sa", "pw", max_dbs=5)
        assert res["status"] == "Success", res
        db0 = res["databases"][0]
        assert db0["name"] == "appdb"
        users = next(t for t in db0["tables"] if t["table"] == "users")
        assert users["row_count"] == 42
        assert users["columns"] == ["uname (nvarchar)", "passw (nvarchar)"]
        # interest-ranked sample pulled for users, not audit_log
        assert len(res["samples"]) == 1
        s = res["samples"][0]
        assert s["table"] == "users" and s["rows"][0]["passw"] == "hunter2"
        assert holder["conn"].closed, "farm must close its connection"
        # 1 (dbs) + 2 (tables+cols) + 1 (sample) queries
        assert len(holder["conn"].queries) == 4


def test_farm_bracket_escapes_catalog_names():
    r, holder = _fake_mssql_open(
        _farm_plan([{"uname": "x"}])
    )
    with r, _allow_gate():
        res = DB.db_schema_farm("192.168.56.30", "sa", "pw")
        assert res["status"] == "Success"
        # db names from the server catalog are bracket-escaped in every query
        joined = "\n".join(holder["conn"].queries)
        assert "[appdb].sys.tables" in joined
        assert "[appdb].INFORMATION_SCHEMA.COLUMNS" in joined
        assert "SELECT TOP 3 * FROM [appdb].[dbo].[users]" in joined


def test_farm_include_samples_false():
    r, holder = _fake_mssql_open(_farm_plan([]))
    with r, _allow_gate():
        res = DB.db_schema_farm(
            "192.168.56.30", "sa", "pw", include_samples=False, max_dbs=2
        )
        assert res["status"] == "Success" and res["samples"] == []
        assert not any("SELECT TOP" in q for q in holder["conn"].queries)


# ---------------------------------------------------------------------------
# mysql / postgres adapters (fake modules; live authority = runtime seat)
# ---------------------------------------------------------------------------


def test_mysql_driver_missing_envelope():
    saved = sys.modules.get("pymysql")
    sys.modules["pymysql"] = None  # forces ImportError on `import pymysql`
    try:
        with _allow_gate():
            res = DB.db_exec_batch("192.168.56.30", "root", "", ["SELECT 1"], dbms="mysql")
            assert res["status"] == "Failed"
            assert "pip install pymysql" in res["error"], res
    finally:
        if saved is not None:
            sys.modules["pymysql"] = saved
        else:
            sys.modules.pop("pymysql", None)


class _FakeMysqlCursor:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, sql):
        self.sql = sql

    def fetchmany(self, n):
        return self._rows[:n]


class _FakeMysqlConn:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.closed = False
        self._rows = [{"id": 1, "uname": "root", "passw": "toor"}]

    def cursor(self):
        return _FakeMysqlCursor(self._rows)

    def close(self):
        self.closed = True


def _install_fake_pymysql():
    fake = types.ModuleType("pymysql")
    cursors = types.ModuleType("pymysql.cursors")
    cursors.DictCursor = object()  # sentinel; the fake ignores it anyway
    fake.cursors = cursors
    fake.connect = lambda **kwargs: _FakeMysqlConn(**kwargs)
    sys.modules["pymysql"] = fake
    return fake


def test_mysql_plumbing_fake_module():
    saved = sys.modules.get("pymysql")
    fake = _install_fake_pymysql()
    try:
        with _allow_gate():
            res = DB.db_exec_batch(
                "192.168.56.30", "root", "", ["SELECT id, uname FROM users"],
                dbms="mysql", port=3306,
            )
            assert res["status"] == "Success", res
            assert res["results"][0]["rows"] == [{"id": 1, "uname": "root", "passw": "toor"}]
    finally:
        if saved is not None:
            sys.modules["pymysql"] = saved
        else:
            sys.modules.pop("pymysql", None)


class _FakePgNativeConn:
    def __init__(self, user, host=None, port=None, password=None, database=None, timeout=None):
        self.columns = [{"name": "id"}, {"name": "uname"}]
        self.closed = False

    def run(self, sql):
        return [[1, "admin"]]

    def close(self):
        self.closed = True


def test_pg_plumbing_fake_module():
    saved_pg = sys.modules.get("pg8000")
    fake_pg = types.ModuleType("pg8000")
    fake_native = types.ModuleType("pg8000.native")
    fake_native.Connection = _FakePgNativeConn
    fake_pg.native = fake_native
    # BOTH keys must be injected: `import pg8000.native` resolves the
    # submodule from sys.modules['pg8000.native'] (a fake has no __path__).
    sys.modules["pg8000"] = fake_pg
    sys.modules["pg8000.native"] = fake_native
    try:
        with _allow_gate():
            res = DB.db_exec_batch(
                "192.168.56.30", "postgres", "pw", ["SELECT id, uname FROM users"],
                dbms="postgres", port=5432, database="app",
            )
            assert res["status"] == "Success", res
            assert res["results"][0]["rows"] == [{"id": 1, "uname": "admin"}]
            assert res["dbms"] == "postgres"
    finally:
        if saved_pg is not None:
            sys.modules["pg8000"] = saved_pg
        else:
            sys.modules.pop("pg8000", None)


def test_pg_driver_missing_envelope():
    saved = sys.modules.get("pg8000")
    sys.modules["pg8000"] = None  # forces ImportError on `import pg8000.native`
    try:
        with _allow_gate():
            res = DB.db_connect("192.168.56.30", "postgres", "pw", dbms="postgres", port=5432)
            assert res["status"] == "Failed"
            assert "pip install pg8000" in res["error"], res
    finally:
        if saved is not None:
            sys.modules["pg8000"] = saved
        else:
            sys.modules.pop("pg8000", None)


# ---------------------------------------------------------------------------
# cross-lane disambiguation wiring (sqlmap <-> db_*)
# ---------------------------------------------------------------------------


def test_sqlmap_disambiguation_wiring():
    import payloads.sqlmap as SM

    assert "db_connect" in SM.run_sqlmap._tool_doc, SM.run_sqlmap._tool_doc
    assert "db_schema_farm" in SM.run_sqlmap._tool_doc
    assert "db_connect" in SM.sqlmap_status._tool_doc


def test_db_tools_point_back_at_sqlmap():
    for fn in (DB.db_connect, DB.db_exec_batch, DB.db_schema_farm, DB.db_exec):
        assert "run_sqlmap" in fn._tool_doc, fn.__name__


def test_all_db_tools_tagged_net_services():
    for fn in (
        DB.db_connect, DB.db_exec, DB.db_exec_batch, DB.db_schema_farm, DB.db_close
    ):
        assert "net.services" in fn._tool_tags, fn.__name__


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