"""Tests for the per-turn tool budget (utils/tool_budget.py).

Covers: counting and final-call detection, turn_key reset, idle-TTL
fallback reset, terminal-lane exemption past the limit, disabled mode,
and directive/result wrapping.
"""

from utils.tool_budget import (
    BUDGET_EXHAUSTED,
    BUDGET_LAST,
    BUDGET_OK,
    BUDGET_TERMINAL_LANE,
    ToolBudget,
    terminal_directive,
    wrap_result,
)


def make_budget(monkeypatch, limit=10, idle_reset_min=5.0, allowlist=None):
    monkeypatch.delenv("TOOL_BUDGET_PER_TURN", raising=False)
    monkeypatch.delenv("TOOL_BUDGET_IDLE_RESET_MIN", raising=False)
    monkeypatch.delenv("TOOL_BUDGET_TERMINAL_ALLOWLIST", raising=False)
    return ToolBudget(limit=limit, idle_reset_min=idle_reset_min, allowlist=allowlist)


class TestCounting:
    def test_first_call_ok(self, monkeypatch):
        b = make_budget(monkeypatch)
        decision, meta = b.pre_dispatch("agent-a", "chat:msg1", "auxiliaries.nmap.run_scan")
        assert decision == BUDGET_OK
        assert meta["used"] == 1 and meta["remaining"] == 9

    def test_ten_calls_then_refused(self, monkeypatch):
        b = make_budget(monkeypatch, limit=10)
        tool = "auxiliaries.nmap.run_scan"
        decisions = [b.pre_dispatch("a", "t1", tool)[0] for _ in range(10)]
        assert decisions[:9] == [BUDGET_OK] * 9
        assert decisions[9] == BUDGET_LAST
        _, meta = b.pre_dispatch("a", "t1", tool)
        assert meta["status"] == BUDGET_EXHAUSTED
        assert meta["directive"], "refusal must carry the directive text"

    def test_new_turn_key_resets(self, monkeypatch):
        b = make_budget(monkeypatch, limit=2)
        tool = "t"
        for _ in range(2):
            b.pre_dispatch("a", "turn-1", tool)
        assert b.pre_dispatch("a", "turn-1", tool)[0] == BUDGET_EXHAUSTED
        assert b.pre_dispatch("a", "turn-2", tool)[0] == BUDGET_OK

    def test_same_agent_isolated_from_other_agents(self, monkeypatch):
        b = make_budget(monkeypatch, limit=1)
        assert b.pre_dispatch("a", "t", "x")[0] == BUDGET_LAST
        assert b.pre_dispatch("b", "t", "x")[0] == BUDGET_LAST

    def test_last_call_meta_counts_tenth(self, monkeypatch):
        b = make_budget(monkeypatch, limit=10)
        decision, meta = b.pre_dispatch("a", "t", "x")
        for _ in range(9):
            decision, meta = b.pre_dispatch("a", "t", "x")
        assert decision == BUDGET_LAST
        assert meta["used"] == 10 and meta["limit"] == 10

    def test_no_turn_key_uses_idle_reset(self, monkeypatch):
        b = make_budget(monkeypatch, limit=2, idle_reset_min=0.001)  # 60ms
        tool = "x"
        b.pre_dispatch("a", None, tool)
        b.pre_dispatch("a", None, tool)           # → last call
        assert b.pre_dispatch("a", None, tool)[0] == BUDGET_EXHAUSTED
        import time
        time.sleep(0.08)                           # past the idle window
        assert b.pre_dispatch("a", None, tool)[0] == BUDGET_OK


class TestTerminalLane:
    def test_reporting_tools_execute_past_limit(self, monkeypatch):
        b = make_budget(monkeypatch, limit=2)
        for _ in range(3):
            b.pre_dispatch("a", "t", "exploit.tool")
        decision, meta = b.pre_dispatch("a", "t", "utils.memory_tools.remember_text")
        assert decision == BUDGET_TERMINAL_LANE
        assert meta["status"] == BUDGET_TERMINAL_LANE

    def test_terminal_lane_does_not_consume(self, monkeypatch):
        b = make_budget(monkeypatch, limit=1)
        b.pre_dispatch("a", "t", "x")
        for _ in range(5):
            assert b.pre_dispatch("a", "t", "utils.findings.report_finding")[0] == BUDGET_TERMINAL_LANE
        assert b.pre_dispatch("a", "t", "x")[0] == BUDGET_EXHAUSTED

    def test_terminal_lanes_count_within_budget(self, monkeypatch):
        b = make_budget(monkeypatch, limit=3)
        decision, meta = b.pre_dispatch("a", "t", "utils.memory_tools.remember_text")
        assert decision == BUDGET_OK  # normal counting before exhaustion


class TestDisabled:
    def test_limit_zero_never_restricts(self, monkeypatch):
        b = make_budget(monkeypatch, limit=0)
        for _ in range(25):
            decision, meta = b.pre_dispatch("a", "t", "x")
            assert decision == BUDGET_OK
            assert meta == {"enabled": False}


class TestEnvConfig:
    def test_env_fallbacks(self, monkeypatch):
        monkeypatch.setenv("TOOL_BUDGET_PER_TURN", "3")
        monkeypatch.setenv("TOOL_BUDGET_IDLE_RESET_MIN", "2")
        b = ToolBudget()
        assert b.limit == 3 and b.idle_reset_sec == 120.0

    def test_env_allowlist(self, monkeypatch):
        monkeypatch.setenv("TOOL_BUDGET_TERMINAL_ALLOWLIST", "utils.findings.,")
        b = ToolBudget()
        assert b.is_terminal_lane("utils.findings.report_finding")
        assert not b.is_terminal_lane("utils.memory_tools.remember_text")


class TestWrapping:
    def test_wrap_dict_preserves_keys(self):
        meta = {"status": BUDGET_LAST, "used": 10, "limit": 10}
        out = wrap_result({"status": "Success", "job_id": "j1"}, "wrap up", meta)
        assert out["job_id"] == "j1" and out["status"] == "Success"
        assert out["tool_budget"]["directive"] == "wrap up"

    def test_wrap_dict_never_overwrites_tool_budget(self):
        meta = {"status": BUDGET_LAST}
        out = wrap_result({"tool_budget": {"custom": 1}}, "d", meta)
        assert out["tool_budget"] == {"custom": 1}

    def test_wrap_string_appends(self):
        out = wrap_result("scan done", "report now", {"status": BUDGET_LAST})
        assert out.startswith("scan done")
        assert "[budget:last_call] report now" in out

    def test_wrap_other_types_inert(self):
        meta = {"status": BUDGET_LAST}
        assert wrap_result([1, 2], "d", meta) == [1, 2]


class TestDirectives:
    def test_directive_text(self):
        assert "10/10" in terminal_directive(BUDGET_LAST, 10, 10)
        assert "10/10" in terminal_directive(BUDGET_EXHAUSTED, 10, 10)