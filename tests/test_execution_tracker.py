"""Unit tests for listeners.execution_tracker — the zombie kill switch.

Fuzz 2026-09-20 residual fix. These tests pin the tracker contract offline:
bookkeeping, same-session enforcement, precise async cancellation, and the
thread-kind verdict shape. No Brain socket, no real subprocess sweeps.
"""

import asyncio

from listeners.execution_tracker import CURRENT_SESSION, ExecutionTracker


def test_list_and_finish_cycle():
    tracker = ExecutionTracker()
    eid = tracker.begin("utils.test.tool", "0", "async")
    entries = tracker.list_executions()["executions"]
    assert any(e["exec_id"] == eid for e in entries)
    assert entries[0]["kind"] == "async"
    tracker.finish(eid)
    assert tracker.list_executions()["count"] == 0


def test_kill_unknown_id():
    tracker = ExecutionTracker()
    res = asyncio.run(tracker.kill("E-999999"))
    assert res["status"] == "Failed"
    assert "list_tool_executions" in res["error"]


def test_kill_cross_session_requires_force():
    tracker = ExecutionTracker()
    eid = tracker.begin("utils.test.tool", "9", "async")

    async def attempt():
        CURRENT_SESSION.set("7")
        return await tracker.kill(eid, force=False)

    res = asyncio.run(attempt())
    assert res["status"] == "Failed"
    assert "force=True" in res["error"]
    # The entry must still be registered after a refusal.
    assert any(e["exec_id"] == eid for e in tracker.list_executions()["executions"])
    tracker.finish(eid)


def test_kill_async_sleep_task():
    tracker = ExecutionTracker()

    async def sleeper():
        await asyncio.sleep(30)

    async def scenario():
        eid = tracker.begin("utils.test.tool", "0", "async")
        task = asyncio.ensure_future(sleeper())
        tracker.attach_task(eid, task)
        CURRENT_SESSION.set("0")
        res = await tracker.kill(eid, force=False)
        return res, task

    res, task = asyncio.run(scenario())
    assert res["status"] == "Success"
    assert res["cancelled"] is True
    assert res["cancel_observed"] is True
    assert task.cancelled() or task.done()


def test_kill_thread_kind_no_future_attached():
    tracker = ExecutionTracker()
    eid = tracker.begin("utils.test.tool", "0", "thread")

    async def attempt():
        CURRENT_SESSION.set("0")
        return await tracker.kill(eid)

    res = asyncio.run(attempt())
    assert res["status"] == "Success"
    # No future was attached, so no "abandoned thread" claim is made.
    assert res["abandoned_thread"] is False
    tracker.finish(eid)


def test_same_session_kill_allowed():
    tracker = ExecutionTracker()
    eid = tracker.begin("utils.test.tool", "0", "async")

    async def attempt():
        CURRENT_SESSION.set("0")
        return await tracker.kill(eid)

    res = asyncio.run(attempt())
    assert res["status"] == "Success"
    assert tracker.list_executions()["count"] == 0