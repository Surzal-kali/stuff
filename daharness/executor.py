"""Execution API exposed by the harness package.

The ``ExecutorMixin`` carries the execution/dispatch methods that are mixed into
:class:`daharness.registry.ToolRegistry`; the module-level helpers below provide
the same capability to callers that do not want to construct a full registry
client (they build a bare instance via ``__new__``).
"""

import asyncio
import functools
import importlib
import inspect
import json
import logging
import os
import subprocess
import sys
from typing import Any, Dict, Optional

from pydantic import ValidationError

from constants import TransportType
from .models import ToolManifest

logger = logging.getLogger(__name__)


class ExecutorMixin:
    """Execution and dispatch behaviour for :class:`ToolRegistry`.

    Kept as a mixin so the registry class in :mod:`daharness.registry` stays
    focused on discovery/embedding while all the "run a tool" paths live here.
    """

    async def execute_tool(self, manifest: ToolManifest, arguments: dict):
        manifest = self._ensure_valid_manifest(manifest)

        # LOGGING: Record actual execution start
        logger.info(
            f"[TOOL_EXECUTE] Executing Tool ID: {manifest.module_id} | Path: {manifest.implementation_path} | Args: {arguments}"
        )

        if manifest.transport == TransportType.LOCAL_FILE:
            # Static-scan manifests (argparse modules) run as subprocesses of
            # the script itself; _execute_local_script also enforces the
            # ALLOWED_TOOL_ROOTS path check.
            return await self._execute_local_script(
                manifest.implementation_path, arguments
            )

        if manifest.transport == TransportType.BRAIN_DISPATCH:
            return await self._execute_brain_tool(manifest.module_id, arguments)

        if manifest.transport == TransportType.MCP_RPC:
            # MCP_RPC tools (e.g. MetasploitClient.dispatch_metasploit) are async
            # methods on the same in-process class instances as the
            # BRAIN_DISPATCH tools. There is no separate MCP endpoint to call,
            # so route them through the identical Brain-first / in-process
            # fallback path. The previous stub returned "pending" without ever
            # invoking the method, which silently dropped every exploit
            # execution (the module never fired, no session was created).
            return await self._execute_brain_tool(manifest.module_id, arguments)

        raise ValueError(f"Unsupported transport type: {manifest.transport}")

    async def _execute_brain_tool(self, tool_id: str, arguments: dict):
        """Dispatch a tool call, launching the decorated function directly.

        Order of preference:
        1. Brain UDS socket (`/tmp/brain.sock`) when it is up and knows the tool.
        2. In-process launch of the pythonic function — this is the fallback that
           keeps tools runnable when the Brain sidecar is down (its startup code
           unlinks the socket, and if the sidecar dies the socket goes with it,
           surfacing as FileNotFoundError: [Errno 2] No such file or directory).
        """
        brain_result = await self._dispatch_via_brain(tool_id, arguments)
        if brain_result is not None:
            return brain_result

        logger.info(
            f"[BRAIN_DISPATCH] Socket unavailable or tool unknown; launching {tool_id} in-process"
        )
        return await self._launch_in_process(tool_id, arguments)

    async def _dispatch_via_brain(
        self, tool_id: str, arguments: dict
    ) -> Optional[Dict[str, Any]]:
        """Try the Brain socket. Returns None when the socket is unusable or the
        Brain does not know the tool, so the caller can fall back in-process.

        Returns a real result dict when the Brain actually ran (or genuinely
        failed) the tool — those are NOT retried in-process to avoid double
        side effects.
        """
        socket_path = "/tmp/brain.sock"
        # A tool that never returns (a listener, a wedged subprocess, a slow
        # nmap -p- -sV, a sqlmap crawl) used to hang this read forever and freeze
        # the whole conversation. Bound it. 600s matches the tool budget the
        # e2e doc assumes (e.g. sqlmap's documented "600s tool timeout"); env
        # overridable for faster lab targets.
        dispatch_timeout = float(os.getenv("BRAIN_DISPATCH_TIMEOUT", "600"))
        try:
            # Prepare the payload: "CALL_TOOL|session_id|tool_id|args"
            # We use session 0 for framework-level calls
            args_json = json.dumps(arguments)
            message = f"CALL_TOOL|0|{tool_id}|{args_json}"

            # Use asyncio for non-blocking socket I/O
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(socket_path), dispatch_timeout
            )

            # Use the framing logic to send/receive (consistent with the Brain)
            from listeners.thebrain import pack_message, read_message
            writer.write(pack_message(message.encode()))
            await writer.drain()

            data = await asyncio.wait_for(read_message(reader), dispatch_timeout)
            writer.close()
            await writer.wait_closed()

            text = data.decode(errors="replace")

            # Parse the JSON status envelope from the Brain. Older sidecars
            # that still return raw text ("SUCCESS: ...", "ERROR: ...") are
            # handled by the legacy fallback so a rolling upgrade doesn't break.
            try:
                envelope = json.loads(text)
            except (json.JSONDecodeError, TypeError):
                # Legacy raw-text Brain: fall back to string matching.
                if "not found in registry" in text:
                    logger.info(f"[BRAIN_DISPATCH] Brain does not know '{tool_id}'; falling back in-process")
                    return None
                return {
                    "stdout": text,
                    "status": "Success" if "ERROR" not in text else "Failed",
                }

            status = str(envelope.get("status", "")).lower()
            error_msg = envelope.get("error")

            # "not found in registry" means the Brain never scanned this tool;
            # fall back in-process instead of failing.
            if status == "error" and error_msg and "not found in registry" in error_msg:
                logger.info(f"[BRAIN_DISPATCH] Brain does not know '{tool_id}'; falling back in-process")
                return None

            result_value = envelope.get("result")
            stdout = result_value if result_value is not None else (error_msg or "")
            if not isinstance(stdout, str):
                stdout = json.dumps(stdout, default=str)

            shaped: Dict[str, Any] = {
                "stdout": stdout,
                "status": "Success" if status == "success" else "Failed",
            }
            # Pass through structured result data for typed callers.
            if result_value is not None and not isinstance(result_value, str):
                shaped["result"] = result_value
            if status != "success" and error_msg:
                shaped["error"] = error_msg
            return shaped
        except FileNotFoundError:
            logger.info(f"[BRAIN_DISPATCH] {socket_path} does not exist; Brain sidecar is down")
            return None
        except asyncio.TimeoutError:
            # Abandon the connection cleanly: an unclosed writer leaks the fd
            # (and the socket pair) for as long as the tool keeps running.
            try:
                writer.close()
            except (NameError, UnboundLocalError):
                pass  # never connected
            # The Brain accepted the call and is still executing it. Report a
            # failure but do NOT fall back in-process: that would run the tool
            # a second time with real side effects (scans, listeners, payloads).
            logger.error(
                f"[BRAIN_DISPATCH] {tool_id}: no reply within {dispatch_timeout}s; "
                "the tool may still be running on the Brain"
            )
            return {
                "error": (
                    f"Tool '{tool_id}' did not return a result within {dispatch_timeout:.0f}s. "
                    "It may still be running on the Brain; check the sidecar logs before retrying."
                ),
                "status": "Failed",
            }
        except (ConnectionError, OSError) as e:
            logger.info(f"[BRAIN_DISPATCH] Socket connect failed ({e}); falling back in-process")
            return None
        except Exception as e:
            logger.error(f"[BRAIN_ERROR] Failed to dispatch tool {tool_id}: {e}")
            return {"error": f"Brain dispatch failed: {str(e)}", "status": "Failed"}

    def _resolve_callable(self, tool_id: str) -> tuple:
        """Resolve a tool_id like 'pkg.mod.func' or 'pkg.mod.Class.func' to a
        runnable callable, instantiating the owning class if needed.

        Returns (callable, error_message); exactly one of the two is populated.
        """
        parts = tool_id.split(".")
        if len(parts) < 2:
            return None, f"Tool id '{tool_id}' is not a dotted module path"

        # Longest importable module prefix wins, so 'pkg.mod.Class.func'
        # resolves the module 'pkg.mod' and walks the remaining attrs.
        mod = None
        mod_len = 0
        for i in range(len(parts) - 1, 0, -1):
            try:
                mod = importlib.import_module(".".join(parts[:i]))
                mod_len = i
                break
            except ImportError:
                continue
        if mod is None:
            return None, f"No importable module found for '{tool_id}'"

        obj: Any = mod
        cls: Any = None
        cls_key = ""
        walked = []
        for attr in parts[mod_len:]:
            walked.append(attr)
            nxt = getattr(obj, attr, None)
            if nxt is None:
                return None, f"Attribute '{'.'.join(walked)}' not found in '{tool_id}'"
            if inspect.isclass(nxt):
                cls = nxt
                cls_key = f"{mod.__name__}.{'.'.join(walked)}"
            obj = nxt

        if cls is not None and inspect.isfunction(obj):
            # Unbound method: bind it to a cached class instance so stateful
            # clients (MetasploitClient, SMBScanner, ...) keep their handles.
            if cls_key not in self._tool_instances:
                try:
                    # Prefer an explicit shared-instance classmethod so stateful
                    # clients (MetasploitClient, SMBScanner, ...) reuse the same
                    # live handles bootstrap created instead of a dead twin.
                    factory = getattr(cls, "get_instance", None)
                    if callable(factory):
                        self._tool_instances[cls_key] = factory()
                    else:
                        self._tool_instances[cls_key] = cls()
                except TypeError as e:
                    return None, (
                        f"Class {cls.__name__} requires constructor arguments "
                        f"and cannot be auto-instantiated: {e}"
                    )
            obj = getattr(self._tool_instances[cls_key], parts[-1])

        if not callable(obj):
            return None, f"'{tool_id}' resolved to non-callable {type(obj).__name__}"
        return obj, ""

    async def _launch_in_process(self, tool_id: str, arguments: dict):
        """Launch the decorated pythonic function directly in this process.

        Async tools are awaited on the running loop; sync tools run in a worker
        thread so blocking calls (impacket, nmap) don't freeze the loop.
        """
        try:
            func, error = self._resolve_callable(tool_id)
            if func is None:
                logger.error(f"[INPROC_LAUNCH] {tool_id}: {error}")
                return {"error": error, "status": "Failed"}

            args = dict(arguments or {})
            # The secretary wraps unparseable argument payloads as {"_raw": ...}
            # and passes them through; leaving it in place makes every tool die
            # with "unexpected keyword argument '_raw'" instead of a clear
            # missing-argument error.
            args.pop("_raw", None)
            if inspect.iscoroutinefunction(func):
                result = await func(**args)
            else:
                result = await asyncio.to_thread(functools.partial(func, **args))

            return self._wrap_launch_result(result)
        except TypeError as e:
            return {"error": f"Bad arguments for {tool_id}: {e}", "status": "Failed"}
        except Exception as e:
            logger.error(f"[INPROC_LAUNCH] {tool_id} failed: {e}", exc_info=True)
            return {"error": f"In-process launch failed: {e}", "status": "Failed"}

    @staticmethod
    def _wrap_launch_result(result: Any) -> Dict[str, Any]:
        """Shape an in-process result like the Brain's {'stdout', 'status'}."""
        if result is None:
            # A None return usually means a precondition failed (e.g. the
            # Metasploit console handle is missing). Reporting that as
            # 'Success' made the secretary narrate failures as successes.
            return {
                "stdout": "",
                "result": None,
                "status": "Failed",
                "error": "Tool returned no result (precondition likely not met)",
            }
        if isinstance(result, str):
            return {"stdout": result, "status": "Success"}
        if isinstance(result, dict):
            # If the wrapper already produced a status dict, respect it.
            # Pre-approval wrappers (dispatch_metasploit's category checks,
            # for example) return {status: "Failed", error: "..."} to
            # signal failure to the secretary, and we should not relabel
            # it as Success just because it's a dict.
            existing_status = result.get("status")
            if existing_status in ("Success", "Failed"):
                # Pass through with a stdout fallback so the agent layer
                # can still surface the human-readable text.
                wrapped = {
                    "stdout": result.get("stdout") or json.dumps(result, default=str),
                    "status": existing_status,
                    "result": result,
                }
                if "error" in result:
                    wrapped["error"] = result["error"]
                return wrapped
            return {
                "stdout": json.dumps(result, default=str),
                "result": result,
                "status": "Success",
            }
        if isinstance(result, (list, int, float, bool)):
            return {
                "stdout": json.dumps(result, default=str),
                "result": result,
                "status": "Success",
            }
        return {"stdout": str(result), "status": "Success"}

    async def _execute_local_script(self, script_path: str, arguments: dict):
        """
        Execute a local Python script or module.
        """
        try:
            resolved_path = self._resolve_script_path(script_path)
            arg_list = []
            for key, value in (arguments or {}).items():
                if isinstance(value, (dict, list, tuple, bool)):
                    arg_list.extend([f"--{key}", json.dumps(value)])
                else:
                    arg_list.extend([f"--{key}", str(value)])

            result = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, str(resolved_path), *arg_list],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "status": "Success" if result.returncode == 0 else "Failed",
            }
        except subprocess.TimeoutExpired:
            return {"error": "Script execution timed out", "return_code": -1}
        except Exception as e:
            return {"error": str(e), "return_code": -1}


# ---------------------------------------------------------------------------
# Standalone helpers for callers that do not want a full registry client.
# Registry-owned execution is preferred because it preserves cached class
# instances across calls; these exist for one-off jobs.
# ---------------------------------------------------------------------------


def _new_registry():
    # Lazy import avoids a circular import with daharness.registry, which mixes
    # ExecutorMixin into ToolRegistry at class-definition time.
    from .registry import ToolRegistry

    registry = ToolRegistry.__new__(ToolRegistry)
    registry._tool_instances = {}
    return registry


async def execute_tool(manifest: ToolManifest, arguments: dict):
    """Execute a manifest without creating a ChromaDB client."""
    return await _new_registry().execute_tool(manifest, arguments)


async def execute_local_script(script_path: str, arguments: dict):
    """Run a local manifest script using the shared execution rules."""
    return await _new_registry()._execute_local_script(script_path, arguments)


async def dispatch_via_brain(tool_id: str, arguments: dict):
    """Attempt Brain dispatch without constructing a registry client."""
    return await _new_registry()._dispatch_via_brain(tool_id, arguments)


async def launch_in_process(tool_id: str, arguments: dict):
    """Launch a decorated Python tool without constructing a registry client."""
    return await _new_registry()._launch_in_process(tool_id, arguments)


__all__ = [
    "ExecutorMixin",
    "dispatch_via_brain",
    "execute_local_script",
    "execute_tool",
    "launch_in_process",
    "ToolManifest",
]
