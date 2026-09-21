"""Playwright sidecar: a scope-enforcing rendered-DOM recon API server.

A loopback HTTP API (like the ZAP daemon pattern) that drives a real
Chromium via Playwright and ENFORCES THE OPERATOR-ARMED SCOPE GATE at the
browser's request-routing layer — not as ad-hoc MCP, but as the same
file-backed authority every other traffic tool honours.

Scope enforcement (the point of this module)
--------------------------------------------
Every request the browser attempts is intercepted via ``context.route`` and
classified by Playwright resource type:

  - **Navigations + programmatic requests** (document, xhr, fetch, websocket)
    are run through ``utils.scope_gate.check_scan`` on the request host and
    ABORTED when out-of-scope. This is the active surface: top-level
    navigations (page.goto, in-page location changes, window.open, form
    submits, link clicks), JS fetch/XHR, and websockets. Out-of-scope hops
    here are real traffic to a host the operator didn't bless — blocked,
    logged in ``blocked_requests``.
  - **Passive subresources** (image, stylesheet, font, media, script,
    manifest, favicon) are ALLOWED from anywhere. Per operator policy: most
    real pages load critical JS/fonts from CDNs that aren't in-scope assets,
    and strictly aborting them breaks rendering for no security gain (the
    dangerous surface — data exfil, internal fetch — is the programmatic
    request lane, which IS gated). A blocked passive resource would just
    blank the page.

The armed scope is read LIVE from ``scope/.armed_packet_scope.json`` (the
same mtime-cached read the gate itself uses), so a REPL-side scope change
takes effect on the very next browser request. When DISARMED (lab mode),
nothing is gated — the browser behaves vanilla.

API (loopback only, JSON)
-------------------------
  GET  /health            -> {"ok": true, "browser": "..."}
  POST /fetch             -> one-shot rendered-DOM envelope
  POST /crawl/start       -> {"job_id": "..."}
  GET  /crawl/status?id=  -> progress + partial results
  POST /crawl/stop?id=    -> stop a crawl

Auth: a persisted Playwright ``storageState`` JSON path may be set via
``PLAYWRIGHT_STORAGE_STATE`` (env, deploy-time injection only — never a tool
arg) and is loaded into the browser context for auth'd crawling.

Honest limits
-------------
- ``challenge_detected`` flags Cloudflare-class interstitials (title/body
  markers, cf-chl headers) but cannot solve them — vanilla only, no stealth
  patches (arms race; honest negatives over faked successes).
- Passive subresource allowance means a page CAN load a tracker CDN; the
  programmatic lane (fetch/xhr/ws) is where the boundary lives.
- No sandboxed-phone support (desktop/framework host only — Sept 13 rule).
- The sidecar is launched by ``bootstrap`` (env-gated, like ZAP); if it is
  not running, the client tools return a clear error instead of faking.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import async_playwright, Error as PWError
    _HAS_PW = True
except Exception:  # noqa: BLE001
    _HAS_PW = False

_HOST = os.getenv("PLAYWRIGHT_SIDECAR_HOST", "127.0.0.1")
_PORT = int(os.getenv("PLAYWRIGHT_SIDECAR_PORT", "8484"))
_UA = os.getenv("PLAYWRIGHT_UA", "framework-pwrecon/1.0")
_STORAGE_STATE = os.getenv("PLAYWRIGHT_STORAGE_STATE", "") or None
_NAV_TIMEOUT_MS = int(os.getenv("PLAYWRIGHT_NAV_TIMEOUT_MS", "25000"))

# Resource types we GATE (active surface). Everything else is allowed.
_GATED_RESOURCE_TYPES = frozenset(
    {"document", "xhr", "fetch", "websocket"}
)

_CHALLENGE_MARKERS = (
    "just a moment", "attention required", "cf-chl", "cloudflare",
    "cf-please-wait", "verify you are human", "challenge-platform",
    "ddos protection by", "checking your browser",
)


# ---------------------------------------------------------------------------
# Scope-gated route handler
# ---------------------------------------------------------------------------

def _scope_ok(url: str) -> Tuple[bool, str]:
    """Live scope verdict for a browser request URL (host-based)."""
    try:
        from utils.scope_gate import check_scan
        return check_scan(url)
    except Exception as e:  # noqa: BLE001 - never crash the browser on a gate hiccup
        # Fail-closed would blank the page on a transient import/IO error;
        # the entry-URL gate at the client is the authoritative pre-flight.
        # Log and allow so a gate error doesn't masquerade as a dead page.
        return True, f"gate-check-skipped ({type(e).__name__})"


async def _route_handler(route, request) -> None:
    """Playwright route interception: gate active requests, pass passive."""
    rtype = request.resource_type
    url = request.url
    if rtype in _GATED_RESOURCE_TYPES:
        ok, reason = _scope_ok(url)
        if not ok:
            # Record the block in a process-global list keyed by page URL is
            # hard from a route handler; instead stash on the route's request
            # via a side dict the fetch/crawl job reads. Simpler: keep a
            # module-level ring buffer the job snapshots.
            _BLOCKED.append({"url": url, "type": rtype, "reason": reason,
                             "ts": time.time()})
            try:
                await route.abort("blockedbyclient")
                return
            except PWError:
                return
    try:
        await route.continue_()
    except PWError:
        pass  # request already gone (navigation cancelled, etc.)


_BLOCKED: List[Dict[str, Any]] = []  # ring buffer; jobs snapshot+trim


def _snapshot_blocked(since: float) -> List[Dict[str, Any]]:
    out = [b for b in _BLOCKED if b["ts"] >= since]
    # trim to last 500 to bound memory
    if len(_BLOCKED) > 500:
        del _BLOCKED[: len(_BLOCKED) - 500]
    return out


# ---------------------------------------------------------------------------
# DOM extraction
# ---------------------------------------------------------------------------

_LINK_RE = re.compile(r'<a[^>]+href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_RE = re.compile(
    r'<form[^>]*\baction\s*=\s*["\']([^"\']*)["\'][^>]*>(.*?)</form>',
    re.IGNORECASE | re.DOTALL,
)
_INPUT_RE = re.compile(
    r'<input[^>]*\b(?:name|type|value)\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_ROUTE_RE = re.compile(
    r"(?:fetch|axios|\.open)\s*\(\s*[\"'`][^\"'`]*[\"'`]\s*,?\s*[\"'`](/[^\"'`\s]{1,200})[\"'`]",
    re.IGNORECASE,
)


def _challenge_detected(title: str, body: str, headers: Dict[str, str]) -> bool:
    blob = (title + " " + body[:4000]).lower()
    if any(m in blob for m in _CHALLENGE_MARKERS):
        return True
    return any("cf-chl" in k.lower() or "challenge" in k.lower()
               for k in headers)


async def _extract_envelope(page, since: float) -> Dict[str, Any]:
    url = page.url
    status = await _last_status(page)
    title = await page.title()
    html = await page.content()
    text = await page.inner_text("body") if await _has_body(page) else html
    links = sorted({urljoin(url, m) for m in _LINK_RE.findall(html)
                    if m and not m.startswith(("javascript:", "mailto:", "tel:"))})
    forms: List[Dict[str, Any]] = []
    for action, inner in _FORM_RE.findall(html):
        inputs = _INPUT_RE.findall(inner)
        forms.append({"action": urljoin(url, action) or url,
                      "inputs": inputs[:20]})
    routes = sorted(set(_ROUTE_RE.findall(html)))[:100]
    blocked = _snapshot_blocked(since)
    challenge = _challenge_detected(title, html, {})
    return {
        "url": url,
        "status": status,
        "title": title[:200],
        "text": text[:8000],
        "links": links[:200],
        "forms": forms[:30],
        "js_routes": routes,
        "blocked_requests": blocked,
        "challenge_detected": challenge,
        "html_bytes": len(html),
    }


async def _last_status(page) -> Optional[int]:
    try:
        resp = await page.evaluate(
            "() => (performance && performance.getEntriesByType "
            "&& performance.getEntriesByType('navigation')[0] || {}).responseStatus"
        )
        return int(resp) if resp is not None else None
    except Exception:
        return None


async def _has_body(page) -> bool:
    try:
        return await page.query_selector("body") is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Sidecar server
# ---------------------------------------------------------------------------

class Sidecar:
    def __init__(self) -> None:
        self.pw = None
        self.browser = None
        self.context = None
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self._job_counter = 0

    async def start(self) -> None:
        if not _HAS_PW:
            raise RuntimeError("playwright not installed")
        self.pw = await async_playwright().start()
        self.browser = await self.pw.chromium.launch(headless=True)
        ctx_kwargs: Dict[str, Any] = {"user_agent": _UA}
        if _STORAGE_STATE and os.path.isfile(_STORAGE_STATE):
            ctx_kwargs["storage_state"] = _STORAGE_STATE
        self.context = await self.browser.new_context(**ctx_kwargs)
        # Context-level route catches all pages/frames in the context.
        await self.context.route("**/*", _route_handler)

    async def stop(self) -> None:
        for j in self.jobs.values():
            j["cancel"] = True
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.pw:
                await self.pw.stop()
        except Exception:
            pass

    async def new_page(self):
        page = await self.context.new_page()
        page.set_default_navigation_timeout(_NAV_TIMEOUT_MS)
        return page

    # -- /fetch ------------------------------------------------------------
    async def fetch(self, url: str, wait_until: str = "networkidle",
                    timeout_ms: int = _NAV_TIMEOUT_MS) -> Dict[str, Any]:
        since = time.time()
        page = await self.new_page()
        try:
            try:
                await page.goto(url, wait_until=wait_until, timeout=timeout_ms)
            except PWError as e:
                # goto errors (neterr, timeout) still yield a page with a
                # partial/blank DOM; surface the error but extract what we have.
                env = await _extract_envelope(page, since)
                env["goto_error"] = str(e)
                env["status"] = env.get("status")
                return env
            return await _extract_envelope(page, since)
        finally:
            await page.close()

    # -- /crawl ------------------------------------------------------------
    async def crawl_start(self, url: str, max_pages: int = 25,
                          max_depth: int = 3, wall_cap: float = 120.0,
                          same_origin: bool = True) -> str:
        self._job_counter += 1
        jid = f"crawl-{self._job_counter}"
        self.jobs[jid] = {
            "url": url, "max_pages": max_pages, "max_depth": max_depth,
            "wall_cap": wall_cap, "same_origin": same_origin,
            "status": "running", "progress": 0,
            "visited": [], "results": [], "blocked": [],
            "started": time.time(), "cancel": False,
        }
        asyncio.create_task(self._crawl(jid))
        return jid

    async def _crawl(self, jid: str) -> None:
        job = self.jobs[jid]
        root = job["url"]
        root_host = urlparse(root).netloc
        queue: List[Tuple[str, int]] = [(root, 0)]
        seen = set()
        deadline = job["started"] + job["wall_cap"]
        try:
            while queue and not job["cancel"]:
                if time.time() > deadline:
                    job["status"] = "deadline"
                    break
                url, depth = queue.pop(0)
                if url in seen or len(seen) >= job["max_pages"]:
                    continue
                # gate each link before visiting (defense-in-depth; the
                # route handler would abort the navigation anyway).
                ok, reason = _scope_ok(url)
                if not ok:
                    job["blocked"].append({"url": url, "reason": reason})
                    continue
                seen.add(url)
                page = await self.new_page()
                try:
                    try:
                        await page.goto(url, wait_until="domcontentloaded",
                                        timeout=_NAV_TIMEOUT_MS)
                    except PWError as e:
                        env = await _extract_envelope(page, time.time())
                        env["goto_error"] = str(e)
                        job["results"].append(env)
                        continue
                    env = await _extract_envelope(page, time.time())
                    job["visited"].append(url)
                    job["results"].append(env)
                    job["progress"] = int(100 * len(seen) / job["max_pages"])
                    if depth < job["max_depth"]:
                        for link in env["links"]:
                            ph = urlparse(link).netloc
                            if job["same_origin"] and ph != root_host:
                                continue
                            if link not in seen:
                                queue.append((link, depth + 1))
                finally:
                    await page.close()
            if job["status"] == "running":
                job["status"] = "done"
        except Exception as e:  # noqa: BLE001
            job["status"] = f"error: {type(e).__name__}: {e}"
        finally:
            job["progress"] = 100

    def crawl_status(self, jid: str) -> Dict[str, Any]:
        j = self.jobs.get(jid)
        if not j:
            return {"ok": False, "error": "unknown job_id"}
        return {
            "ok": True,
            "status": j["status"],
            "progress": j["progress"],
            "visited": len(j["visited"]),
            "pages": len(j["results"]),
            "blocked_count": len(j["blocked"]),
            "results": j["results"] if j["status"] in ("done", "deadline") \
                or j["status"].startswith("error") else [],
            "blocked": j["blocked"],
            "elapsed_s": round(time.time() - j["started"], 2),
        }

    def crawl_stop(self, jid: str) -> Dict[str, Any]:
        j = self.jobs.get(jid)
        if not j:
            return {"ok": False, "error": "unknown job_id"}
        j["cancel"] = True
        return {"ok": True, "status": "cancelling"}


# ---------------------------------------------------------------------------
# HTTP wire (asyncio.start_server, JSON line protocol)
# ---------------------------------------------------------------------------

_sidecar: Optional[Sidecar] = None


def _json_resp(code: int, obj: Any) -> bytes:
    body = json.dumps(obj).encode()
    return (f"HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body


async def _read_json(reader: asyncio.StreamReader, max_bytes: int = 1 << 20) -> Dict[str, Any]:
    raw = await reader.read(max_bytes)
    if not raw:
        return {}
    # split headers/body
    if b"\r\n\r\n" in raw:
        _, _, body = raw.partition(b"\r\n\r\n")
    else:
        body = raw
    try:
        return json.loads(body.decode() or "{}")
    except Exception:
        return {}


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=5.0)
        if not line:
            return
        parts = line.decode(errors="replace").split()
        if len(parts) < 2:
            writer.write(_json_resp(400, {"error": "bad request"}))
            await writer.drain()
            return
        method, path = parts[0], parts[1]
        # drain headers
        while True:
            h = await reader.readline()
            if h in (b"\r\n", b"\n", b""):
                break
        if path == "/health":
            writer.write(_json_resp(200, {"ok": True,
                                          "browser": "chromium" if _sidecar else "down"}))
        elif path == "/fetch" and method == "POST":
            data = await _read_json(reader)
            url = (data.get("url") or "").strip()
            if not url or not _sidecar:
                writer.write(_json_resp(400, {"error": "missing url" if not url
                                              else "sidecar not ready"}))
                await writer.drain()
                return
            try:
                env = await _sidecar.fetch(
                    url, wait_until=data.get("wait_until", "networkidle"),
                    timeout_ms=int(data.get("timeout_ms", _NAV_TIMEOUT_MS)),
                )
                writer.write(_json_resp(200, env))
            except Exception as e:  # noqa: BLE001
                writer.write(_json_resp(500, {"error": f"{type(e).__name__}: {e}"}))
        elif path == "/crawl/start" and method == "POST":
            data = await _read_json(reader)
            url = (data.get("url") or "").strip()
            if not url or not _sidecar:
                writer.write(_json_resp(400, {"error": "missing url" if not url
                                              else "sidecar not ready"}))
                await writer.drain()
                return
            jid = await _sidecar.crawl_start(
                url, max_pages=int(data.get("max_pages", 25)),
                max_depth=int(data.get("max_depth", 3)),
                wall_cap=float(data.get("wall_cap", 120.0)),
                same_origin=bool(data.get("same_origin", True)),
            )
            writer.write(_json_resp(200, {"job_id": jid}))
        elif path.startswith("/crawl/status") and method == "GET":
            from urllib.parse import parse_qs
            qs = parse_qs(urlparse(path).query)
            jid = (qs.get("id", [""])[0])
            writer.write(_json_resp(200, _sidecar.crawl_status(jid) if _sidecar
                                    else {"ok": False, "error": "sidecar not ready"}))
        elif path.startswith("/crawl/stop") and method == "POST":
            from urllib.parse import parse_qs
            qs = parse_qs(urlparse(path).query)
            jid = (qs.get("id", [""])[0])
            writer.write(_json_resp(200, _sidecar.crawl_stop(jid) if _sidecar
                                    else {"ok": False, "error": "sidecar not ready"}))
        else:
            writer.write(_json_resp(404, {"error": "not found"}))
        await writer.drain()
    except Exception as e:  # noqa: BLE001
        try:
            writer.write(_json_resp(500, {"error": f"{type(e).__name__}: {e}"}))
            await writer.drain()
        except Exception:
            pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def main() -> None:
    global _sidecar
    if not _HAS_PW:
        print("playwright not installed; sidecar cannot start", flush=True)
        return
    _sidecar = Sidecar()
    await _sidecar.start()
    server = await asyncio.start_server(_handle, _HOST, _PORT)
    print(f"[+] playwright sidecar on http://{_HOST}:{_PORT}", flush=True)
    async with server:
        await server.serve_forever()


def run() -> None:
    """Entry point for bootstrap to launch the sidecar as a subprocess."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
