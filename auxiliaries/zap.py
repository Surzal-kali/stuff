"""OWASP ZAP HTTP API client + framework tools.

Talks to a headless ZAP daemon (``zap.sh -daemon``) over its plain-HTTP API
(loopback only). The daemon is launched by ``bootstrap.start_zap_daemon`` and
exposes the API at ``http://127.0.0.1:<ZAP_PORT>`` with the configured
``ZAP_API_KEY`` sent as the ``apikey`` query parameter on every call.

Why HTTP-API rather than the ZAP MCP add-on
-------------------------------------------
The MCP add-on (port 8282) is fine but adds a second protocol layer the model
would have to reason about. The HTTP API has been stable since 2.x and gives
us exactly the primitives we want: spider, AJAX spider, active scan, alerts,
alerts by id, raw HTTP messages by URL, sites tree, and report generation.
We get "ZAP-as-grep" via ``zap_history_regex`` which calls ``core/view/getMessage``
to pull the raw response and runs a local ``re.search`` on it -- the model
can then ask things like "show me every form on the page that lacks a CSRF
token" without standing up a second LLM loop.

The client is a stateful singleton (``ZAPClient.get_instance()``) following
the same pattern as ``MetasploitClient`` -- this lets the Brain's instance
cache and the in-process fallback share one ``requests.Session`` and one
configured base URL / API key.

All public methods are wrapped as ``@framework_tool``-decorated module-level
functions so the static AST discovery pass + Brain scan both pick them up.
Sync only: every call hits a local daemon and never blocks longer than a
couple of seconds, but they're invoked in worker threads by both dispatchers
anyway, so we don't pay the async tax.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

import requests

from constants import framework_tool


ZAP_HOST = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.getenv("ZAP_PORT", "8090"))
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
ZAP_BASE = f"http://{ZAP_HOST}:{ZAP_PORT}"


def _canonical(url: str) -> str:
    """Normalise a URL for comparison: strip trailing slashes, lowercase
    host. Used to verify ``core/view/messages?url=...`` returned the URL
    we actually asked for (it does fuzzy substring matching otherwise)."""
    from urllib.parse import urlsplit
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    path = parts.path.rstrip("/") or "/"
    return f"{host}{path}"


def _canonical_from_envelope(envelope: Dict[str, Any]) -> str:
    """Recover the URL an envelope corresponds to from its requestHeader."""
    req = envelope.get("requestHeader", "")
    # requestHeader starts with "GET <url> HTTP/1.1" -- take the second token.
    parts = req.split()
    if len(parts) >= 2:
        return _canonical(parts[1])
    return ""


def _status_from_headers(response_header: str) -> str:
    """Pull the status line from a raw HTTP response header block.

    The header block starts with ``HTTP/1.1 200 OK\\r\\n`` -- return the
    second token (``200``) so the model can show status at a glance. Empty
    string on malformed input rather than raising -- callers display it.
    """
    if not response_header:
        return ""
    first_line = response_header.splitlines()[0] if response_header else ""
    parts = first_line.split()
    return parts[1] if len(parts) >= 2 else ""


class ZAPClient:
    """Single shared client; configured once from env at first instantiation.

    Tools reach the daemon via ``ZAPClient.get_instance()`` so the API key,
    base URL, and ``requests.Session`` (which keeps a TCP keep-alive) are
    reused across the whole process.
    """

    _instance: Optional["ZAPClient"] = None

    @classmethod
    def get_instance(cls) -> "ZAPClient":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self.base = ZAP_BASE
        self.api_key = ZAP_API_KEY
        self.session = requests.Session()
        # Tiny retry budget for the daemon's first few seconds after launch --
        # the API can return 503 briefly while ZAP is initialising its DB.
        retry = requests.adapters.Retry(
            total=5, backoff_factor=0.5,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET"]),
        )
        self.session.mount("http://", requests.adapters.HTTPAdapter(max_retries=retry))

    # ---- raw transport ---------------------------------------------------

    def _get(self, view: str, expect_json: bool = True, **q: Any) -> Any:
        params = dict(q)
        if self.api_key:
            params["apikey"] = self.api_key
        # ZAP 2.17 requires the /JSON/ URL prefix for JSON responses. Without
        # it the request returns 400 Bad Format (the daemon's old path-based
        # format detection is broken: it tries to parse the first path
        # segment -- e.g. "core" -- as the format enum and dies).
        url = f"{self.base}/JSON/{view}"
        r = self.session.get(url, params=params, timeout=120)
        r.raise_for_status()
        if expect_json:
            return r.json()
        return r.text

    def healthcheck(self) -> bool:
        """Return True if the daemon responds with any HTTP status (it always
        answers 200 on the root even before the API is fully wired). Used by
        ``bootstrap.wait_for_zap`` during launch."""
        try:
            self.session.get(self.base, timeout=2)
            return True
        except requests.RequestException:
            return False

    # ---- primitives ------------------------------------------------------

    def open_url(self, url: str) -> Dict[str, Any]:
        """Load a URL into the session; passive scanner observes it."""
        return self._get("core/action/accessUrl", url=url)

    def spider(self, url: str, max_depth: int = 5, recurse: bool = True) -> str:
        """Start the traditional crawler; returns the scan id (e.g. ``"0"``)."""
        return self._get(
            "spider/action/scan", url=url,
            maxDepth=max_depth, recurse=str(recurse).lower(),
        ).get("scan", "")

    def spider_status(self, scan_id: str) -> int:
        """0..100 progress; 100 means done."""
        return int(self._get("spider/view/status", scanId=scan_id).get("status", 0))

    def ajax_spider(self, url: str) -> str:
        """Start the headless-browser AJAX spider; returns the scan id."""
        return self._get("ajaxSpider/action/scan", url=url).get("scan", "")

    def ajax_spider_status(self) -> str:
        """Running / stopped / finished."""
        return self._get("ajaxSpider/view/status").get("status", "unknown")

    def active_scan(self, url: str, policy: Optional[str] = None) -> str:
        """Run an active scan against a URL (optionally with a named policy)."""
        q: Dict[str, Any] = {"url": url, "recurse": "true"}
        if policy:
            q["scanPolicyName"] = policy
        return self._get("ascan/action/scan", **q).get("scan", "")

    def active_scan_status(self, scan_id: str) -> int:
        """0..100 progress."""
        return int(self._get("ascan/view/status", scanId=scan_id).get("status", 0))

    def alerts(
        self,
        base_url: Optional[str] = None,
        risk_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List all alerts raised (optionally filtered by URL prefix and risk
        level: 0 informational, 1 low, 2 medium, 3 high, 4 informational)."""
        q: Dict[str, Any] = {}
        if base_url:
            q["baseurl"] = base_url
        if risk_id is not None:
            q["riskId"] = risk_id
        return self._get("alert/view/alerts", **q).get("alerts", [])

    def alert_message(self, alert_id: str) -> Dict[str, Any]:
        """Return the alert metadata AND the full HTTP message that triggered it.

        ZAP 2.17 dropped ``alert/view/message`` (returns ``BAD_VIEW``). The
        supported path is two hops: ``alert/view/alert?id=...`` gives us the
        alert metadata including ``messageId``, then ``core/view/message?id=...``
        returns the actual HTTP wire bytes for that message. We return both
        so the model can see what rule fired AND what request it fired on.
        """
        alert_envelope = self._get("alert/view/alert", id=alert_id)
        alert = alert_envelope.get("alert", {})
        message_id = alert.get("messageId")
        if not message_id:
            return {"alert": alert, "message": None,
                    "error": "alert has no messageId (no associated request)"}
        msg_envelope = self._get("core/view/message", id=message_id)
        msg = msg_envelope.get("message", {})
        return {
            "alert": alert,
            "message": {
                "request": msg.get("requestHeader", ""),
                "response_headers": msg.get("responseHeader", ""),
                "response_body": msg.get("responseBody", ""),
                "response_status": _status_from_headers(msg.get("responseHeader", "")),
            },
        }

    def history_regex(
        self, url: str, pattern: str, body_only: bool = True,
    ) -> Dict[str, Any]:
        """Fetch the raw HTTP message for ``url`` and run ``re.search`` over
        it. This is the "ZAP-as-grep" entry point: the model can ask for any
        substring/regex across a previously-spidered response -- e.g. all
        ``<input type="hidden"`` fields, every form action, every JS endpoint.

        Implementation note: ZAP 2.17 renamed ``core/view/getMessage`` (now
        ``BAD_VIEW``); the supported endpoint is ``core/view/messages?url=...``
        which returns a list of full message envelopes. We take the first
        match -- sufficient for any URL the spider actually fetched.
        """
        msgs = self._get("core/view/messages", url=url).get("messages", [])

        # ZAP's ``messages?url=...`` is fuzzy: it returns any envelope whose
        # URL *contains* the requested string, and if no match exists it
        # returns the entire history. We must verify the envelope we got
        # actually corresponds to ``url`` before grepping it, or we'd silently
        # grep a different page and the model would never know.
        target = _canonical(url)
        exact = [m for m in msgs if target in _canonical_from_envelope(m)]
        if not exact:
            return {
                "url": url,
                "pattern": pattern,
                "error": (
                    f"no history entry for {url!r} (have you spidered it "
                    f"yet? messages endpoint returned {len(msgs)} unrelated "
                    "envelopes)"
                ),
                "match_count": 0,
                "matches": [],
            }
        envelope = exact[0]
        if body_only:
            body = envelope.get("responseBody", "")
        else:
            # Stitch the raw HTTP wire bytes: response headers + blank line + body.
            body = (
                envelope.get("responseHeader", "")
                + "\r\n\r\n"
                + envelope.get("responseBody", "")
            )
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return {"error": f"invalid regex: {e}", "matches": []}
        matches = rx.findall(body)
        return {
            "url": url,
            "pattern": pattern,
            "body_bytes": len(body),
            "match_count": len(matches),
            "matches": matches[:200],  # cap so the model doesn't drown in output
            "truncated": len(matches) > 200,
        }

    def sites(self) -> List[str]:
        """Top-level hosts discovered by the session."""
        return self._get("core/view/sites").get("sites", [])

    def sites_tree(self, url: Optional[str] = None) -> str:
        """Full tree as JSON string. Pass ``url`` to scope to a subtree."""
        if url:
            return self._get("core/view/sitesTree", url=url, expect_json=False)
        return self._get("core/view/sitesTree", expect_json=False)

    def report(
        self,
        report_format: str = "html",
        report_file: str = "/tmp/zap_report.html",
        report_title: str = "Framework ZAP scan",
    ) -> Dict[str, Any]:
        """Generate a local report (html / xml / json / md). Returns the path.

        The ZAP ``reports`` add-on is NOT bundled into the daemon JAR --
        a vanilla ``zap.sh -daemon`` invocation returns ``no_implementor``
        (HTTP 400) for any /report/ endpoint. We detect that case and
        return a structured error instead of letting the exception bubble,
        so the model can suggest installing the add-on from the marketplace.
        """
        try:
            self._get(
                "report/action/generate",
                reportFormat=report_format,
                reportFileName=report_file,
                reportTitle=report_title,
            )
        except requests.exceptions.HTTPError as e:
            # 400 + body containing "no_implementor" -> add-on missing.
            if (e.response is not None
                    and "no_implementor" in (e.response.text or "")):
                return {
                    "path": None,
                    "error": (
                        "ZAP reports add-on is not installed. The vanilla "
                        "zap.sh -daemon image does not bundle it. Run "
                        "`zap.sh -daemon -addoninstall reports` once to "
                        "install, or fetch the reports add-on from the "
                        "ZAP marketplace, then restart the daemon."
                    ),
                }
            raise
        return {"path": report_file}


def _zap() -> ZAPClient:
    return ZAPClient.get_instance()


# --- @framework_tool wrappers ----------------------------------------------
#
# Doc strings here are what the registry embeds for semantic matching. Keep
# them concrete ("...returns a scan_id you poll with zap_spider_status")
# rather than vague ("runs a scan") -- the secretary picks tools by meaning.


@framework_tool("Open a URL in the ZAP session (passive scan starts observing).")
def zap_open_url(target: str) -> Dict[str, Any]:
    """Open a single URL so ZAP observes it. Use this before spidering or
    scanning to seed the session with a known-good entry point.

    Args:
        target: Fully qualified URL including scheme, e.g. ``http://192.168.90.110/``.
            Must be reachable from this host; ZAP fetches it directly.
    """
    return _zap().open_url(target)


@framework_tool("Start the traditional ZAP spider against a URL; returns spider_id.")
def zap_spider(target: str, max_depth: int = 5, recurse: bool = True) -> Dict[str, str]:
    """Crawl from ``target`` up to ``max_depth`` hops. Returns the spider id;
    poll with ``zap_spider_status`` until it reaches 100.

    Args:
        target: Fully qualified URL to start crawling from.
        max_depth: Maximum link depth from ``target`` (default 5).
        recurse: Follow links recursively (default True). Set False for a
            single-page fetch.
    """
    return {"spider_id": _zap().spider(target, max_depth=max_depth, recurse=recurse)}


@framework_tool("Get spider progress (0..100) for a given spider_id.")
def zap_spider_status(scan_id: str) -> Dict[str, Any]:
    """Args:
        scan_id: The spider id returned by ``zap_spider``.
    """
    return {"spider_id": scan_id, "status": _zap().spider_status(scan_id)}


@framework_tool("Start the AJAX (headless-browser) spider against a URL.")
def zap_ajax_spider(target: str) -> Dict[str, str]:
    """Args:
        target: Fully qualified URL to start the headless-browser crawl from.
    """
    return {"ajax_spider_id": _zap().ajax_spider(target)}


@framework_tool("Get AJAX spider status string (running / stopped / finished).")
def zap_ajax_spider_status() -> Dict[str, str]:
    return {"status": _zap().ajax_spider_status()}


@framework_tool("Start an active scan against a URL; returns ascan_id.")
def zap_active_scan(target: str, policy: Optional[str] = None) -> Dict[str, str]:
    """Active scan attacks every URL the spider discovered. ``policy`` is
    optional and names a ZAP scan policy (e.g. ``"Default Policy"``).

    Args:
        target: Fully qualified URL; ZAP will attack this URL and anything
            linked from it that's in scope.
        policy: Optional scan policy name. ``None`` uses the default policy.
    """
    return {"ascan_id": _zap().active_scan(target, policy=policy)}


@framework_tool("Get active-scan progress (0..100) for a given ascan_id.")
def zap_active_scan_status(scan_id: str) -> Dict[str, Any]:
    """Args:
        scan_id: The ascan id returned by ``zap_active_scan``.
    """
    return {"ascan_id": scan_id, "status": _zap().active_scan_status(scan_id)}


@framework_tool(
    "List ZAP alerts (optionally filtered by URL prefix and risk level).",
    next_hints=["zap_alert_message", "report_finding"],
)
def zap_alerts(base_url: Optional[str] = None,
               risk_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """List all ZAP alerts raised during the session, with optional filtering.

    Risk levels: 0 informational, 1 low, 2 medium, 3 high, 4 informational
    (ZAP uses 0 and 4 for different informational buckets).

    Args:
        base_url: Optional URL prefix to filter by (e.g. ``http://192.168.90.110``).
        risk_id: Optional minimum risk level (0-4). Returns ALL alerts when None.
    """
    return _zap().alerts(base_url=base_url, risk_id=risk_id)


@framework_tool(
    "Get an alert's metadata plus the full HTTP request/response that triggered it.",
    next_hints=["report_finding"],
)
def zap_alert_message(alert_id: str) -> Dict[str, Any]:
    """Returns the alert rule that fired (name, risk, CWE, evidence) AND the
    raw HTTP request + response that triggered it. Use to triage a finding:
    confirm it's a real positive and not a fingerprinting false positive.

    Args:
        alert_id: The ``id`` field of an alert (an integer string from ``zap_alerts``).
    """
    return _zap().alert_message(alert_id)


@framework_tool(
    "Grep the raw HTTP response for a previously-spidered URL using a regex. "
    "This is the ZAP-as-grep tool: pass any regex, get all matches back."
)
def zap_history_regex(target: str, pattern: str,
                      body_only: bool = True) -> Dict[str, Any]:
    """Use cases: enumerate hidden form fields, find all JS endpoints, locate
    comments containing TODOs, etc. Body-only skips the HTTP headers.

    Args:
        target: URL that ZAP has already fetched (must be in history).
        pattern: Python regex to run against the response.
        body_only: If True (default), grep only the response body. If False,
            grep the raw response including headers (useful for header checks).
    """
    return _zap().history_regex(target, pattern, body_only=body_only)


@framework_tool("List top-level hosts discovered by the ZAP session.")
def zap_sites() -> List[str]:
    return _zap().sites()


@framework_tool("Get the full ZAP sites tree (optionally scoped to a subtree URL).")
@framework_tool("Get the full ZAP sites tree (optionally scoped to a subtree URL).")
def zap_sites_tree(target: Optional[str] = None) -> str:
    """JSON dump of the entire discovered URL hierarchy.

    Args:
        target: Optional URL to scope the tree to a subtree under that URL.
            None (default) returns the entire hierarchy.
    """
    return _zap().sites_tree(url=target)


@framework_tool("Generate a ZAP report file (html/xml/json/md) and return its path.")
def zap_report(report_format: str = "html",
               report_file: str = "/tmp/zap_report.html",
               report_title: str = "Framework ZAP scan") -> Dict[str, Any]:
    """Requires the ZAP ``reports`` add-on; a vanilla daemon may not have
    it. On failure, returns a dict with an ``error`` field describing
    what's missing instead of raising.

    Args:
        report_format: One of "html", "xml", "json", "md".
        report_file: Absolute path on the local filesystem to write the report.
        report_title: Title embedded in the report header.
    """
    return _zap().report(
        report_format=report_format,
        report_file=report_file,
        report_title=report_title,
    )
