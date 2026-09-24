"""BloodHound CE API client + framework tools.

Talks to the BloodHound Community Edition REST API (v2) over HTTP. The
BloodHound CE container is a workbench service (docker-compose.yaml), not a
sidecar launched by bootstrap — it's always running when the operator starts
the workbench stack.  The client is a stateful singleton
(``BloodHoundClient.get_instance()``) following the same pattern as
``MetasploitClient`` and ``ZAPClient``: one ``requests.Session``, one JWT
token, shared across the Brain's instance cache and the in-process fallback.

Scope-gate: NONE by design.  BloodHound queries its own graph database — it
never sends traffic to a target, contacts no target host, and makes no DNS
lookups against in-scope assets.  This is offline analysis of data that was
already collected (by bloodhound-python / SharpHound against a lab domain the
operator owns).  Same class as radare2/jadx (offline artifact analysis).
Documented here so a future "hardening" pass does not silently gate an
analysis lane.

Auth
----
BloodHound CE uses JWT bearer tokens.  The client logs in with the admin
principal name + password, holds the token, and refreshes it on 401.  The
initial password is randomized at first boot and printed in the container
logs (``# Initial Password Set To:    <password>    #``); after the operator
changes it, set ``BLOODHOUND_ADMIN_PASSWORD`` in ``.env``.

Environment variables:
  - ``BLOODHOUND_URL`` — base URL (default ``http://bloodhound:8080`` on the
    workbench network; ``http://localhost:18080`` from the host).
  - ``BLOODHOUND_ADMIN_PRINCIPAL`` — admin principal name (default ``admin``).
  - ``BLOODHOUND_ADMIN_PASSWORD`` — admin password (REQUIRED; no default —
    the initial randomized password is not guessable).
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from constants import framework_tool

logger = logging.getLogger(__name__)

# --- .env loading (sudo-safe) — same pattern as program_scope.py -----------
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)
except Exception:
    pass

_BH_URL = os.getenv("BLOODHOUND_URL", "http://bloodhound:8080").rstrip("/")
_BH_PRINCIPAL = os.getenv("BLOODHOUND_ADMIN_PRINCIPAL", "admin")
_BH_PASSWORD = os.getenv("BLOODHOUND_ADMIN_PASSWORD", "")
_TIMEOUT = (10.0, 120.0)

# Loopback fallback for the host lane.  The container DNS name (``bloodhound``)
# only resolves on the workbench network (inside open-terminal); on the host
# lane BloodHound CE is reachable at the published host port instead.  The
# client flips to this fallback on the first connection failure and stays
# there (see BloodHoundClient._try_fallback), so one .env serves both lanes.
_BH_FALLBACK_URL = (
    f"http://127.0.0.1:{os.getenv('BLOODHOUND_PORT', '18080')}".rstrip("/")
)

# Output caps so large graph results don't blow up the model's context.
_RESULT_NODE_CAP = 200
_RESULT_EDGE_CAP = 200
_OUTPUT_CAP = int(os.getenv("BH_OUTPUT_CAP", str(200 * 1024)))


def _clip(text: str) -> str:
    if len(text) > _OUTPUT_CAP:
        return text[:_OUTPUT_CAP] + f"\n... [truncated {len(text) - _OUTPUT_CAP} chars] ..."
    return text


class BloodHoundAPIError(Exception):
    """Raised when the BloodHound API returns an error response."""

    def __init__(self, status_code: int, message: str = "") -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"BloodHound {status_code}: {message}")


class BloodHoundClient:
    """Stateful singleton client: one session, one JWT token, auto-refresh.

    Both the Brain's ``FunctionRegistry._instances`` and the in-process
    launcher's ``_tool_instances`` cache prefer ``get_instance()`` so all
    callers share the same authenticated session.
    """

    _instance: Optional["BloodHoundClient"] = None

    @classmethod
    def get_instance(cls) -> "BloodHoundClient":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self.base = _BH_URL
        self.principal = _BH_PRINCIPAL
        self.password = _BH_PASSWORD
        self.session = requests.Session()
        self._token: Optional[str] = None
        self._token_ts: float = 0.0

    def _try_fallback(self) -> bool:
        """On connection failure, flip to the host-lane loopback URL.

        Returns True if a fallback exists and we switched to it.  Sticky: once
        flipped, every later request uses the fallback.  No-op when the
        fallback IS the current base (container lane, where the fallback URL
        is unreachable and retrying it would just burn the timeout).
        """
        if _BH_FALLBACK_URL and self.base != _BH_FALLBACK_URL:
            self.base = _BH_FALLBACK_URL
            return True
        return False

    def _login(self) -> None:
        """Authenticate and store the JWT token.

        Payload shape: BloodHound CE builds since ~2026-09 require an explicit
        ``login_method`` ("secret" = password auth) and take the principal as
        ``username``.  Older builds used ``principal_name`` with no method
        field and return 404 "resource not found" when ``login_method`` is
        unknown (they only support the legacy shape).  We try the modern shape
        first and fall back to the legacy shape on a 404 so both image
        generations work.
        """
        if not self.password:
            raise BloodHoundAPIError(
                0,
                "BLOODHOUND_ADMIN_PASSWORD not set — find the initial password "
                "in `docker logs bloodhound-server | grep 'Initial Password'`, "
                "or set it after your first login change.",
            )
        try:
            r = self.session.post(
                f"{self.base}/api/v2/login",
                json={
                    "login_method": "secret",
                    "username": self.principal,
                    "secret": self.password,
                },
                timeout=_TIMEOUT,
            )
        except requests.ConnectionError as e:
            if not self._try_fallback():
                raise BloodHoundAPIError(
                    0,
                    f"BloodHound unreachable at {self.base} — is the "
                    f"container running? ({e})",
                ) from e
            # Fallback lane: retry the modern-shape login on the new base.
            r = self.session.post(
                f"{self.base}/api/v2/login",
                json={
                    "login_method": "secret",
                    "username": self.principal,
                    "secret": self.password,
                },
                timeout=_TIMEOUT,
            )
        if r.status_code == 404:
            # Legacy image (pre-login_method): principal_name-only shape.
            r = self.session.post(
                f"{self.base}/api/v2/login",
                json={
                    "principal_name": self.principal,
                    "password": self.password,
                },
                timeout=_TIMEOUT,
            )
        if not r.ok:
            raise BloodHoundAPIError(r.status_code, f"login failed: {r.text[:500]}")
        data = r.json()
        # Modern builds wrap the token: {"data": {"session_token": ...}}.
        # Legacy builds returned a flat {"token": ...} / {"access_token": ...}.
        self._token = (
            (data.get("data") or {}).get("session_token")
            or data.get("token")
            or data.get("access_token")
        )
        if not self._token:
            raise BloodHoundAPIError(0, "login response missing token field")
        self._token_ts = time.time()

    def _auth_headers(self) -> Dict[str, str]:
        if self._token is None or (time.time() - self._token_ts > 3600):
            self._login()
        return {"Authorization": f"Bearer {self._token}"}

    def _request(
        self, method: str, path: str, *, params: Optional[dict] = None,
        json_body: Optional[dict] = None, retry_auth: bool = True,
    ) -> Any:
        """Make an authenticated API request with one 401 retry.

        ORDERING TRAP (fixed 2026-09-24): resolve the auth headers BEFORE
        building the URL. ``_auth_headers()`` may call ``_login()``, which can
        flip ``self.base`` to the fallback lane when the primary is down. If
        the URL is built first (the old order), it stays pinned to the dead
        primary even though auth just succeeded on the fallback — the request
        then fires at the unresolvable host and produces the self-contradicting
        error "unreachable at http://127.0.0.1:18080 (…Failed to resolve
        'bloodhound'…)" (both halves true, opposite lanes). Auth stays inside
        the try so a both-lanes-dead ConnectionError from ``_login()`` still
        converts to the BloodHoundAPIError envelope the tools catch.
        """
        try:
            headers = self._auth_headers()
            url = f"{self.base}{path}"
            r = self.session.request(
                method, url, params=params, json=json_body,
                headers=headers, timeout=_TIMEOUT,
            )
        except requests.ConnectionError as e:
            if self._try_fallback():
                return self._request(method, path, params=params,
                                     json_body=json_body, retry_auth=retry_auth)
            raise BloodHoundAPIError(
                0,
                f"BloodHound unreachable at {self.base} — is the container "
                f"running? ({e})",
            ) from e
        if r.status_code == 401 and retry_auth:
            self._token = None
            return self._request(method, path, params=params, json_body=json_body,
                                 retry_auth=False)
        if not r.ok:
            msg = r.text[:1000]
            try:
                err = r.json()
                if isinstance(err, dict):
                    msg = err.get("message") or err.get("error") or msg
            except (ValueError, json.JSONDecodeError):
                pass
            raise BloodHoundAPIError(r.status_code, msg)
        if r.status_code == 204 or not r.content:
            return {}
        try:
            return r.json()
        except (ValueError, json.JSONDecodeError):
            return r.text

    # ---- primitives ------------------------------------------------------

    def health(self) -> bool:
        """Quick reachability check (no auth needed for /api/version)."""
        try:
            self.session.get(f"{self.base}/api/version", timeout=5)
            return True
        except requests.RequestException:
            return False

    def login(self) -> Dict[str, Any]:
        """Force a fresh login (used by bh_login tool for diagnostics)."""
        self._token = None
        self._login()
        return {"status": "ok", "principal": self.principal, "url": self.base}

    # ---- collection upload (file-ingest) ---------------------------------

    def list_file_uploads(self) -> List[Dict[str, Any]]:
        data = self._request("GET", "/api/v2/file-upload")
        if isinstance(data, dict):
            return data.get("data") or data.get("jobs") or []
        return data if isinstance(data, list) else []

    def start_file_upload(self, filename: str) -> str:
        """Create a file-upload job. Returns the job_id."""
        data = self._request("POST", "/api/v2/file-upload/start",
                             json_body={"file_name": filename})
        if isinstance(data, dict):
            return data.get("id") or data.get("job_id") or data.get("data", {}).get("id", "")
        return ""

    def upload_file_chunk(self, job_id: str, file_path: str) -> Dict[str, Any]:
        """Upload a file to an existing upload job.

        Same ordering trap as ``_request``: auth headers are resolved first so
        a fallback flip inside ``_login()`` is reflected in the URL that is
        built below.
        """
        p = Path(file_path)
        if not p.is_file():
            raise BloodHoundAPIError(0, f"file not found: {file_path}")
        try:
            headers = self._auth_headers()
            with open(p, "rb") as fh:
                files = {"file": (p.name, fh, "application/octet-stream")}
                r = self.session.post(
                    f"{self.base}/api/v2/file-upload/{job_id}",
                    files=files,
                    headers=headers,
                    timeout=_TIMEOUT,
                )
        except requests.ConnectionError as e:
            if self._try_fallback():
                return self.upload_file_chunk(job_id, file_path)
            raise BloodHoundAPIError(
                0,
                f"BloodHound unreachable at {self.base} — is the container "
                f"running? ({e})",
            ) from e
        if not r.ok:
            raise BloodHoundAPIError(r.status_code, f"upload chunk failed: {r.text[:500]}")
        try:
            return r.json()
        except (ValueError, json.JSONDecodeError):
            return {"status": "uploaded"}

    def end_file_upload(self, job_id: str) -> Dict[str, Any]:
        """Finalize a file-upload job, triggering ingestion."""
        return self._request("POST", f"/api/v2/file-upload/{job_id}/end")

    def accepted_file_types(self) -> List[str]:
        data = self._request("GET", "/api/v2/file-upload/accepted-types")
        if isinstance(data, dict):
            return data.get("data") or data.get("types") or []
        return data if isinstance(data, list) else []

    # ---- graph queries ---------------------------------------------------

    def run_cypher(self, cypher: str) -> Dict[str, Any]:
        """Run a raw Cypher query and return nodes + edges.

        BloodHound CE's ``POST /api/v2/graphs/cypher`` returns a unified graph
        with nodes and edges arrays.  We cap the result so large queries don't
        overwhelm the model's context window.

        Empty-result quirk (verified 2026-09-24 against the 2026-09
        specterops/bloodhound build): this API returns **404 "resource not
        found"** when a Cypher query matches zero rows — 200 for
        ``MATCH (n) RETURN n LIMIT 1`` on a populated graph, 404 for
        ``MATCH (d:Domain) ...`` on an empty one.  Normalized here to an
        honest empty graph so callers see 0 nodes, not a hard failure.
        """
        try:
            data = self._request("POST", "/api/v2/graphs/cypher",
                                 json_body={"query": cypher})
        except BloodHoundAPIError as e:
            if e.status_code == 404:
                return {
                    "nodes": [], "edges": [],
                    "meta": {"empty_result_404": True},
                }
            raise
        return self._normalize_graph(data)

    def shortest_path(self, start_node: str, end_node: str,
                      max_hops: int = 0) -> Dict[str, Any]:
        """Find the shortest path between two nodes via the pathfinding API."""
        params: Dict[str, Any] = {"start_node": start_node, "end_node": end_node}
        if max_hops > 0:
            params["max_hops"] = max_hops
        data = self._request("GET", "/api/v2/graphs/shortest-path",
                             params=params)
        return self._normalize_graph(data)

    def pathfinding(self, start_node: str, end_node: str) -> Dict[str, Any]:
        """General pathfinding query (same as shortest_path but uses the
        pathfinding endpoint that may support more options)."""
        data = self._request("GET", "/api/v2/pathfinding",
                             params={"start_node": start_node, "end_node": end_node})
        return self._normalize_graph(data)

    def graph_search(self, query: str) -> Dict[str, Any]:
        """Search for graph nodes by name/property."""
        data = self._request("GET", "/api/v2/graph-search",
                             params={"query": query})
        return self._normalize_graph(data)

    def get_node_kinds(self) -> List[str]:
        """List all node kinds in the graph (User, Computer, Group, Domain...)."""
        data = self._request("GET", "/api/v2/graphs/kinds")
        if isinstance(data, dict):
            kinds = data.get("data") or data.get("kinds") or []
            if isinstance(kinds, list):
                return [k.get("name", str(k)) if isinstance(k, dict) else str(k)
                        for k in kinds]
        return data if isinstance(data, list) else []

    # ---- AD entity lookups ------------------------------------------------

    def get_available_domains(self) -> List[Dict[str, Any]]:
        data = self._request("GET", "/api/v2/available-domains")
        if isinstance(data, dict):
            return data.get("data") or []
        return data if isinstance(data, list) else []

    def get_domain(self, object_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/api/v2/domains/{object_id}")

    def get_user(self, object_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/api/v2/users/{object_id}")

    def get_computer(self, object_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/api/v2/computers/{object_id}")

    def get_group(self, object_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/api/v2/groups/{object_id}")

    def get_entity(self, object_id: str) -> Dict[str, Any]:
        """Get any entity by its object_id (uses the base entity endpoint)."""
        return self._request("GET", f"/api/v2/base/{object_id}")

    def get_entity_controllers(self, object_id: str) -> Dict[str, Any]:
        """Who controls this entity? (attack path source)."""
        return self._normalize_graph(
            self._request("GET", f"/api/v2/base/{object_id}/controllers")
        )

    def get_entity_controllables(self, object_id: str) -> Dict[str, Any]:
        """What does this entity control? (attack path targets)."""
        return self._normalize_graph(
            self._request("GET", f"/api/v2/base/{object_id}/controllables")
        )

    def get_domain_dcsyncers(self, object_id: str) -> Dict[str, Any]:
        """Who can DCSync this domain?"""
        return self._normalize_graph(
            self._request("GET", f"/api/v2/domains/{object_id}/dc-syncers")
        )

    def get_computer_admins(self, object_id: str) -> Dict[str, Any]:
        """Who has admin rights on this computer?"""
        return self._normalize_graph(
            self._request("GET", f"/api/v2/computers/{object_id}/admin-users")
        )

    def get_computer_sessions(self, object_id: str) -> Dict[str, Any]:
        """Who is logged into this computer?"""
        return self._normalize_graph(
            self._request("GET", f"/api/v2/computers/{object_id}/sessions")
        )

    def get_user_sessions(self, object_id: str) -> Dict[str, Any]:
        """Where is this user logged in?"""
        return self._normalize_graph(
            self._request("GET", f"/api/v2/users/{object_id}/sessions")
        )

    def get_user_memberships(self, object_id: str) -> Dict[str, Any]:
        """What groups is this user a member of?"""
        return self._normalize_graph(
            self._request("GET", f"/api/v2/users/{object_id}/memberships")
        )

    def get_group_members(self, object_id: str) -> Dict[str, Any]:
        """Who is in this group?"""
        return self._normalize_graph(
            self._request("GET", f"/api/v2/groups/{object_id}/members")
        )

    # ---- analysis / datapipe ----------------------------------------------

    def get_analysis_status(self) -> Dict[str, Any]:
        return self._request("GET", "/api/v2/analysis")

    def start_analysis(self) -> Dict[str, Any]:
        return self._request("PUT", "/api/v2/analysis")

    def cancel_analysis(self) -> Dict[str, Any]:
        return self._request("DELETE", "/api/v2/analysis")

    def get_datapipe_status(self) -> Dict[str, Any]:
        return self._request("GET", "/api/v2/datapipe/status")

    def get_completeness(self) -> Dict[str, Any]:
        """Database completeness stats (how much data is ingested)."""
        return self._request("GET", "/api/v2/completeness")

    # ---- attack paths -----------------------------------------------------

    def list_attack_path_types(self) -> List[str]:
        data = self._request("GET", "/api/v2/attack-path-types")
        if isinstance(data, dict):
            return data.get("data") or data.get("types") or []
        return data if isinstance(data, list) else []

    def get_attack_paths(self) -> Dict[str, Any]:
        """Get all attack path findings."""
        return self._request("GET", "/api/v2/attack-paths/details")

    # ---- normalize graph responses ----------------------------------------

    @staticmethod
    def _normalize_graph(data: Any) -> Dict[str, Any]:
        """Normalize a BloodHound graph response into {nodes, edges, meta}.

        BloodHound CE returns a unified graph with ``nodes`` and ``edges``
        arrays.  Some endpoints wrap under ``data``; others return the flat
        graph.  Cap the arrays so the model's context isn't overwhelmed.
        """
        if not isinstance(data, dict):
            return {"nodes": [], "edges": [], "meta": {"raw_type": type(data).__name__}}

        graph = data.get("data") if isinstance(data.get("data"), dict) else data
        if not isinstance(graph, dict):
            graph = {}
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        meta: Dict[str, Any] = {}
        for k in ("properties", "count", "total", "next", "previous"):
            if k in data:
                meta[k] = data[k]

        node_truncated = len(nodes) > _RESULT_NODE_CAP
        edge_truncated = len(edges) > _RESULT_EDGE_CAP
        nodes = nodes[:_RESULT_NODE_CAP]
        edges = edges[:_RESULT_EDGE_CAP]

        # Compact nodes to name + kind + object_id (drop heavy properties).
        compact_nodes = []
        for n in nodes:
            if isinstance(n, dict):
                compact_nodes.append({
                    "id": n.get("id") or n.get("object_id") or "",
                    "kind": n.get("kind") or n.get("type") or "",
                    "name": (n.get("properties") or {}).get("name", "")
                            or n.get("name", ""),
                    "object_id": n.get("object_id") or n.get("id") or "",
                })
            else:
                compact_nodes.append({"raw": str(n)[:200]})

        compact_edges = []
        for e in edges:
            if isinstance(e, dict):
                compact_edges.append({
                    "source": e.get("source") or e.get("start") or "",
                    "target": e.get("target") or e.get("end") or "",
                    "kind": e.get("kind") or e.get("type") or "",
                })
            else:
                compact_edges.append({"raw": str(e)[:200]})

        meta["node_count"] = len(nodes)
        meta["edge_count"] = len(edges)
        if node_truncated:
            meta["node_truncated"] = True
        if edge_truncated:
            meta["edge_truncated"] = True

        return {
            "nodes": compact_nodes,
            "edges": compact_edges,
            "meta": meta,
        }


# ---------------------------------------------------------------------------
# Pre-built Cypher query templates (generic AD analysis — no GOAD spoilers).
# The secretary uses bh_query_template to run these without having to compose
# Cypher from scratch.  Each template takes an optional node_name for
# targeting a specific user/computer/group.
# ---------------------------------------------------------------------------

_CYPHER_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "shortest_path_to_da": {
        "doc": (
            "Find the shortest path from a given node to any Domain Admin "
            "group member. Pass node_name to specify the starting user. "
            "Returns the attack path (nodes + edges)."
        ),
        "requires_name": True,
        "query": (
            "MATCH (n:User {{name: $name}}), "
            "(target:User), "
            "p=shortestPath((n)-[*1..15]->(target)) "
            "WHERE target.name CONTAINS 'DOMAIN ADMIN' "
            "RETURN p LIMIT 5"
        ),
    },
    "shortest_path_to_domain_admin_group": {
        "doc": (
            "Find the shortest path from a given node to the Domain Admins "
            "group itself (not just its members). Pass node_name to specify "
            "the starting user or computer."
        ),
        "requires_name": True,
        "query": (
            "MATCH (n {{name: $name}}), "
            "(g:Group), "
            "p=shortestPath((n)-[*1..15]->(g)) "
            "WHERE g.name CONTAINS 'DOMAIN ADMINS' "
            "RETURN p LIMIT 5"
        ),
    },
    "owned_to_tier_zero": {
        "doc": (
            "Find the shortest path from a given owned node to any Tier Zero "
            "entity (Enterprise Admins, Domain Admins, Schema Admins, DC "
            "computer accounts). Pass node_name for the owned node."
        ),
        "requires_name": True,
        "query": (
            "MATCH (n {{name: $name}}), "
            "(target), "
            "p=shortestPath((n)-[*1..15]->(target)) "
            "WHERE target.name =~ '(?i).*DOMAIN ADMINS.*|.*ENTERPRISE ADMINS.*"
            "|.*SCHEMA ADMINS.*|.*DC$' "
            "RETURN p LIMIT 5"
        ),
    },
    "kerberoastable_users": {
        "doc": (
            "List all users with SPNs set (Kerberoastable users). No node_name "
            "needed — returns all matches. These users' TGS tickets can be "
            "requested and cracked offline."
        ),
        "requires_name": False,
        "query": (
            "MATCH (u:User) WHERE u.serviceprincipalnames IS NOT NULL "
            "AND u.serviceprincipalnames <> [] "
            "RETURN u.name, u.serviceprincipalnames, u.enabled "
            "LIMIT 100"
        ),
    },
    "asreproastable_users": {
        "doc": (
            "List all users with DONT_REQ_PREAUTH set (AS-REP roastable). "
            "No node_name needed. These users' AS-REP can be grabbed without "
            "knowing their password."
        ),
        "requires_name": False,
        "query": (
            "MATCH (u:User) WHERE u.dontreqpreauth = true "
            "RETURN u.name, u.enabled LIMIT 100"
        ),
    },
    "dcsync_rights": {
        "doc": (
            "Find all principals with DCSync rights (GetChanges / "
            "GetChangesAll / Replication-Get-Changes-All on the domain). "
            "No node_name needed — returns all principals with these rights."
        ),
        "requires_name": False,
        "query": (
            "MATCH (n)-[:GetChanges|GetChangesAll|Replication-Get-Changes-All"
            "->(d:Domain) "
            "RETURN n.name, n.kind, d.name LIMIT 100"
        ),
    },
    "unconstrained_delegation": {
        "doc": (
            "List all computers with unconstrained delegation enabled. "
            "No node_name needed. Any user logging into these computers "
            "leaves a TGT in memory that can be extracted."
        ),
        "requires_name": False,
        "query": (
            "MATCH (c:Computer) WHERE c.unconstraineddelegation = true "
            "RETURN c.name, c.enabled LIMIT 100"
        ),
    },
    "all_users": {
        "doc": (
            "List all user nodes in the graph (name + enabled status). "
            "No node_name needed. Capped at 100."
        ),
        "requires_name": False,
        "query": "MATCH (u:User) RETURN u.name, u.enabled LIMIT 100",
    },
    "all_computers": {
        "doc": (
            "List all computer nodes in the graph (name + OS + enabled). "
            "No node_name needed. Capped at 100."
        ),
        "requires_name": False,
        "query": (
            "MATCH (c:Computer) RETURN c.name, c.operatingsystem, c.enabled "
            "LIMIT 100"
        ),
    },
    "all_domains": {
        "doc": (
            "List all domain nodes in the graph. No node_name needed."
        ),
        "requires_name": False,
        "query": "MATCH (d:Domain) RETURN d.name LIMIT 50",
    },
    "all_groups": {
        "doc": (
            "List all group nodes. No node_name needed. Capped at 100."
        ),
        "requires_name": False,
        "query": "MATCH (g:Group) RETURN g.name LIMIT 100",
    },
    "group_members": {
        "doc": (
            "List members of a specific group. Pass node_name for the group "
            "name."
        ),
        "requires_name": True,
        "query": (
            "MATCH (g:Group {{name: $name}})<-[:MemberOf*1..]-(n) "
            "RETURN n.name, n.kind LIMIT 200"
        ),
    },
    "admin_rights_on_computer": {
        "doc": (
            "Find who has admin rights on a specific computer. Pass "
            "node_name for the computer name."
        ),
        "requires_name": True,
        "query": (
            "MATCH (n)-[:AdminTo|MemberOf*1..]->(c:Computer {{name: $name}}) "
            "RETURN n.name, n.kind LIMIT 200"
        ),
    },
    "sessions_on_computer": {
        "doc": (
            "Find who is logged into a specific computer. Pass node_name "
            "for the computer name. Useful for credential theft targets."
        ),
        "requires_name": True,
        "query": (
            "MATCH (u:User)-[:HasSession]->(c:Computer {{name: $name}}) "
            "RETURN u.name, u.enabled LIMIT 200"
        ),
    },
    "gpo_controllers": {
        "doc": (
            "Find who controls a specific GPO. Pass node_name for the GPO "
            "name. GPO control can lead to code execution on all computers "
            "the GPO applies to."
        ),
        "requires_name": True,
        "query": (
            "MATCH (n)-[:GPLink|Owns|WriteGPLink|WriteDacl*1..]->"
            "(g:GPO {{name: $name}}) "
            "RETURN n.name, n.kind LIMIT 200"
        ),
    },
}


# ---------------------------------------------------------------------------
# Framework tools
# ---------------------------------------------------------------------------

@framework_tool(
    "BloodHound CE authentication diagnostic: log in to BloodHound and "
    "verify the connection is working. Returns the principal name and base "
    "URL on success, or a clear error (missing password, unreachable "
    "container) on failure. Use this first if other BloodHound tools return "
    "auth or connection errors. No scope gate — BloodHound queries its own "
    "graph database, never contacts a target host.",
    tags=["recon.ad"],
    next_hints=["bh_ingest", "bh_query", "bh_query_template"],
)
def bh_login() -> Dict[str, Any]:
    """Authenticate to BloodHound CE and verify the connection."""
    client = BloodHoundClient.get_instance()
    try:
        return client.login()
    except BloodHoundAPIError as e:
        return {"status": "Failed", "error": str(e)}


@framework_tool(
    "Ingest BloodHound collector JSON data: upload one or more JSON files "
    "(from bloodhound-python or SharpHound) to BloodHound CE for analysis. "
    "Pass a file path or a directory path — directories are scanned "
    "recursively for *.json files. The upload is a three-step process: "
    "create a job, upload the file(s), then finalize the job to trigger "
    "ingestion and analysis. No scope gate — this uploads local collector "
    "output to a local BloodHound container.",
    tags=["recon.ad"],
    next_hints=["bh_query_template", "bh_analysis_status"],
)
def bh_ingest(file_path: str) -> Dict[str, Any]:
    """Upload collector JSON file(s) to BloodHound CE.

    Args:
        file_path: Path to a single JSON file or a directory containing
            collector JSON output. Directories are scanned recursively.
    """
    client = BloodHoundClient.get_instance()

    p = Path(file_path).expanduser().resolve()
    if not p.exists():
        return {"status": "Failed", "error": f"path not found: {file_path}"}

    # Collect JSON files.
    if p.is_dir():
        json_files = sorted(p.rglob("*.json"))
    elif p.is_file() and p.suffix == ".json":
        json_files = [p]
    else:
        return {
            "status": "Failed",
            "error": f"not a JSON file or directory: {file_path}",
        }

    if not json_files:
        return {
            "status": "Failed",
            "error": f"no JSON files found under {file_path}",
        }

    uploaded: List[Dict[str, Any]] = []
    for jf in json_files:
        try:
            job_id = client.start_file_upload(jf.name)
            if not job_id:
                return {
                    "status": "Failed",
                    "error": f"failed to create upload job for {jf.name}",
                    "uploaded": uploaded,
                }
            client.upload_file_chunk(job_id, str(jf))
            client.end_file_upload(job_id)
            uploaded.append({"file": jf.name, "job_id": job_id, "status": "ingested"})
        except BloodHoundAPIError as e:
            uploaded.append({"file": jf.name, "status": "failed", "error": str(e)})

    failed = [u for u in uploaded if u.get("status") == "failed"]
    if failed and not any(u.get("status") == "ingested" for u in uploaded):
        return {
            "status": "Failed",
            "error": f"all {len(failed)} file(s) failed to upload",
            "details": uploaded,
        }

    return {
        "status": "Success",
        "files_uploaded": len(uploaded),
        "files_ingested": len([u for u in uploaded if u.get("status") == "ingested"]),
        "files_failed": len(failed),
        "details": uploaded,
        "next_hints": [
            "Wait a few seconds for analysis to process, then call "
            "bh_query_template with 'all_domains' or 'all_users' to verify "
            "the data landed.",
        ],
    }


@framework_tool(
    "Run an arbitrary Cypher query against the BloodHound CE graph database "
    "and return structured nodes + edges. Use bh_query_template instead for "
    "common AD analysis patterns (shortest path to DA, kerberoastable users, "
    "DCSync rights, etc.) — it composes the Cypher for you. This tool is for "
    "custom queries the templates don't cover. Results are capped (200 nodes, "
    "200 edges) to fit the model's context window. No scope gate — BloodHound "
    "queries its own graph database.",
    tags=["recon.ad"],
    next_hints=["report_finding", "dispatch_metasploit"],
)
def bh_query(cypher: str) -> Dict[str, Any]:
    """Run a raw Cypher query against the BloodHound graph.

    Args:
        cypher: A Cypher query string (e.g. ``MATCH (u:User) RETURN u.name
            LIMIT 10``).
    """
    if not cypher or not cypher.strip():
        return {"status": "Failed", "error": "cypher query is required"}
    client = BloodHoundClient.get_instance()
    try:
        result = client.run_cypher(cypher)
        result["status"] = "Success"
        result["cypher"] = cypher
        return result
    except BloodHoundAPIError as e:
        return {"status": "Failed", "error": str(e), "cypher": cypher}


@framework_tool(
    "Run a pre-built AD analysis Cypher query template against BloodHound CE. "
    "Templates include: shortest_path_to_da (find attack path from a user to "
    "Domain Admins), owned_to_tier_zero, kerberoastable_users, "
    "asreproastable_users, dcsync_rights, unconstrained_delegation, "
    "all_users, all_computers, all_domains, all_groups, group_members, "
    "admin_rights_on_computer, sessions_on_computer, gpo_controllers. Some "
    "templates require a node_name argument (the target user/computer/group "
    "name). No scope gate — BloodHound queries its own graph database.",
    tags=["recon.ad"],
    next_hints=["report_finding", "dispatch_metasploit", "secretsdump",
                "psexec_exec"],
)
def bh_query_template(
    template: str,
    node_name: str = "",
) -> Dict[str, Any]:
    """Run a pre-built Cypher query template.

    Args:
        template: One of the template names (see _CYPHER_TEMPLATES keys).
            Examples: ``shortest_path_to_da``, ``kerberoastable_users``,
            ``dcsync_rights``, ``all_users``.
        node_name: Required for templates that target a specific node
            (shortest_path_to_da, group_members, admin_rights_on_computer,
            etc.). Ignored by list-all templates.
    """
    template = (template or "").strip().lower()
    spec = _CYPHER_TEMPLATES.get(template)
    if spec is None:
        available = ", ".join(sorted(_CYPHER_TEMPLATES.keys()))
        return {
            "status": "Failed",
            "error": f"unknown template '{template}'. Available: {available}",
        }

    if spec.get("requires_name") and not node_name.strip():
        return {
            "status": "Failed",
            "error": (
                f"template '{template}' requires a node_name argument "
                f"(the user/computer/group name to query). "
                f"Template doc: {spec['doc']}"
            ),
        }

    # Substitute the $name parameter into the query.
    cypher = spec["query"]
    if "$name" in cypher:
        # Escape single quotes in the name to prevent Cypher injection.
        safe_name = node_name.strip().replace("'", "\\'")
        cypher = cypher.replace("$name", f"'{safe_name}'")

    client = BloodHoundClient.get_instance()
    try:
        result = client.run_cypher(cypher)
        result["status"] = "Success"
        result["template"] = template
        result["cypher"] = cypher
        result["template_doc"] = spec["doc"]
        # Add a human-readable summary for the model.
        n_nodes = len(result.get("nodes", []))
        n_edges = len(result.get("edges", []))
        result["summary"] = (
            f"Template '{template}' returned {n_nodes} node(s) and "
            f"{n_edges} edge(s)."
        )
        if n_nodes == 0:
            result["summary"] += (
                " No results — the data may not be ingested yet, or the "
                "node name doesn't exist in the graph. Try bh_ingest first, "
                "or bh_query_template with 'all_users'/'all_domains' to "
                "verify what's in the graph."
            )
        return result
    except BloodHoundAPIError as e:
        return {
            "status": "Failed",
            "error": str(e),
            "template": template,
            "cypher": cypher,
        }


@framework_tool(
    "List available BloodHound CE query templates and their descriptions. "
    "Returns each template name, whether it requires a node_name argument, "
    "and a one-line description of what it does. Use this to discover "
    "available AD analysis patterns before calling bh_query_template.",
    tags=["recon.ad"],
    next_hints=["bh_query_template"],
)
def bh_list_templates() -> Dict[str, Any]:
    """List all available query templates."""
    templates = []
    for name, spec in sorted(_CYPHER_TEMPLATES.items()):
        templates.append({
            "name": name,
            "requires_node_name": spec.get("requires_name", False),
            "description": spec["doc"],
        })
    return {
        "status": "Success",
        "count": len(templates),
        "templates": templates,
    }


@framework_tool(
    "Get BloodHound CE analysis and datapipe status: whether analysis is "
    "running, the datapipe status, and database completeness stats. Call this "
    "after bh_ingest to check whether the ingested data has been processed "
    "and is ready to query. No scope gate — internal BloodHound status only.",
    tags=["recon.ad"],
    next_hints=["bh_query_template"],
)
def bh_analysis_status() -> Dict[str, Any]:
    """Check BloodHound analysis/datapipe status and data completeness."""
    client = BloodHoundClient.get_instance()
    try:
        analysis = client.get_analysis_status()
        datapipe = client.get_datapipe_status()
        completeness = client.get_completeness()
        return {
            "status": "Success",
            "analysis": analysis,
            "datapipe": datapipe,
            "completeness": completeness,
        }
    except BloodHoundAPIError as e:
        return {"status": "Failed", "error": str(e)}


@framework_tool(
    "Start BloodHound CE analysis (post-ingestion processing). This triggers "
    "the datapipe to process ingested data and compute attack paths. Call "
    "this after bh_ingest if analysis doesn't start automatically. Check "
    "progress with bh_analysis_status. No scope gate — internal BloodHound "
    "operation.",
    tags=["recon.ad"],
    next_hints=["bh_analysis_status", "bh_query_template"],
)
def bh_start_analysis() -> Dict[str, Any]:
    """Trigger BloodHound CE analysis."""
    client = BloodHoundClient.get_instance()
    try:
        result = client.start_analysis()
        return {"status": "Success", "result": result}
    except BloodHoundAPIError as e:
        return {"status": "Failed", "error": str(e)}


@framework_tool(
    "List all available domains in the BloodHound CE graph. Use this after "
    "ingesting data to see which domains are represented. Returns domain "
    "names and object IDs. No scope gate — BloodHound graph query only.",
    tags=["recon.ad"],
    next_hints=["bh_query_template", "bh_get_entity"],
)
def bh_list_domains() -> Dict[str, Any]:
    """List all domains in the BloodHound graph."""
    client = BloodHoundClient.get_instance()
    try:
        domains = client.get_available_domains()
        return {
            "status": "Success",
            "count": len(domains) if isinstance(domains, list) else 0,
            "domains": domains,
        }
    except BloodHoundAPIError as e:
        return {"status": "Failed", "error": str(e)}


@framework_tool(
    "Get detailed info about a specific BloodHound CE entity (user, computer, "
    "group, domain, GPO, OU, etc.) by its object_id. Use bh_graph_search to "
    "find the object_id for a name first. Returns the entity's properties. "
    "No scope gate — BloodHound graph query only.",
    tags=["recon.ad"],
    next_hints=["bh_get_controllers", "bh_get_controllables", "report_finding"],
)
def bh_get_entity(object_id: str) -> Dict[str, Any]:
    """Get detailed info about a BloodHound entity by object_id.

    Args:
        object_id: The BloodHound object_id (from a graph search or query
            result). E.g. ``S-1-5-21-...-1104`` for a user.
    """
    if not object_id or not object_id.strip():
        return {"status": "Failed", "error": "object_id is required"}
    client = BloodHoundClient.get_instance()
    try:
        entity = client.get_entity(object_id.strip())
        return {"status": "Success", "entity": entity}
    except BloodHoundAPIError as e:
        return {"status": "Failed", "error": str(e), "object_id": object_id}


@framework_tool(
    "Find who CONTROLS a given BloodHound CE entity (attack path sources). "
    "Returns the principals that have privileges over the target entity "
    "(AdminTo, GenericAll, WriteDacl, Owns, etc.). Pass the entity's "
    "object_id. No scope gate — BloodHound graph query only.",
    tags=["recon.ad"],
    next_hints=["report_finding", "dispatch_metasploit"],
)
def bh_get_controllers(object_id: str) -> Dict[str, Any]:
    """Find who controls a BloodHound entity.

    Args:
        object_id: The BloodHound object_id of the target entity.
    """
    if not object_id or not object_id.strip():
        return {"status": "Failed", "error": "object_id is required"}
    client = BloodHoundClient.get_instance()
    try:
        result = client.get_entity_controllers(object_id.strip())
        result["status"] = "Success"
        result["object_id"] = object_id
        return result
    except BloodHoundAPIError as e:
        return {"status": "Failed", "error": str(e), "object_id": object_id}


@framework_tool(
    "Find what a given BloodHound CE entity CONTROLS (attack path targets). "
    "Returns the entities that the source entity has privileges over "
    "(AdminTo, GenericAll, WriteDacl, Owns, etc.). Pass the entity's "
    "object_id. No scope gate — BloodHound graph query only.",
    tags=["recon.ad"],
    next_hints=["report_finding", "dispatch_metasploit"],
)
def bh_get_controllables(object_id: str) -> Dict[str, Any]:
    """Find what a BloodHound entity controls.

    Args:
        object_id: The BloodHound object_id of the source entity.
    """
    if not object_id or not object_id.strip():
        return {"status": "Failed", "error": "object_id is required"}
    client = BloodHoundClient.get_instance()
    try:
        result = client.get_entity_controllables(object_id.strip())
        result["status"] = "Success"
        result["object_id"] = object_id
        return result
    except BloodHoundAPIError as e:
        return {"status": "Failed", "error": str(e), "object_id": object_id}


@framework_tool(
    "Search the BloodHound CE graph for nodes by name. Returns matching "
    "nodes with their object_ids, kinds, and names. Use this to find the "
    "object_id for a specific user/computer/group before calling "
    "bh_get_entity or bh_get_controllers. No scope gate — BloodHound graph "
    "query only.",
    tags=["recon.ad"],
    next_hints=["bh_get_entity", "bh_get_controllers"],
)
def bh_graph_search(query: str) -> Dict[str, Any]:
    """Search the BloodHound graph for nodes by name.

    Args:
        query: The name (or partial name) to search for, e.g. a username,
            computer name, or group name.
    """
    if not query or not query.strip():
        return {"status": "Failed", "error": "query is required"}
    client = BloodHoundClient.get_instance()
    try:
        result = client.graph_search(query.strip())
        result["status"] = "Success"
        result["query"] = query
        return result
    except BloodHoundAPIError as e:
        return {"status": "Failed", "error": str(e), "query": query}