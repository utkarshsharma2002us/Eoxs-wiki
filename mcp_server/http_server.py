"""SSE transport for mcp_server, exposing it as a remote MCP connector for
claude.ai. Reuses the exact same tool implementations from server.py (still
used as-is for local/stdio access via Claude Code CLI or Claude Desktop) --
only the transport differs, and here, unlike stdio, there IS a real
identity boundary to enforce.

Auth scheme matches the OLD vault system's already-working MCP connector
(raj-wiki-vault's mcp_server.py, confirmed live in the user's Claude
account) exactly, after an initial attempt at Streamable-HTTP +
Authorization-header auth turned out not to match what claude.ai's
"Add custom connector" dialog actually exposes (only an optional OAuth
Client Secret field -- no generic header input). The old server's own
comment explains the real pattern: "the server has no login, so the URL
path itself is the credential." No OAuth, no headers -- each identity's
SSE endpoint is mounted under its own long random secret path segment, so
the URL itself is what gates access AND which access_tier clearance the
connection gets.

Four identities, four secrets, four independent Server instances (see
server.py's build_server()) -- clearance is baked into each instance at
construction time, never derived from anything in the request, so there's
no header/param a client could send to widen its own access:

  - MCP_URL_SECRET         -> FULL_CLEARANCE (tier1 + tier2_confidential_hr
    + tier2_confidential + tier2). This is the secret already live in
    claude.ai before tiering existed -- left pointing at full access so
    whoever already has it (presumably Raj) keeps working unchanged.
    Confirm who currently holds this URL before handing it out further.
  - MCP_HR_URL_SECRET      -> HR_CLEARANCE (tier2_confidential_hr +
    tier2_confidential + tier2, not tier1/Raj-personal). For HR and other
    explicitly-trusted roles. Gained tier2_confidential_hr 2026-09-02 (see
    schema/035_tier2_confidential_hr.sql) -- previously shared
    tier2_confidential + tier2 outright with `general` below, meaning the
    ONLY thing keeping payroll/onboarding/disciplinary/credential content
    out of general's context was query-time redaction; now that content
    structurally never reaches general's clearance list at all.
  - MCP_GENERAL_URL_SECRET -> INTERNAL_TEAM_CLEARANCE (tier2_confidential +
    tier2, NOT tier2_confidential_hr, NOT tier1/Raj-personal), plus
    extra_redact_categories=("monetary_amounts", "employee_activity_monitoring"):
    every dollar figure gets stripped (including payroll -- though payroll
    content should now typically be excluded at the row level via the HR
    tier split above, not reached at all) and Cattr/performance-monitoring
    content stays HR+full-only regardless of the wider tier clearance.
    2026-08-11: widened from tier2-only to tier2_confidential, since most
    tier2_confidential pages carry a dollar figure alongside otherwise-
    relevant general content that general shouldn't lose over one number --
    see redaction.py for the category definitions. 2026-09-02: no longer
    literally HR_CLEARANCE (see schema/035_tier2_confidential_hr.sql) --
    general keeps the pre-split tier2_confidential + tier2 access exactly as
    before, it just no longer picks up the new HR-only tier that HR gained.
    The redaction categories above remain in place underneath as a fallback
    safety net for tier2_confidential/tier2 rows that mention money/
    monitoring content for reasons unrelated to the HR carve-out.
  - MCP_INTERN_URL_SECRET  -> GENERAL_CLEARANCE (tier2 only -- unlike
    general above, intern was NOT widened to tier2_confidential), plus
    extra_redact_categories=("monetary_amounts",): every tool response
    also gets checked for dollar figures/prices/totals/deal sizes and has
    them stripped, on top of the normal tier2-only filtering. For interns
    -- same data as any other employee, minus every number that's money.

2026-08-12: `full` and `hr` also get the employees.py tool set (the first
write-capable tools this server has ever exposed) -- list/search/get plus
create/update/deactivate/reactivate_employee, gated independently of
`clearance` via `enable_employee_tools` (general/intern get none of it;
before 2026-09-02 `general` shared HR_CLEARANCE with `hr` for read tools
even though employee tools were withheld anyway -- now `general` has its
own INTERNAL_TEAM_CLEARANCE, see above). See mcp_server/employees.py and
schema/025_employees.sql.

2026-08-13: `full` and `hr` also get mcp_server/asset_writes.py's
create_asset/update_asset -- the second and, per explicit instruction, last
write surface in this server. `full` is unrestricted; `hr` gets
update_asset ONLY, and only for `SALARY_ASSET_SLUG` ('eoxs-salary-details')
-- any other slug is refused with a plain permission error. general/intern
get neither tool. See schema/032_asset_change_log.sql. 2026-09-02: this
asset's access_tier was reclassified to tier2_confidential_hr as part of
the HR-tier split (see schema/035_tier2_confidential_hr.sql) -- this write
restriction is unrelated and unchanged by that, since it was never about
which tier the asset sits at, only which identity may write to that one
slug.

2026-08-13: a 5th identity, `staging_qa`, exists purely for QA-testing
write behavior (does the model create/update the right rows, does it ever
touch something it shouldn't) with zero risk to live data. Full clearance,
every read tool, both employee and asset write tools fully unrestricted --
but every single tool call this identity makes, read or write, is
transparently routed to the eoxs_wiki_staging DATABASE instead of live
eoxs_wiki (see mcp_server/db.py's use_database()/ContextVar and
server.py's build_server() `database` param). This is NOT the `wiki_staging`
SCHEMA that live drafts sit in before promotion (schema/017's comment) --
it's the other, unrelated "staging" concept: a full separate physical
database eoxs_wiki_staging, which wiki_ingestion has no code path to reach
at all (confirmed by grep: zero references to get_staging_conn/
PGDATABASE_STAGING anywhere in wiki_ingestion/). A write through this
identity can therefore never reach the wiki-ingestion pipeline, structurally,
not just by policy. Every write is also tagged `changed_by='staging_qa'` in
employee_change_log/asset_change_log, so QA activity is trivially
distinguishable from anything else. See loaders/reset_staging_qa_data.py to
wipe staging's employees/assets tables and re-mirror them from live for a
clean slate between QA sessions.

Run with: python -m mcp_server.http_server  (dev, binds 127.0.0.1 only)
Deployed via systemd as eoxs-mcp.service, reverse-proxied by nginx at
https://5.223.44.95/mcp/<secret>/sse -- nginx passes /mcp/ through
unchanged (no prefix stripping) for both secrets alike, see
deploy/nginx-https.conf's single generic `location /mcp/` block.
"""
import hashlib
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
import contextlib

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.responses import Response

from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

import psycopg2

from mcp_server.server import build_server, FULL_CLEARANCE, HR_CLEARANCE, INTERNAL_TEAM_CLEARANCE, GENERAL_CLEARANCE

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# Mounted with the /mcp prefix baked in (matching nginx's location /mcp/,
# which passes the URI through UNCHANGED rather than stripping it -- see
# deploy/nginx-https.conf). SseServerTransport uses this path to build the
# "endpoint" event it sends the client (telling it where to POST messages),
# so the app must know its real external path, not just its local one --
# otherwise that URL is missing /mcp, the client's POST 404s against
# nginx's default location (the OTHER app on port 8090), and the session
# hangs after a successful-looking initial SSE connection.
# Behind nginx the app is reached at /mcp/<secret>/sse and sees that full
# path, so the prefix is "/mcp". On DigitalOcean App Platform the ingress
# rule matches prefix /mcp and STRIPS it before forwarding, so the app sees
# /<secret>/sse instead -- with a hardcoded "/mcp" every route 404s while the
# health check passes, which is exactly how this presented.
#
# MCP_MOUNT_PREFIX therefore configures the path the routes are registered
# at. It must match what THIS process receives. MCP_PUBLIC_PREFIX separately
# controls the path advertised to clients in the SSE "endpoint" event (see
# the note above): on App Platform the routes live at "" but the client must
# still be told "/mcp", because its POST goes back through the ingress.
# Note the sentinel: App Platform silently DROPS an env var whose value is the
# empty string, so `MCP_MOUNT_PREFIX: ""` never arrives and the default wins --
# which is why the first attempt at this still 404'd. "none" is therefore the
# way to ask for "no prefix at all".
_raw_mount = os.environ.get("MCP_MOUNT_PREFIX", "/mcp")
MOUNT_PREFIX = "" if _raw_mount.lower() in ("none", "empty", "/") else _raw_mount
PUBLIC_PREFIX = os.environ.get("MCP_PUBLIC_PREFIX", MOUNT_PREFIX)

SALARY_ASSET_SLUG = "eoxs-salary-details"

_raj_secret = os.environ.get("MCP_URL_SECRET", "raj")

IDENTITIES = [
    # Single main identity for RAJ: full clearance, unrestricted read & write tools
    ("full", _raj_secret, FULL_CLEARANCE, (), True, "all", None, None),
]
if _raj_secret != "raj":
    IDENTITIES.append(("full", "raj", FULL_CLEARANCE, (), True, "all", None, None))


_STREAMABLE_MANAGERS = []


logger = logging.getLogger("eoxs_mcp.http_server")


def _make_routes(identity_name, secret, clearance, extra_redact_categories=(), enable_employee_tools=True, asset_write_scope="all", database=None, header_auth_connector=None):
    mcp_server_instance = build_server(
        clearance, name=f"eoxs-wiki-db-{identity_name}", extra_redact_categories=extra_redact_categories,
        enable_employee_tools=enable_employee_tools, identity_name=identity_name, asset_write_scope=asset_write_scope,
        database=database,
    )
    sse = SseServerTransport(f"{PUBLIC_PREFIX}/{secret}/messages/")

    async def _handle_sse_raw(scope, receive, send):
        async with sse.connect_sse(scope, receive, send) as streams:
            await mcp_server_instance.run(streams[0], streams[1], mcp_server_instance.create_initialization_options())
        return Response()

    async def sse_endpoint(request):
        return await _handle_sse_raw(request.scope, request.receive, request._send)

    manager = StreamableHTTPSessionManager(app=mcp_server_instance, stateless=True)
    _STREAMABLE_MANAGERS.append(manager)

    async def dispatch(scope, receive, send):
        raw = scope.get("path", "")
        root = scope.get("root_path", "")
        tail = (raw[len(root):] if root and raw.startswith(root) else raw).rstrip("/") or "/"

        if tail.startswith("/messages"):
            await sse.handle_post_message(scope, receive, send)
        elif tail not in ("/mcp", "/sse"):
            await JSONResponse({"error": "not found", "hint": "use /mcp"},
                               status_code=404)(scope, receive, send)
        elif scope["method"] == "GET":
            await _handle_sse_raw(scope, receive, send)
        else:
            await manager.handle_request(scope, receive, send)

    mount_path = f"/{secret}" if secret.startswith("/") else f"{MOUNT_PREFIX}/{secret}"
    return [Mount(mount_path, app=dispatch)]


routes = [
    route
    for identity_name, secret, clearance, extra, enable_employee_tools, asset_write_scope, database, header_auth_connector in IDENTITIES
    for route in _make_routes(identity_name, secret, clearance, extra, enable_employee_tools, asset_write_scope, database, header_auth_connector)
]

# Unauthenticated liveness probe.
async def health(request):
    return JSONResponse({
        "status": "ok",
        "mount_prefix": MOUNT_PREFIX,
        "public_prefix": PUBLIC_PREFIX,
        "route_count": len(routes),
        "route_fingerprints": sorted({
            seg[:6]
            for r in routes
            for seg in [
                (getattr(r, "path", "") or "")[len(MOUNT_PREFIX):].lstrip("/").split("/")[0]
            ]
            if seg and seg not in ("health",)
        }),
    })


routes.append(Route("/health", endpoint=health, methods=["GET"]))

@contextlib.asynccontextmanager
async def _lifespan(app):
    """StreamableHTTPSessionManager.handle_request needs its task group live."""
    async with contextlib.AsyncExitStack() as stack:
        for _m in _STREAMABLE_MANAGERS:
            await stack.enter_async_context(_m.run())
        yield


app = Starlette(routes=routes, lifespan=_lifespan)


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("MCP_HTTP_PORT", "8091"))
    host = os.environ.get("MCP_HTTP_HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)

