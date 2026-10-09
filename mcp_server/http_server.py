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

IDENTITIES = [
    # 5th element: enable_employee_tools (see server.py's build_server()
    # docstring) -- general/intern get NO employee tools at all.
    # 6th element: asset_write_scope -- "all" (full, unrestricted),
    # a specific slug set (hr, salary register only), or None (general/
    # intern, no asset write tools at all). Independent of `clearance` for
    # the same reason enable_employee_tools is: these are the only two
    # write surfaces in the whole server, deliberately gated identity-by-
    # identity, never by the read-side tier system.
    # 7th element: database -- None (live, every real identity) or
    # "staging" (staging_qa only -- routes every tool call to
    # eoxs_wiki_staging, see mcp_server/db.py's use_database()).
    # 2026-09-03: moved off secret-in-the-URL, same pattern as 'general'/'hr'
    # above. "raj" is now a fixed PUBLIC path segment naming who this identity
    # is for -- clearance stays "full" internally (identity_name, used for
    # build_server/tool naming/changed_by), only the URL and auth mechanism
    # changed. Named by person rather than by clearance level ("full") because
    # a separate "ayan" full-clearance identity exists on this same server;
    # "/full/mcp" would not have distinguished the two.
    # MCP_URL_SECRET is no longer read; its old URL now 404s.
    ("full", "raj", FULL_CLEARANCE, (), True, "all", None, "raj"),
    ("ayan", os.environ["MCP_AYAN_URL_SECRET"], FULL_CLEARANCE, (), True, "all", None, None),  # 2026-08-21 apex: Ayan own write-capable identity (mirror of full; changed_by=ayan)
    # 2026-09-03: moved off secret-in-the-URL, same pattern as 'general' above.
    # "hr" is now a fixed PUBLIC path segment; auth is a per-person token in an
    # x-auth-token header against public.mcp_tokens (connector='hr').
    # MCP_HR_URL_SECRET is no longer read; its old URL now 404s.
    ("hr", "hr", HR_CLEARANCE, ("non_payroll_monetary_amounts",), True, {SALARY_ASSET_SLUG}, None, "hr"),
    # 2026-08-11: expanded from GENERAL_CLEARANCE (tier2 only) to
    # tier2_confidential + tier2 -- most tier2_confidential pages carry a
    # dollar figure alongside otherwise-relevant general content, and general
    # was losing the whole page over one number. Same URL/secret as before,
    # so nothing breaks for anyone who already has this link -- it now just
    # returns more, redacted content. monetary_amounts blocks every dollar
    # figure; employee_activity_monitoring keeps Cattr/performance data
    # HR+full-only regardless of the wider tier clearance (see redaction.py).
    # 2026-09-02: was HR_CLEARANCE (literally shared with `hr`) until the
    # tier2_confidential_hr split -- now INTERNAL_TEAM_CLEARANCE, which is
    # the pre-split tier2_confidential + tier2 list, deliberately excluding
    # the new HR-only tier. See schema/035_tier2_confidential_hr.sql and the
    # module docstring above.
    # 2026-09-03: moved off secret-in-the-URL. "internal-team" is a fixed PUBLIC
    # path segment, not a credential -- the URL is now the same for every person
    # on the team. Auth is a per-person token in an x-auth-token header instead
    # (8th element, header_auth_connector), checked against public.mcp_tokens
    # in eoxs_frontend_threads. Revoking one person is one row update and
    # touches nobody else's access or the URL itself -- the old secret required
    # rotating the link (and re-onboarding everyone) to revoke anyone.
    # MCP_GENERAL_URL_SECRET is no longer read; its old URL now 404s.
    ("general", "internal-team", INTERNAL_TEAM_CLEARANCE, ("monetary_amounts", "employee_activity_monitoring"), False, None, None, "internal-team"),
    # 2026-09-03: moved off secret-in-the-URL, same pattern as full/general/hr.
    # "intern" is role-based (many interchangeable people fill it), so the
    # public path matches the identity name, same convention as "hr".
    # MCP_INTERN_URL_SECRET is no longer read; its old URL now 404s.
    ("intern", "intern", GENERAL_CLEARANCE, ("monetary_amounts",), False, None, None, "intern"),
    # staging_qa: full clearance, every read tool, BOTH write tool sets
    # fully unrestricted (unlike hr's real-world restrictions -- there's
    # nothing to protect here, it's disposable test data) -- but database=
    # "staging" means every single call, read or write, hits
    # eoxs_wiki_staging, never live. Deliberately not documented in any of
    # the 4 main skill files -- this identity is for direct hands-on QA by
    # whoever holds the secret, not for a persistent claude.ai connector
    # meant to answer real questions. See deploy/eoxs-wiki-db-skill-staging-qa.md.
    ("staging_qa", os.environ["MCP_STAGING_URL_SECRET"], FULL_CLEARANCE, (), True, "all", "staging", None),
]


_STREAMABLE_MANAGERS = []


logger = logging.getLogger("eoxs_mcp.http_server")


def _resolve_header_token(headers, connector):
    """Authorization/x-auth-token header -> username, for identities migrated
    off secret-in-the-URL (currently just 'general' / internal-team).

    Reads public.mcp_tokens in eoxs_frontend_threads -- a DIFFERENT database
    from this server's own (OV2, on the DigitalOcean cluster) -- over the
    local unix socket as `deploy`, which holds SELECT only. That keeps this
    lookup read-only even though it lives in a write-capable process: a bug
    here can confirm or deny a token, never mint or revoke one.

    Only the SHA-256 is ever compared; the raw token is never stored anywhere,
    including in this process's memory beyond the single request.
    """
    bearer = headers.get("authorization") or headers.get("x-auth-token")
    if not bearer:
        return None
    tok = bearer.split(None, 1)[1].strip() if bearer.lower().startswith("bearer ") else bearer.strip()
    if not tok:
        return None
    digest = hashlib.sha256(tok.encode()).hexdigest()
    # Every parameter pinned explicitly, INCLUDING port. This process's own
    # .env sets PGPORT=25060 for its OV2 database on the DigitalOcean cluster,
    # and psycopg2 reads unset libpq parameters from the environment -- host
    # was pinned but port was not, so the connection silently tried the DO
    # cluster's port against a local socket path and failed outright
    # (".s.PGSQL.25060": No such file or directory). This is the identical
    # class of bug that hit wiki_mcp's own connection helper earlier: an
    # inherited PG* variable redirecting a connection that looked pinned.
    conn = psycopg2.connect(host="/var/run/postgresql", port=5432,
                            dbname="eoxs_frontend_threads", user="deploy")
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT username FROM public.mcp_tokens
                           WHERE token_sha256=%s AND active AND connector=%s""", (digest, connector))
            row = cur.fetchone()
    finally:
        conn.close()
    return row[0] if row else None


def _make_routes(identity_name, secret, clearance, extra_redact_categories=(), enable_employee_tools=False, asset_write_scope=None, database=None, header_auth_connector=None):
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
        # Starlette's Route always wraps a plain function as func(request) -> response
        # (it doesn't special-case a 3-arg scope/receive/send signature) -- SSE needs
        # the raw ASGI call underneath, so unpack the Request back into that shape.
        return await _handle_sse_raw(request.scope, request.receive, request._send)

    # One dispatcher owning every method on this identity's mount, serving both
    # MCP transports.
    #
    # The route above was GET-only, so a client probing with POST -- the
    # Streamable HTTP handshake, which is what claude.ai tries first -- got 405
    # Method Not Allowed from Starlette. A client cannot tell "wrong method"
    # apart from "authenticate first" (401/403/405 all mean the request was not
    # accepted as sent), so it reported the server as asking for sign-in. The
    # probe only runs at registration, which is why logging out and back in
    # appeared to fix it: the saved connector skipped the probe and went
    # straight to the GET handshake that always worked.
    #
    # /mcp is now the canonical suffix; /sse is kept as an alias so every
    # already-registered connector keeps working. Anything else 404s rather
    # than falling through to the SSE branch and opening a stream for a stray
    # request.
    manager = StreamableHTTPSessionManager(app=mcp_server_instance, stateless=True)
    _STREAMABLE_MANAGERS.append(manager)

    async def dispatch(scope, receive, send):
        # This Starlette hands a mounted app the FULL path and puts the matched
        # prefix in root_path -- it does not strip the remainder for you.
        raw = scope.get("path", "")
        root = scope.get("root_path", "")
        tail = (raw[len(root):] if root and raw.startswith(root) else raw).rstrip("/") or "/"

        if header_auth_connector:
            # secret is a fixed public label here (e.g. "internal-team"), not a
            # credential -- the URL is the same for everyone. Auth is a per-
            # person token in a header instead, so one person's access can be
            # revoked without touching the URL or anyone else's token.
            headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
            user = _resolve_header_token(headers, header_auth_connector)
            if not user:
                # No WWW-Authenticate: that header advertises RFC 6750 bearer
                # auth (the OAuth family) and made claude.ai auto-select
                # "Always required (Detected)", which then tries an OAuth flow
                # this server does not implement. State plainly what is wanted
                # instead of a header a client will misinterpret.
                return await JSONResponse(
                    {"error": "unauthorized",
                     "detail": "This connector uses a static token, not OAuth. Set "
                               "Authentication to None and add a request header "
                               "'x-auth-token' with the token an admin minted for you."},
                    status_code=401)(scope, receive, send)
            logger.info("auth ok identity=%s user=%s path=%s method=%s",
                        identity_name, user, tail, scope.get("method"))

        if tail.startswith("/messages"):
            await sse.handle_post_message(scope, receive, send)
        elif tail not in ("/mcp", "/sse"):
            await JSONResponse({"error": "not found", "hint": "use /mcp"},
                               status_code=404)(scope, receive, send)
        elif scope["method"] == "GET":
            await _handle_sse_raw(scope, receive, send)
        else:
            await manager.handle_request(scope, receive, send)

    # Header-auth identities (the new pattern) get a clean top-level path --
    # /internal-team/mcp, not /mcp/internal-team/mcp -- since `secret` is now a
    # readable label, not an opaque credential that needed hiding under the
    # shared prefix. Secret-in-path identities keep MOUNT_PREFIX unchanged;
    # nginx has a matching top-level location block per header-auth identity
    # (currently just /internal-team/), proxying to the same backend.
    mount_path = f"/{secret}" if header_auth_connector else f"{MOUNT_PREFIX}/{secret}"
    return [Mount(mount_path, app=dispatch)]


routes = [
    route
    for identity_name, secret, clearance, extra, enable_employee_tools, asset_write_scope, database, header_auth_connector in IDENTITIES
    for route in _make_routes(identity_name, secret, clearance, extra, enable_employee_tools, asset_write_scope, database, header_auth_connector)
]

# Unauthenticated liveness probe. Deliberately reveals nothing: no identity
# list, no secrets, no database state -- just proof the process is up and
# accepting connections. Needed because every other route on this app is
# scoped to a URL secret, and a container platform's health check cannot be
# given one (it would end up in platform config and logs). Without this,
# App Platform probes "/" , gets a 404, and kills the container as unhealthy.
async def health(request):
    # Reports the mount prefix and route COUNT so a deployment can be debugged
    # without a shell and without exposing any secret: never the secrets
    # themselves, never a full route path (those contain the URL credential).
    return JSONResponse({
        "status": "ok",
        "mount_prefix": MOUNT_PREFIX,
        "public_prefix": PUBLIC_PREFIX,
        "route_count": len(routes),
        # First 6 chars of each registered secret, so a 404 can be traced to a
        # secret mismatch between platform env and the URL being requested.
        # 6 chars of a 43-char token is not enough to guess or replay.
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
    # 0.0.0.0, not 127.0.0.1: on the droplet nginx proxies to this from the
    # same host either way, but on a container platform (App Platform) the
    # load balancer connects from OUTSIDE the container -- a loopback bind
    # refuses it, the health check fails, and the platform kills the
    # container as "misbehaving". Binding all interfaces is safe here because
    # the only public path in either environment is the reverse proxy /
    # platform ingress, never this port directly.
    host = os.environ.get("MCP_HTTP_HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
