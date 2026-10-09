"""DB connection helper for the MCP server. Read-only for every existing
table -- execute() below is the one exception, added specifically for the
employees table (mcp_server/employees.py), the first write path this MCP
server has ever had. Every other tool in this codebase only ever calls
query()/query_one().

2026-08-13: get_conn() can target a different physical database per MCP
identity -- added for the `staging_qa` identity (see server.py's
build_server() `database` param), which needs every read/write tool to
transparently hit eoxs_wiki_staging instead of live eoxs_wiki, with zero
changes to any individual tool function in employees.py/asset_writes.py/
server.py. A ContextVar is the mechanism: build_server()'s call_tool()
wrapper sets it for the duration of exactly one tool invocation (via
use_database() below), every query()/query_one()/execute() call made
during that invocation picks it up automatically through get_conn(), and
it's reset immediately after -- no tool function needed a new parameter.
Default (unset) behavior is unchanged: os.environ["PGDATABASE"] (live)."""
import os
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

STAGING_DB = os.environ.get("PGDATABASE_STAGING", "eoxs_wiki_staging")

_target_database = ContextVar("target_database", default=None)


@contextmanager
def use_database(name):
    """name: None (default -- live, unchanged) or "staging" (routes every
    query()/query_one()/execute() call made inside this block to
    eoxs_wiki_staging). Always resets on exit, including on exception."""
    token = _target_database.set(name)
    try:
        yield
    finally:
        _target_database.reset(token)


def get_conn():
    dbname = os.environ.get("PGDATABASE", "eoxs_wiki")
    if _target_database.get() == "staging":
        dbname = STAGING_DB
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "eoxs-db-live-cluster-do-user-42137371-0.d.db.ondigitalocean.com"),
        port=os.environ.get("PGPORT", "25060"),
        dbname=dbname,
        user=os.environ.get("PGUSER", "eoxs_app"),
        password=os.environ.get("PGPASSWORD", "Eoxs6333_kronox_db"),
        sslmode=os.environ.get("PGSSLMODE", "require"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def query(sql, params=None):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def query_one(sql, params=None):
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql, params=None):
    """Runs an INSERT/UPDATE with a RETURNING clause and commits. Returns the
    single returned row as a dict, or None if RETURNING produced no row."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            row = cur.fetchone()
        conn.commit()
        return dict(row) if row else None
    finally:
        conn.close()
