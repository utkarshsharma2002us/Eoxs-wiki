"""DB connections for the raw-ingestion service: one to live (eoxs_wiki),
one to staging (eoxs_wiki_staging). Every source fetcher writes to both --
live first (required to succeed), staging best-effort (log and continue on
failure, per design: live must never wait on staging's health).
"""
import os
from pathlib import Path

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

LIVE_DB = os.environ.get("PGDATABASE", "eoxs_wiki")
STAGING_DB = os.environ.get("PGDATABASE_STAGING", LIVE_DB)


def _connect(dbname):
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "eoxs-db-live-cluster-do-user-42137371-0.d.db.ondigitalocean.com"),
        port=os.environ.get("PGPORT", "25060"),
        dbname=dbname,
        user=os.environ.get("PGUSER", "eoxs_app"),
        password=os.environ.get("PGPASSWORD", "Eoxs6333_kronox_db"),
        sslmode=os.environ.get("PGSSLMODE", "require"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def get_live_conn():
    return _connect(LIVE_DB)


def get_staging_conn():
    return _connect(STAGING_DB)


def dual_write(write_fn, *args, **kwargs):
    """Runs write_fn(conn, *args, **kwargs) against live first (must
    succeed -- exception propagates), then against staging as best-effort
    (exception is caught, logged, and swallowed so a staging outage never
    blocks live data from landing or the cursor from advancing).

    write_fn must commit internally and return whatever the caller needs
    from the LIVE result (staging's return value is discarded).
    """
    live_conn = get_live_conn()
    try:
        result = write_fn(live_conn, *args, **kwargs)
    finally:
        live_conn.close()

    try:
        staging_conn = get_staging_conn()
        try:
            write_fn(staging_conn, *args, **kwargs)
        finally:
            staging_conn.close()
    except Exception as e:
        import logging
        logging.getLogger("ingestion.db").warning(
            "staging write failed (live succeeded, continuing): %s", e
        )

    return result
