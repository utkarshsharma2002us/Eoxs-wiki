"""Shared DB connection + VAULT_ROOT helper for all loaders."""
import os
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

VAULT_ROOT = Path(os.environ["VAULT_ROOT"])


def get_conn():
    conn = psycopg2.connect(
        host=os.environ.get("PGHOST", "eoxs-db-live-cluster-do-user-42137371-0.d.db.ondigitalocean.com"),
        port=os.environ.get("PGPORT", "25060"),
        dbname=os.environ.get("PGDATABASE", "eoxs_wiki"),
        user=os.environ.get("PGUSER", "eoxs_app"),
        password=os.environ.get("PGPASSWORD", "Eoxs6333_kronox_db"),
        sslmode=os.environ.get("PGSSLMODE", "require"),
    )
    return conn
