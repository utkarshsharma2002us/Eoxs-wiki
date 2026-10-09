"""Applies schema/*.sql files in filename order against the database in .env.
Tracks applied files in a schema_migrations table so reruns are safe."""
import os
import sys
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

SCHEMA_DIR = Path(__file__).resolve().parent

def get_conn():
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "eoxs-db-live-cluster-do-user-42137371-0.d.db.ondigitalocean.com"),
        port=os.environ.get("PGPORT", "25060"),
        dbname=os.environ.get("PGDATABASE", "eoxs_wiki"),
        user=os.environ.get("PGUSER", "eoxs_app"),
        password=os.environ.get("PGPASSWORD", "Eoxs6333_kronox_db"),
        sslmode=os.environ.get("PGSSLMODE", "require"),
    )

def main():
    conn = get_conn()
    conn.autocommit = False
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                filename TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        conn.commit()

    sql_files = sorted(SCHEMA_DIR.glob("*.sql"))
    for sql_file in sql_files:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM schema_migrations WHERE filename = %s", (sql_file.name,))
            if cur.fetchone():
                print(f"skip  {sql_file.name} (already applied)")
                continue
        sql = sql_file.read_text(encoding="utf-8")
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute("INSERT INTO schema_migrations (filename) VALUES (%s)", (sql_file.name,))
            conn.commit()
            print(f"apply {sql_file.name}")
        except Exception as e:
            conn.rollback()
            print(f"FAIL  {sql_file.name}: {e}")
            sys.exit(1)
    conn.close()
    print("done")

if __name__ == "__main__":
    main()
