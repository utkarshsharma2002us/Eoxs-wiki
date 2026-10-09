"""MCP server exposing eoxs_wiki (Postgres) via a tool set mirroring the
existing OV2 vault MCP server, for direct reliability/quality comparison.

Read-only: every tool issues SELECT queries against eoxs_app, which itself
has no reason to hold write privileges beyond what the loaders need locally.

Access-tier enforcement: every raw-source tool takes a `clearance` kwarg
(a list of allowed access_tier values) that's bound per-connection via
build_server(), never taken from the caller's tool-call arguments -- it's
not in any tool's inputSchema, so nothing the MCP client sends can widen
its own clearance. `server`/`TOOLS`/`main()` below (stdio transport, used
for local/Claude-Code-CLI access) default to FULL_CLEARANCE, matching the
fact that whoever can run this file already has direct Postgres
credentials in .env -- no narrower boundary to enforce there. The HTTP/SSE
transport (http_server.py) is where the real boundary lives: it builds a
SEPARATE Server instance per identity, each closed over its own clearance,
mounted at its own secret URL path.

Four levels, additive by role (see schema/020_tier2_confidential.sql and
schema/035_tier2_confidential_hr.sql for the full definitions):
  tier1                 Raj's own personal data, PLUS (2026-08-26) this
                         repository's own docs/architecture/codebase
                         reference (repo_docs table) -- internal
                         engineering/ops detail with no reason to be
                         visible past `full`. FULL_CLEARANCE only.
  tier2_confidential_hr (2026-09-02) Employee-facing HR/financial content:
                         payroll/salary/compensation/incentive/bonus,
                         onboarding/offboarding, disciplinary action
                         (penalisation, suspension), sensitive credential
                         material. Carved out of tier2_confidential so it
                         is invisible to `general` (internal team) even
                         before the redaction layer runs -- previously the
                         only thing keeping this out of general's
                         responses was query-time redaction stripping
                         monetary_amounts/employee_activity_monitoring
                         after the row was already visible.
                         FULL_CLEARANCE + HR_CLEARANCE only.
  tier2_confidential    Company-confidential, everything else in the old
                         bucket (investor relations, financial statements,
                         vendor contracts, legal/compliance, employee
                         activity/performance monitoring). FULL_CLEARANCE +
                         HR_CLEARANCE + the clearance list bound to
                         `general` (internal team) -- unchanged from before
                         this split.
  tier2                 General, everyone. All four clearances.

Wiki tools (get_wiki_page/search_wiki) ARE tier-filtered now that
wiki-page access-tier computation is built (wiki_ingestion/promote.py for
new pages, wiki_ingestion/tier_classifier.py for the historical backlog).
"""
import asyncio
import functools
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from mcp_server.db import query as db_query, query_one as db_query_one, use_database
from mcp_server import redaction
from mcp_server.employees import EMPLOYEE_TOOLS, EMPLOYEE_WRITE_TOOLS, tool_defs as employee_tool_defs
from mcp_server.asset_writes import ASSET_WRITE_TOOLS, create_asset_tool_def, update_asset_tool_def
from mcp_server.repo_docs import REPO_DOCS_TOOLS, tool_defs as repo_docs_tool_defs

BODY_PREVIEW_CHARS = 1500  # full body is often 10-50K chars; a preview keeps get_* calls usable

FULL_CLEARANCE = ["tier1", "tier2_confidential_hr", "tier2_confidential", "tier2"]
HR_CLEARANCE = ["tier2_confidential_hr", "tier2_confidential", "tier2"]
# 2026-09-02: 'general' (internal team) used to share HR_CLEARANCE outright.
# Now given its own constant, explicitly excluding tier2_confidential_hr --
# this is the actual enforcement point for "internal team never sees the HR
# tier, pre-redaction", not just a redaction-layer filter. See
# schema/035_tier2_confidential_hr.sql and http_server.py's IDENTITIES.
INTERNAL_TEAM_CLEARANCE = ["tier2_confidential", "tier2"]
GENERAL_CLEARANCE = ["tier2"]

# ---------------------------------------------------------------------------
# Tool implementations. Every function's parameter names match the JSON
# schema keys below exactly -- call_tool() dispatches via func(**arguments),
# so a mismatch here silently breaks every real call from Claude. Tools that
# read tiered raw tables take a trailing `clearance` kwarg, bound per-server
# instance by build_server() -- never part of any tool's inputSchema, so it
# can never arrive from the client's own arguments.
# ---------------------------------------------------------------------------

def get_index(clearance=FULL_CLEARANCE):
    # tickets/sales_orders deliberately absent (2026-08-10): removed from
    # this system entirely -- support tickets and invoices now live only
    # in EOXS Teams Odoo, a separate connector, faster to query there.
    counts = db_query_one("""
        SELECT
            (SELECT count(*) FROM wiki_pages WHERE access_tier::text = ANY(%s)) AS wiki_pages,
            (SELECT count(*) FROM email_threads WHERE access_tier::text = ANY(%s)) AS email_threads,
            (SELECT count(*) FROM call_transcripts WHERE source='fireflies' AND access_tier::text = ANY(%s)) AS fireflies_calls,
            (SELECT count(*) FROM call_transcripts WHERE source='fathom' AND access_tier::text = ANY(%s)) AS fathom_calls,
            (SELECT count(*) FROM clients) AS clients,
            (SELECT count(*) FROM implementation_tasks WHERE access_tier::text = ANY(%s)) AS implementation_tasks
    """, (clearance, clearance, clearance, clearance, clearance))
    by_type = db_query(
        "SELECT page_type, count(*) AS n FROM wiki_pages WHERE access_tier::text = ANY(%s) GROUP BY page_type ORDER BY page_type",
        (clearance,),
    )
    return {"totals": counts, "wiki_pages_by_type": by_type}


# wiki_citations.source_type -> the raw table + join column used to resolve
# a citation to a concrete row your other tools can fetch directly (get_email,
# get_call, get_asset, get_repo_doc, get_implementation_task). Mirrors the
# join logic already used by wiki_ingestion/promote.py and tier_classifier.py
# -- implementation_task is the one exception, joined on odoo_task_id, never
# the internal serial id, because that table gets fully refreshed every
# raw-ingestion sweep (see get_implementation_task's docstring). 'ticket' is
# a legacy value with no live table (tickets were removed from this system
# 2026-08-10) -- left unresolvable on purpose. 'unresolved'/'unresolvable'/
# 'wiki_page' are pre-existing junk/self-reference values from older
# imports, also left unresolvable.
CITATION_FETCH_HINTS = {
    "email_thread": "get_email",
    "call_transcript": "get_call",
    "asset": "get_asset",
    "repo_doc": "get_repo_doc",
    "implementation_task": "get_implementation_task",
}


# Per-page "most recent real-world event this page actually describes",
# computed from its citations' own dates -- NOT wiki_pages.updated_date,
# which is wiki-synthesis time and has no reliable correlation with the
# recency of the underlying content (confirmed 2026-09-08: two live pages
# titled identically, "Ryan Capinski -> Tripp Collier (Collier Metals)
# Referral Call", exist because wiki-ingestion's drafting agent failed to
# detect an existing same-topic draft across a 6-hour cycle boundary and
# both got independently promoted -- a separate, upstream duplication bug,
# see docs/wiki-ingestion.md -- and get_wiki_page's old ORDER BY updated_date
# DESC picked whichever page happened to be *synthesized* most recently,
# which for a title match on just "Ryan Capinski" surfaced an unrelated
# September page that merely mentions him in passing, over the actual
# Collier-referral content, because that page's synthesis run was newer).
# email_thread uses thread_dates (array, take the max); call_transcript uses
# call_date; implementation_task uses task_updated_date (most-recently-
# active, not creation); asset/repo_doc have no event-date of their own
# (they're reference docs, not dated correspondence) so fall back to the
# citation row's own updated_at as the least-bad signal available.
_CITED_EVENT_DATE_SQL = """
    (SELECT max(d) FROM (
        SELECT (SELECT max(x) FROM unnest(t.thread_dates) x) AS d
          FROM wiki_citations wc JOIN email_threads t ON t.id = wc.source_id
         WHERE wc.wiki_page_id = wp.id AND wc.source_type = 'email_thread'
        UNION ALL
        SELECT t.call_date::timestamptz
          FROM wiki_citations wc JOIN call_transcripts t ON t.id = wc.source_id
         WHERE wc.wiki_page_id = wp.id AND wc.source_type = 'call_transcript'
        UNION ALL
        SELECT t.task_updated_date::timestamptz
          FROM wiki_citations wc JOIN implementation_tasks t ON t.odoo_task_id = wc.source_id
         WHERE wc.wiki_page_id = wp.id AND wc.source_type = 'implementation_task'
        UNION ALL
        SELECT t.updated_at
          FROM wiki_citations wc JOIN assets t ON t.id = wc.source_id
         WHERE wc.wiki_page_id = wp.id AND wc.source_type = 'asset'
        UNION ALL
        SELECT t.updated_at
          FROM wiki_citations wc JOIN repo_docs t ON t.id = wc.source_id
         WHERE wc.wiki_page_id = wp.id AND wc.source_type = 'repo_doc'
    ) all_dates)
"""


def _citations_for_page(page_id, clearance):
    """Every raw source this wiki page cites, plus which tool+identifier to
    call to fetch the actual record -- so a citation can be followed
    directly instead of re-searching raw data blind. This is the piece that
    was missing entirely before 2026-09-08: wiki_citations (4,510 rows) was
    populated by ingestion but never read by any live-serving tool, so a
    model that found the right wiki page still had no structured way to
    jump to the exact source thread/call/asset it cited."""
    rows = db_query(
        "SELECT source_type, source_id, source_ref_raw FROM wiki_citations WHERE wiki_page_id = %s ORDER BY id",
        (page_id,),
    )
    for row in rows:
        source_type, source_id = row["source_type"], row["source_id"]
        fetch_tool = CITATION_FETCH_HINTS.get(source_type)
        if fetch_tool is None or source_id is None:
            row["fetch_tool"] = None
            row["fetch_identifier"] = None
            continue
        row["fetch_tool"] = fetch_tool
        row["fetch_identifier"] = source_id
    return rows


def get_wiki_page(title, clearance=FULL_CLEARANCE):
    # Ordered by the most recent event its own citations actually describe,
    # not synthesis time (updated_date) -- see _CITED_EVENT_DATE_SQL's
    # comment. A page with no resolvable citations (max = NULL) sorts last,
    # then updated_date breaks any further tie.
    page = db_query_one(
        f"""SELECT wp.* FROM wiki_pages wp
            WHERE wp.title ILIKE %s AND wp.access_tier::text = ANY(%s)
            ORDER BY {_CITED_EVENT_DATE_SQL} DESC NULLS LAST, wp.updated_date DESC NULLS LAST
            LIMIT 1""",
        (f"%{title}%", clearance),
    )
    if not page:
        return {"error": f"no wiki page matching '{title}'"}

    full_body = page.pop("body", "") or ""
    page["body_preview"] = full_body[:BODY_PREVIEW_CHARS]
    page["body_length"] = len(full_body)
    page["body_truncated"] = len(full_body) > BODY_PREVIEW_CHARS
    page.pop("body_tsv", None)

    page["outbound_links"] = db_query(
        """SELECT wl.to_title_raw, wp.title AS resolved_title
           FROM wiki_links wl LEFT JOIN wiki_pages wp ON wp.id = wl.to_page_id
           WHERE wl.from_page_id = %s""",
        (page["id"],),
    )
    page["flags"] = db_query(
        "SELECT flag_type, text FROM wiki_flags WHERE wiki_page_id = %s", (page["id"],)
    )
    # citations: the raw sources this page was drafted from -- call
    # `fetch_tool` with `fetch_identifier` to get the full raw record
    # (e.g. get_email(66376)) instead of re-searching raw data.
    page["citations"] = _citations_for_page(page["id"], clearance)
    return page


def search_wiki(query, clearance=FULL_CLEARANCE):
    # id included (previously omitted) so a hit can be chained straight into
    # get_wiki_page or a citations lookup without a second title-based search.
    # Ranked by text relevance first (as before), with the cited event date
    # (see _CITED_EVENT_DATE_SQL) as a tiebreak -- "the most recent X about Y"
    # needs both: pure ts_rank alone has no way to prefer the newer of two
    # similarly-relevant pages (e.g. two duplicate-titled pages about the
    # same person/topic from different points in time).
    results = db_query(
        f"""SELECT wp.id, wp.title, wp.page_type,
                   ts_headline('english', wp.body, plainto_tsquery('english', %s)) AS snippet,
                   ts_rank(wp.body_tsv, plainto_tsquery('english', %s)) AS rank
            FROM wiki_pages wp
            WHERE wp.body_tsv @@ plainto_tsquery('english', %s) AND wp.access_tier::text = ANY(%s)
            ORDER BY rank DESC, {_CITED_EVENT_DATE_SQL} DESC NULLS LAST
            LIMIT 20""",
        (query, query, query, clearance),
    )
    for row in results:
        row["citations"] = _citations_for_page(row["id"], clearance)
    return results


def list_emails(account="all", month="", date="", clearance=FULL_CLEARANCE):
    """Ordered by the most recent entry in thread_dates (when the mail was
    actually sent), NOT source_file_path -- that column is only ever set for
    the legacy file-based import (see get_email's docstring), so sorting or
    filtering on it silently hid every API-ingested thread (all current
    Gmail/Zoho mail) behind the older, legacy-imported rows that still have
    a path. Found 2026-09-02: list_emails looked "stuck" at mid-August even
    though search_emails/get_email proved current data existed and was
    already wiki-cited.

    date: optional 'YYYY-MM-DD' for day-level filtering (added 2026-09-08 --
    previously only month granularity existed, so a query like "the email I
    sent Aug 28" had no precise tool-level way to be answered; the caller
    had to eyeball a whole month's list or guess)."""
    sql = """SELECT id, source_account, gmail_thread_id, subject, message_count, source_file_path,
                     (SELECT max(d) FROM unnest(thread_dates) d) AS last_message_at
              FROM email_threads WHERE access_tier::text = ANY(%s)"""
    params = [clearance]
    if account != "all":
        sql += " AND source_account = %s"
        params.append(account)
    if date:
        sql += " AND EXISTS (SELECT 1 FROM unnest(thread_dates) d WHERE d::date = %s)"
        params.append(date)
    elif month:
        sql += " AND EXISTS (SELECT 1 FROM unnest(thread_dates) d WHERE to_char(d, 'YYYY-MM') = %s)"
        params.append(month)
    sql += " ORDER BY last_message_at DESC NULLS LAST LIMIT 100"
    return db_query(sql, params)


def _search_emails_query(tsquery_fn, query, account, clearance):
    sql = f"""
        SELECT id, source_account, subject, source_file_path, snippet, rank FROM (
            SELECT DISTINCT ON (t.id) t.id, t.source_account, t.subject, t.source_file_path,
                   ts_headline('english', m.body, q.tsq) AS snippet,
                   GREATEST(ts_rank(m.body_tsv, q.tsq), ts_rank(to_tsvector('english', t.subject), q.tsq)) AS rank
            FROM email_threads t
            JOIN email_messages m ON m.thread_id = t.id
            CROSS JOIN LATERAL (SELECT {tsquery_fn}('english', %s) AS tsq) q
            WHERE (m.body_tsv @@ q.tsq OR to_tsvector('english', t.subject) @@ q.tsq)
              AND t.access_tier::text = ANY(%s)
    """
    params = [query, clearance]
    if account != "all":
        sql += " AND t.source_account = %s"
        params.append(account)
    sql += " ORDER BY t.id, rank DESC) ranked ORDER BY rank DESC LIMIT 20"
    return db_query(sql, params)


def search_emails(query, account="all", clearance=FULL_CLEARANCE):
    """Two-tier search (added 2026-09-08, replacing a single strict-AND
    query): plainto_tsquery treats a multi-word query as an implicit AND of
    every term, so a query naming several entities at once (e.g. "Tripp
    Collier PS Data information") required all four words to co-occur in
    one message body -- correctly returning [] when no thread happened to
    contain every term, even though threads existed that were obviously the
    right answer to a human (one had "PS Data" without "Collier", another
    had "Collier"/"Tripp" repeatedly without "PS Data"). Real fix for that
    class of query is wiki-first retrieval (search_wiki, which resolves
    entities via synthesis+citations, not brute-force co-occurrence) -- this
    two-tier fallback just makes raw keyword search itself less brittle when
    it IS the right tool:
      1. AND match (plainto_tsquery) against body OR subject, ranked by
         ts_rank -- subject was previously never matched at all, only
         selected for display, so a thread titled exactly right but not
         restating the query in its body was invisible to search.
      2. Only if (1) returns nothing: OR match (any term matches), built via
         websearch_to_tsquery (tolerant of stray punctuation, unlike
         to_tsquery which requires strict tsquery syntax) over the query
         terms joined with " or " -- still ranked, so a multi-entity query
         degrades to its best partial match instead of silently returning
         zero results.
    Previously also had no ORDER BY at all with a LIMIT 20 -- meaning a
    real match could be silently dropped past the cutoff by arbitrary scan
    order even when it WAS found. Both tiers now rank by ts_rank."""
    results = _search_emails_query("plainto_tsquery", query, account, clearance)
    if not results:
        or_query = " or ".join(query.split())
        results = _search_emails_query("websearch_to_tsquery", or_query, account, clearance)
    return results


def get_email(identifier, clearance=FULL_CLEARANCE):
    """identifier: the row's numeric id (from a search/list result -- REQUIRED for
    API-ingested threads, which always have a NULL source_file_path) or a legacy
    source_file_path string (only ever set for the historical file-based load).
    A thread outside the caller's clearance returns the same "not found" as a
    thread that doesn't exist -- no separate "exists but restricted" message,
    so a general-clearance caller can't use this to confirm a tier1 thread's
    existence."""
    if str(identifier).isdigit():
        thread = db_query_one(
            "SELECT * FROM email_threads WHERE id = %s AND access_tier::text = ANY(%s)", (int(identifier), clearance)
        )
    else:
        thread = db_query_one(
            "SELECT * FROM email_threads WHERE source_file_path = %s AND access_tier::text = ANY(%s)",
            (identifier, clearance),
        )
    if not thread:
        return {"error": f"no email thread matching '{identifier}'"}
    thread["messages"] = db_query(
        "SELECT message_index, message_date, from_addr, body FROM email_messages WHERE thread_id = %s ORDER BY message_index",
        (thread["id"],),
    )
    thread["attachments"] = db_query(
        """SELECT id, message_id, filename, mimetype, size_bytes,
                  (extracted_text IS NOT NULL) AS text_extracted
           FROM email_attachments WHERE thread_id = %s ORDER BY message_id""",
        (thread["id"],),
    )
    return thread


DEFAULT_ATTACHMENT_RETURN_CHARS = 50000  # bounds a single call's response, not what's stored --
# ingestion/attachment_extract.py stores the complete extracted text unconditionally. A caller
# that needs more than one default-sized page uses offset (generic) or sheet (xlsx-specific,
# see the "--- sheet: X ---" markers _extract_xlsx writes) to get the rest, rather than the
# whole file blowing out its own context in one call every time, on every attachment, regardless
# of size. See the 2026-09-10 MAX_EXTRACT_CHARS incident this replaced for why storage-time
# truncation is the wrong layer for this: it silently drops later sheets forever, unrecoverably,
# rather than just requiring a second call to reach them.


def _xlsx_sheet_names(text):
    return re.findall(r"^--- sheet: (.*?) ---$", text, re.MULTILINE)


def get_attachment_text(attachment_id, sheet="", offset=0, max_chars=DEFAULT_ATTACHMENT_RETURN_CHARS, clearance=FULL_CLEARANCE):
    """Returns the extracted text for one email attachment, by the 'id' from
    get_email's attachments list. Attachments have no access_tier column of
    their own -- enforced via a join to the parent thread's access_tier
    instead, same defense-in-depth pattern used everywhere a child row is
    only ever reachable through a parent that already checks tier.
    extracted_text is NULL for formats extraction doesn't support (only pdf/
    docx/xlsx/csv are covered) -- callers should check get_email's
    text_extracted flag first rather than assume every attachment has text.

    sheet: for xlsx attachments, return just that one sheet's rows (exact
    title match against the sheet tabs in the original file) instead of the
    whole workbook -- the natural unit to ask for, and immune to offset math
    landing mid-row. Ignored for non-xlsx formats.

    offset/max_chars: generic pagination over the full extracted_text for
    everything else (or for xlsx when no sheet is given) -- response notes
    whether there's more and, if so, the offset to pass next."""
    row = db_query_one(
        """SELECT a.filename, a.mimetype, a.extracted_text
           FROM email_attachments a JOIN email_threads t ON t.id = a.thread_id
           WHERE a.id = %s AND t.access_tier::text = ANY(%s)""",
        (attachment_id, clearance),
    )
    if not row:
        return {"error": f"no attachment matching id={attachment_id}"}
    text = row["extracted_text"]
    if text is None:
        return {"error": f"no extracted text available for attachment '{row['filename']}' "
                          "(unsupported format, or ingested before extraction was added)"}

    sheet_names = _xlsx_sheet_names(text)

    if sheet:
        m = re.search(
            rf"^--- sheet: {re.escape(sheet)} ---$\n(.*?)(?=^--- sheet:|\Z)",
            text, re.MULTILINE | re.DOTALL,
        )
        if not m:
            return {"error": f"no sheet named {sheet!r} in this attachment",
                    "available_sheets": sheet_names or None}
        section = m.group(1)
        return {"filename": row["filename"], "mimetype": row["mimetype"], "sheet": sheet,
                "extracted_text": section, "total_chars": len(section)}

    total_chars = len(text)
    chunk = text[offset:offset + max_chars]
    result = {"filename": row["filename"], "mimetype": row["mimetype"],
              "extracted_text": chunk, "offset": offset, "total_chars": total_chars}
    if offset + len(chunk) < total_chars:
        result["truncated"] = True
        result["next_offset"] = offset + len(chunk)
    if sheet_names:
        result["available_sheets"] = sheet_names
    return result


def list_calls(month="", date="", source="", clearance=FULL_CLEARANCE):
    """date: optional 'YYYY-MM-DD' for day-level filtering (added 2026-09-08,
    same reasoning as list_emails's date param -- call_date is a plain date
    column here, so this is a straight equality check, no unnest needed)."""
    sql = "SELECT id, source, meeting_title, call_date, participants, source_file_path FROM call_transcripts WHERE access_tier::text = ANY(%s)"
    params = [clearance]
    if source:
        sql += " AND source = %s"
        params.append(source)
    if date:
        sql += " AND call_date = %s"
        params.append(date)
    elif month:
        sql += " AND to_char(call_date, 'YYYY-MM') = %s"
        params.append(month)
    sql += " ORDER BY call_date DESC NULLS LAST LIMIT 100"
    return db_query(sql, params)


def _search_calls_query(tsquery_fn, query, source, clearance):
    sql = f"""
        SELECT id, source, meeting_title, call_date, source_file_path, snippet, rank FROM (
            SELECT DISTINCT ON (c.id) c.id, c.source, c.meeting_title, c.call_date, c.source_file_path,
                   ts_headline('english', c.transcript_body, q.tsq) AS snippet,
                   GREATEST(ts_rank(c.transcript_tsv, q.tsq), ts_rank(to_tsvector('english', c.meeting_title), q.tsq)) AS rank
            FROM call_transcripts c
            CROSS JOIN LATERAL (SELECT {tsquery_fn}('english', %s) AS tsq) q
            WHERE (c.transcript_tsv @@ q.tsq OR to_tsvector('english', c.meeting_title) @@ q.tsq)
              AND c.access_tier::text = ANY(%s)
    """
    params = [query, clearance]
    if source:
        sql += " AND c.source = %s"
        params.append(source)
    # Rank first (a strong match shouldn't be pushed out by LIMIT), recency as
    # tiebreak within similar relevance -- "the most recent call about X" needs
    # both: pure call_date ordering (the old behavior) could drop the single
    # best-matching call past LIMIT 20 behind irrelevant-but-newer calls that
    # also happen to satisfy the AND query.
    sql += " ORDER BY c.id, rank DESC) ranked ORDER BY rank DESC, call_date DESC NULLS LAST LIMIT 20"
    return db_query(sql, params)


def search_calls(query, source="", clearance=FULL_CLEARANCE):
    """Two-tier search (added 2026-09-08, same fix as search_emails): ranked
    AND match against transcript body OR meeting_title (title was previously
    selected but never matched against), falling back to a ranked OR match
    only when AND finds nothing. Previously ordered purely by call_date DESC
    with no relevance ranking at all -- a real match could be pushed past
    LIMIT 20 by newer, less-relevant calls."""
    results = _search_calls_query("plainto_tsquery", query, source, clearance)
    if not results:
        or_query = " or ".join(query.split())
        results = _search_calls_query("websearch_to_tsquery", or_query, source, clearance)
    return results


def get_call(identifier, clearance=FULL_CLEARANCE):
    """identifier: the row's numeric id (from a search/list result -- REQUIRED for
    API-ingested calls, i.e. every Fireflies/Fathom call, which always have a NULL
    source_file_path) or a legacy source_file_path string (only ever set for the
    historical file-based load). Same not-found-vs-restricted non-disclosure as
    get_email."""
    if str(identifier).isdigit():
        call = db_query_one(
            "SELECT * FROM call_transcripts WHERE id = %s AND access_tier::text = ANY(%s)", (int(identifier), clearance)
        )
    else:
        call = db_query_one(
            "SELECT * FROM call_transcripts WHERE source_file_path = %s AND access_tier::text = ANY(%s)",
            (identifier, clearance),
        )
    if not call:
        return {"error": f"no call matching '{identifier}'"}
    call["segments"] = db_query(
        "SELECT segment_order, speaker, text FROM call_segments WHERE call_id = %s ORDER BY segment_order",
        (call["id"],),
    )
    return call


def list_assets(clearance=FULL_CLEARANCE):
    return db_query(
        "SELECT id, slug, title, access_tier, updated_at FROM assets WHERE access_tier::text = ANY(%s) ORDER BY title",
        (clearance,),
    )


def search_assets(query, clearance=FULL_CLEARANCE):
    """Trigram-similarity-ranked (pg_trgm), not full-text -- like
    search_implementation_tasks, this table has no tsvector column (a
    handful of long documents, not worth the machinery full-text search on
    emails/calls/wiki needs). 2026-08-14: switched from a flat ILIKE list to
    similarity()-scored ranking specifically so a vague/approximate
    reference (e.g. "AI Joe product SOP" when no asset is literally titled
    that) returns a real confidence signal -- match_score -- instead of an
    unordered list with no way to tell a strong match from a coincidental
    one. A body ILIKE hit (the document merely CONTAINS the query
    somewhere) adds a small, fixed bonus (+0.15, capped at 1.0) on top of
    title similarity rather than replacing it -- an earlier version used a
    flat floor instead of a bonus, which flattened every body-containing
    document to the identical score for a short/generic query (e.g. "SOP"
    matched 10 of 15 documents' bodies, all tying at the floor value) and
    lost real, meaningful ranking differences between them. The additive
    form keeps documents with the term actually IN THE TITLE ranked above
    ones that merely mention it somewhere in a long body."""
    return db_query(
        """SELECT id, slug, title, access_tier,
                  round(LEAST(1.0, similarity(title, %s) + CASE WHEN body ILIKE %s THEN 0.15 ELSE 0 END)::numeric, 3) AS match_score
           FROM assets
           WHERE access_tier::text = ANY(%s)
             AND (similarity(title, %s) > 0.1 OR body ILIKE %s)
           ORDER BY match_score DESC LIMIT 20""",
        (query, f"%{query}%", clearance, query, f"%{query}%"),
    )


def get_asset(identifier, clearance=FULL_CLEARANCE):
    """identifier: the row's numeric id, or its slug (from list_assets/
    search_assets, or wiki_pages.sources_raw / wiki_citations.source_ref_raw
    on any wiki page citing this document) -- either works. Unlike
    get_email/get_call there's no legacy source_file_path lookup path;
    this table has no historical file-based load, only the one-time
    import from raj-wiki-vault (see ingestion/import_assets.py)."""
    if str(identifier).isdigit():
        row = db_query_one("SELECT * FROM assets WHERE id = %s AND access_tier::text = ANY(%s)", (int(identifier), clearance))
    else:
        row = db_query_one("SELECT * FROM assets WHERE slug = %s AND access_tier::text = ANY(%s)", (identifier, clearance))
    if row:
        row["change_history"] = db_query(
            "SELECT changed_by, change_type, occurred_at FROM asset_change_log "
            "WHERE asset_id = %s ORDER BY occurred_at DESC",
            (row["id"],),
        )
    if not row:
        return {"error": f"no asset matching '{identifier}'"}
    return row


def list_clients():
    return db_query("SELECT id, slug, display_name, domains, odoo_base_url FROM clients ORDER BY display_name")


def list_contacts(client=""):
    sql = """
        SELECT c.name, c.email, c.is_relay_inbox, cl.slug AS client
        FROM contacts c JOIN clients cl ON cl.id = c.client_id
        WHERE 1=1
    """
    params = []
    if client:
        sql += " AND cl.slug = %s"
        params.append(client)
    sql += " ORDER BY cl.display_name, c.name"
    return db_query(sql, params)


def get_client_profile(client, clearance=FULL_CLEARANCE):
    """Aggregates everything linked to one client by client_id in a single
    call -- every raw table (email_threads, call_transcripts,
    implementation_tasks) has a client_id column, but every other tool
    here only searches ONE of them at a time, so answering something like
    "give me everything on client X" required chaining several separate
    tool calls with no guarantee the caller actually would. This is the
    single-call alternative: client record, contacts, and recent-activity
    summaries across every source, cross-linked by client_id -- not
    exhaustive detail (use get_email/get_call/get_implementation_task for
    that), but enough to see the whole relationship at a glance and know
    what to drill into. Every recent-activity list and count below is
    clearance-filtered the same as the dedicated list_*/search_* tools --
    a general-clearance caller sees fewer tasks/emails/calls and lower
    counts for this client, not an error.

    2026-08-10: support tickets and invoices/sales orders removed from
    this system entirely (now sourced live from EOXS Teams Odoo via a
    separate connector, faster to query there directly) -- no
    ticket/sales_order fields here anymore.

    NOTE on scope: only searches LIVE tables. Synthesized wiki content for
    this client may exist in wiki_staging (reviewed, not yet promoted) --
    that's flagged by staging_wiki_pages_pending_promotion below (a count
    and titles only, not body content -- staging is not part of this
    read-only server's live-data contract) so the caller knows to ask a
    human to check staging or promote first, rather than concluding no
    wiki content exists.
    """
    row = db_query_one("SELECT id, slug, display_name, domains, odoo_base_url, odoo_db FROM clients WHERE slug = %s", (client,))
    if not row:
        row = db_query_one("SELECT id, slug, display_name, domains, odoo_base_url, odoo_db FROM clients WHERE display_name ILIKE %s", (f"%{client}%",))
    if not row:
        return {"error": f"no client matching '{client}' -- see list_clients for valid slugs"}
    client_id = row["id"]

    row["contacts"] = db_query(
        "SELECT name, email, is_relay_inbox FROM contacts WHERE client_id = %s ORDER BY name", (client_id,)
    )
    row["implementation_tasks_recent"] = db_query(
        """SELECT task_name, stage, owner, task_created_date
           FROM implementation_tasks WHERE client_id = %s AND access_tier::text = ANY(%s) ORDER BY task_created_date DESC NULLS LAST LIMIT 20""",
        (client_id, clearance),
    )
    row["implementation_task_count"] = db_query_one(
        "SELECT count(*) AS n FROM implementation_tasks WHERE client_id = %s AND access_tier::text = ANY(%s)", (client_id, clearance)
    )["n"]
    row["emails_recent"] = db_query(
        """SELECT id, source_account, subject FROM email_threads
           WHERE client_id = %s AND access_tier::text = ANY(%s) ORDER BY id DESC LIMIT 20""",
        (client_id, clearance),
    )
    row["email_count"] = db_query_one(
        "SELECT count(*) AS n FROM email_threads WHERE client_id = %s AND access_tier::text = ANY(%s)", (client_id, clearance)
    )["n"]
    row["calls_recent"] = db_query(
        """SELECT id, source, meeting_title, call_date FROM call_transcripts
           WHERE client_id = %s AND access_tier::text = ANY(%s) ORDER BY call_date DESC NULLS LAST LIMIT 20""",
        (client_id, clearance),
    )
    row["call_count"] = db_query_one(
        "SELECT count(*) AS n FROM call_transcripts WHERE client_id = %s AND access_tier::text = ANY(%s)", (client_id, clearance)
    )["n"]
    row["live_wiki_pages"] = db_query(
        "SELECT title, page_type FROM wiki_pages WHERE title ILIKE %s AND access_tier::text = ANY(%s) ORDER BY title",
        (f"%{row['display_name']}%", clearance),
    )
    staging_pending = db_query(
        """SELECT title, page_type, status FROM wiki_staging.wiki_pages
           WHERE title ILIKE %s AND status = 'reviewed' ORDER BY title""",
        (f"%{row['display_name']}%",),
    )
    row["staging_wiki_pages_pending_promotion"] = {
        "count": len(staging_pending),
        "titles": [p["title"] for p in staging_pending],
        "note": "Reviewed but not yet promoted to live wiki_pages -- ask a human to promote, or query wiki_staging directly for full content.",
    }
    return row


def get_client_file(file_path, clearance=FULL_CLEARANCE):
    for table in ("call_transcripts",):
        row = db_query_one(f"SELECT * FROM {table} WHERE source_file_path = %s AND access_tier::text = ANY(%s)", (file_path, clearance))
        if row:
            row.pop("transcript_tsv", None)
            return row
    row = db_query_one("SELECT * FROM wiki_pages WHERE source_file_path = %s AND access_tier::text = ANY(%s)", (file_path, clearance))
    if row:
        row.pop("body_tsv", None)
        return row
    return {"error": f"no row found for file_path '{file_path}' in any loaded table"}


def list_implementation_tasks(client="", stage="", date="", clearance=FULL_CLEARANCE):
    """date: optional 'YYYY-MM-DD', matched against task_created_date OR
    task_updated_date OR deadline (added 2026-09-08) -- this table has three
    date columns and no single obvious one a day-filtered query means, so a
    match against any of them is the safer default over silently picking one."""
    sql = """
        SELECT it.id, c.slug AS client, it.project_name, it.task_name, it.stage, it.owner,
               it.priority, it.kanban_state, it.active, it.task_created_date, it.task_updated_date, it.deadline
        FROM implementation_tasks it JOIN clients c ON c.id = it.client_id
        WHERE it.access_tier::text = ANY(%s)
    """
    params = [clearance]
    if client:
        sql += " AND c.slug = %s"
        params.append(client)
    if stage:
        sql += " AND it.stage = %s"
        params.append(stage)
    if date:
        sql += " AND (it.task_created_date = %s OR it.task_updated_date = %s OR it.deadline = %s)"
        params.extend([date, date, date])
    sql += " ORDER BY it.task_created_date DESC NULLS LAST LIMIT 100"
    return db_query(sql, params)


def _search_implementation_tasks_query(tsquery_fn, query, client, clearance):
    # implementation_tasks.task_tsv (schema/037_implementation_tasks_tsv.sql,
    # 2026-09-08) -- a real stored generated column + GIN index, same pattern
    # as email_messages.body_tsv/call_transcripts.transcript_tsv. Safe to add
    # now that ingestion/write_implementation.py upserts on (client_id,
    # odoo_task_id) instead of the full DELETE+INSERT this table used before
    # (see that module's docstring) -- id and any derived/stored column
    # survive a refresh.
    sql = f"""
        SELECT id, client, task_name, stage, owner, priority, task_created_date, snippet, rank FROM (
            SELECT DISTINCT ON (it.id) it.id, c.slug AS client, it.task_name, it.stage, it.owner, it.priority,
                   it.task_created_date,
                   ts_headline('english', coalesce(it.description, ''), q.tsq) AS snippet,
                   ts_rank(it.task_tsv, q.tsq) AS rank
            FROM implementation_tasks it JOIN clients c ON c.id = it.client_id
            CROSS JOIN LATERAL (SELECT {tsquery_fn}('english', %s) AS tsq) q
            WHERE it.task_tsv @@ q.tsq AND it.access_tier::text = ANY(%s)
    """
    params = [query, clearance]
    if client:
        sql += " AND c.slug = %s"
        params.append(client)
    sql += " ORDER BY it.id, rank DESC) ranked ORDER BY rank DESC, task_created_date DESC NULLS LAST LIMIT 20"
    return db_query(sql, params)


def search_implementation_tasks(query, client="", clearance=FULL_CLEARANCE):
    """Two-tier tsvector search (added 2026-09-08, replacing whole-phrase
    ILIKE '%query%' against task_name/description). The old version was
    strictly worse than the email/call full-text bugs it mirrors: ILIKE on
    the entire raw query string requires those exact words in that exact
    order and adjacency to appear literally, so a multi-word query naming
    several things (e.g. "Tripp Collier PS Data information") would almost
    never match anything, even a task whose name/description contained all
    the same words in a different order. Now word-level AND (ranked, via
    task_tsv), with an OR fallback tier, same as search_emails/search_calls."""
    results = _search_implementation_tasks_query("plainto_tsquery", query, client, clearance)
    if not results:
        or_query = " or ".join(query.split())
        results = _search_implementation_tasks_query("websearch_to_tsquery", or_query, client, clearance)
    return results


def get_implementation_task(task_id, clearance=FULL_CLEARANCE):
    """Looks up by the serial `id` first, falling back to `odoo_task_id`.
    `id` IS stable now (ingestion/write_implementation.py upserts on
    (client_id, odoo_task_id) rather than the full DELETE+INSERT this table
    used before -- see that module's docstring), so the fallback mainly
    matters for citations/references written while the old full-refresh
    behavior was still live, or wherever odoo_task_id is the only id at
    hand (e.g. a wiki_citations row, which always stores odoo_task_id, per
    docs/wiki-ingestion.md §4). The two id spaces don't overlap (id: 15000s+,
    odoo_task_id: under 1000, verified empirically), so trying `id` first is
    unambiguous and doesn't change behavior for any existing caller passing
    a real id.

    NOTE: odoo_task_id collides across different clients (the same task
    number can exist for multiple clients' Odoo instances) -- this lookup
    doesn't disambiguate by client, matching existing behavior (first
    match wins). Same caveat applies to wiki citations that reference
    odoo_task_id; not fixed here."""
    task = db_query_one(
        """SELECT it.*, c.slug AS client_slug, c.display_name AS client_name
           FROM implementation_tasks it JOIN clients c ON c.id = it.client_id
           WHERE it.id = %s AND it.access_tier::text = ANY(%s)""",
        (task_id, clearance),
    )
    if not task:
        task = db_query_one(
            """SELECT it.*, c.slug AS client_slug, c.display_name AS client_name
               FROM implementation_tasks it JOIN clients c ON c.id = it.client_id
               WHERE it.odoo_task_id = %s AND it.access_tier::text = ANY(%s)""",
            (task_id, clearance),
        )
    if not task:
        return {"error": f"no implementation task with id or odoo_task_id={task_id}"}
    task["events"] = db_query(
        """SELECT event_order, event_type, author, event_time, body, tracking_changes
           FROM implementation_task_events WHERE task_id = %s ORDER BY event_order""",
        (task["id"],),
    )
    task["attachments"] = db_query(
        "SELECT filename, mimetype, size_bytes FROM implementation_task_attachments WHERE task_id = %s",
        (task["id"],),
    )
    return task


# Tools that take a clearance kwarg -- everything else (wiki, clients, contacts)
# is untiered (list_clients/list_contacts -- no access_tier column at all).
TIER_FILTERED_TOOLS = {
    "get_index", "get_wiki_page", "search_wiki", "list_emails", "search_emails", "get_email", "get_attachment_text",
    "list_calls", "search_calls", "get_call",
    "list_assets", "search_assets", "get_asset",
    "get_client_profile", "get_client_file", "list_implementation_tasks", "search_implementation_tasks",
    "get_implementation_task",
    "list_repo_docs", "search_repo_docs", "get_repo_doc",
}

# 2026-08-14: every tool call in this set gets an unmissable "_environment"
# field stamped onto its result (see call_tool() below) -- real, live
# confusion this fixes: a caller connected to `staging_qa` with no skill
# file attached (so no prompt-level context telling it this was the
# sandbox) reasoned from nothing but its own caution that it must be on
# live, and nearly asked the user to approve a write it believed would hit
# production -- it never actually wrote anything (verified directly against
# both databases afterward), but the *belief* was wrong, and every prior
# tool result gave it zero factual basis to know better. Every OTHER tool
# in this server is silent about which database it hit, by original design
# (skill files were meant to carry that context) -- this stamp exists
# specifically on the write path, where getting this wrong has real stakes,
# so a model never has to trust an attached skill file (easy to omit or
# mismatch) over the ground truth the server itself already knows.
WRITE_TOOL_NAMES = EMPLOYEE_WRITE_TOOLS | set(ASSET_WRITE_TOOLS)

TOOLS = {
    "get_index": get_index,
    "get_wiki_page": get_wiki_page,
    "search_wiki": search_wiki,
    "list_emails": list_emails,
    "search_emails": search_emails,
    "get_email": get_email,
    "get_attachment_text": get_attachment_text,
    "list_calls": list_calls,
    "search_calls": search_calls,
    "get_call": get_call,
    "list_assets": list_assets,
    "search_assets": search_assets,
    "get_asset": get_asset,
    "list_clients": list_clients,
    "list_contacts": list_contacts,
    "get_client_profile": get_client_profile,
    "get_client_file": get_client_file,
    "list_implementation_tasks": list_implementation_tasks,
    "search_implementation_tasks": search_implementation_tasks,
    "get_implementation_task": get_implementation_task,
    **REPO_DOCS_TOOLS,
}


def _tool_defs(enable_employee_tools=False, asset_write_scope=None):
    defs = [
        Tool(
            name="get_index",
            description="Return row counts across all tables — the DB equivalent of the wiki index.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="get_wiki_page",
            description="Return a specific wiki page by title or partial match, with a body preview (first "
                        f"{BODY_PREVIEW_CHARS} chars, plus body_length/body_truncated), outbound links, flags, "
                        "and citations (the raw sources this page was drafted from — each has fetch_tool/"
                        "fetch_identifier, e.g. get_email/66376, to pull the exact source record directly). "
                        "ALWAYS try this or search_wiki BEFORE a raw search_emails/search_calls/search_assets/"
                        "search_implementation_tasks call — a synthesized page's citations point straight at "
                        "the right raw thread/call/asset/task, avoiding a blind keyword search across all raw "
                        "data. Fall back to raw search only when the wiki has nothing relevant. "
                        "Full body is large — this intentionally previews rather than dumping the whole page.",
            inputSchema={"type": "object", "properties": {"title": {"type": "string"}}, "required": ["title"]},
        ),
        Tool(
            name="search_wiki",
            description="Full-text search synthesized wiki pages (entities, concepts, analyses, overviews, "
                        "sources, prospects). Each result includes 'id' (chain into get_wiki_page or reuse "
                        "directly) and 'citations' (raw sources this page cites, each with fetch_tool/"
                        "fetch_identifier — e.g. get_email/66376 — to pull the exact record). "
                        "THE FIRST TOOL TO TRY for almost any content question, including ones that sound like "
                        "raw-source lookups (\"find the email about X\", \"what did we discuss on the call "
                        "about Y\") — a wiki page's citations resolve entity/topic queries far more reliably "
                        "than full-text keyword search against raw emails/calls/tasks, which can miss the "
                        "right thread entirely if it doesn't happen to contain every query word. Only fall "
                        "back to search_emails/search_calls/search_assets/search_implementation_tasks directly "
                        "when this returns nothing relevant.",
            inputSchema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        ),
        Tool(
            name="list_emails",
            description="List email threads. account: 'all'|'raj_gmail'|'ron_gmail'|'remya_gmail'|'support_zoho'. "
                        "date: 'YYYY-MM-DD' for a specific day, month: 'YYYY-MM' for a whole month (date takes "
                        "precedence if both given), or leave both empty for the most recent 100 threads. "
                        "Try search_wiki first if the query names a topic/person/company rather than just a date.",
            inputSchema={"type": "object", "properties": {
                "account": {"type": "string", "default": "all"}, "month": {"type": "string", "default": ""},
                "date": {"type": "string", "default": ""}}},
        ),
        Tool(
            name="search_emails",
            description="Full-text search raw email message bodies. account filter same as list_emails.",
            inputSchema={"type": "object", "properties": {
                "query": {"type": "string"}, "account": {"type": "string", "default": "all"}}, "required": ["query"]},
        ),
        Tool(
            name="get_email",
            description="Return a full email thread (all messages) by the 'id' from a list_emails/search_emails "
                        "result. Also accepts a legacy source_file_path string, but every live-ingested (Gmail/"
                        "Zoho) thread has a NULL source_file_path -- use 'id' for those, which is always present.",
            inputSchema={"type": "object", "properties": {"identifier": {"type": "string"}}, "required": ["identifier"]},
        ),
        Tool(
            name="get_attachment_text",
            description="Return the extracted text content of one email attachment, by the 'id' from get_email's "
                        "attachments list. Only pdf/docx/xlsx/csv attachments have extracted text -- check "
                        "get_email's text_extracted flag on the attachment first. The full text is always "
                        "stored, but one call returns at most 50000 characters by default -- for a large "
                        "attachment, the response includes 'available_sheets' (xlsx workbooks) and/or "
                        "'truncated'+'next_offset' (anything else) so you know there's more and how to get it. "
                        "Pass 'sheet' with an exact tab name from 'available_sheets' to get just that sheet "
                        "(xlsx only, preferred over offset math since it can't land mid-row); pass 'offset' "
                        "(from a prior response's 'next_offset') to page through sequentially otherwise.",
            inputSchema={"type": "object", "properties": {
                "attachment_id": {"type": "string"},
                "sheet": {"type": "string", "default": "", "description": "exact xlsx sheet tab name, from a prior response's available_sheets"},
                "offset": {"type": "integer", "default": 0, "description": "character offset to resume from, from a prior response's next_offset"},
                "max_chars": {"type": "integer", "default": 50000, "description": "max characters to return in this call"},
            }, "required": ["attachment_id"]},
        ),
        Tool(
            name="list_calls",
            description="List call transcripts. source: 'fireflies'|'fathom' or omit for both. month: 'YYYY-MM' or empty.",
            inputSchema={"type": "object", "properties": {
                "month": {"type": "string", "default": ""}, "source": {"type": "string", "default": ""}}},
        ),
        Tool(
            name="search_calls",
            description="Full-text search call transcripts. source: 'fireflies'|'fathom' or omit for both — use this to answer e.g. 'latest Fathom calls'.",
            inputSchema={"type": "object", "properties": {
                "query": {"type": "string"}, "source": {"type": "string", "default": ""}}, "required": ["query"]},
        ),
        Tool(
            name="get_call",
            description="Return a full call transcript (all speaker segments) by the 'id' from a list_calls/"
                        "search_calls result. Also accepts a legacy source_file_path string, but every "
                        "live-ingested (Fireflies/Fathom) call has a NULL source_file_path -- use 'id' for "
                        "those, which is always present.",
            inputSchema={"type": "object", "properties": {"identifier": {"type": "string"}}, "required": ["identifier"]},
        ),
        Tool(
            name="list_assets",
            description="List curated internal reference documents (SOPs, company overview, ICP, salary "
                        "register, product-feature specs, technical references) -- the raw source behind wiki "
                        "pages under wiki/sources/assets/. Title/id/slug only, not full body -- use get_asset "
                        "for that.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="search_assets",
            description="Search internal reference documents by title (fuzzy/approximate match, ranked) or "
                        "body content (substring). Results are sorted by 'match_score' (0-1, title-similarity "
                        "based) -- a clear top score well above the rest means a confident match; several "
                        "close scores means genuine ambiguity between documents. Use list_assets for the full "
                        "catalog instead.",
            inputSchema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        ),
        Tool(
            name="get_asset",
            description="Return the full raw text of one internal reference document by its numeric 'id' "
                        "(from list_assets/search_assets) or its 'slug' (also the value in a citing wiki page's "
                        "sources_raw). This is the actual source document — the corresponding wiki page under "
                        "wiki/sources/assets/ is a synthesized summary, not the raw text; use this tool when the "
                        "full original wording matters (e.g. exact SOP steps, exact salary figures).",
            inputSchema={"type": "object", "properties": {"identifier": {"type": "string"}}, "required": ["identifier"]},
        ),
        Tool(
            name="list_clients",
            description="List all clients in the registry (slug, display name, domains, Odoo instance).",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="list_contacts",
            description="List known contacts (name, email) for a client, or all clients if omitted. "
                        "client: client slug (e.g. 'sabre-alloys') or empty for all.",
            inputSchema={"type": "object", "properties": {"client": {"type": "string", "default": ""}}},
        ),
        Tool(
            name="get_client_profile",
            description="THE tool for 'tell me everything about client X' -- aggregates the client record, "
                        "contacts, recent implementation tasks, recent emails, recent calls, and "
                        "live+pending-promotion wiki pages, all cross-linked by client_id in one call. Prefer "
                        "this over chaining separate search_* calls for a client overview; use the individual "
                        "get_email/get_call/get_implementation_task tools to drill into any one item this "
                        "surfaces. Support tickets and invoices/sales orders are not in this system -- query "
                        "EOXS Teams Odoo directly for those. client: slug (e.g. 'sabre-alloys') or a "
                        "display-name substring.",
            inputSchema={"type": "object", "properties": {"client": {"type": "string"}}, "required": ["client"]},
        ),
        Tool(
            name="get_client_file",
            description="Return a row from any loaded table by its original source_file_path (call transcript or wiki page).",
            inputSchema={"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]},
        ),
        Tool(
            name="list_implementation_tasks",
            description="List Odoo implementation Kanban tasks (client onboarding/dev tasks -- distinct from support tickets). "
                        "client: client slug (e.g. 'greer-steel') or empty for all. stage: exact stage name (e.g. 'Completed') or empty for all.",
            inputSchema={"type": "object", "properties": {
                "client": {"type": "string", "default": ""}, "stage": {"type": "string", "default": ""}}},
        ),
        Tool(
            name="search_implementation_tasks",
            description="Full-text search Odoo implementation Kanban tasks by task name or description. "
                        "client: client slug to restrict to one client, or empty for all.",
            inputSchema={"type": "object", "properties": {
                "query": {"type": "string"}, "client": {"type": "string", "default": ""}}, "required": ["query"]},
        ),
        Tool(
            name="get_implementation_task",
            description="Return a full implementation task (description, stage/owner/priority, all chatter events "
                        "including stage-change history, and attachment metadata) by its numeric id from a "
                        "list/search_implementation_tasks result.",
            inputSchema={"type": "object", "properties": {"task_id": {"type": "integer"}}, "required": ["task_id"]},
        ),
    ] + repo_docs_tool_defs()
    if enable_employee_tools:
        defs = defs + employee_tool_defs()
    if asset_write_scope == "all":
        defs = defs + [create_asset_tool_def(), update_asset_tool_def()]
    elif asset_write_scope is not None:
        defs = defs + [update_asset_tool_def()]
    return defs


def build_server(clearance, name="eoxs-wiki-db", extra_redact_categories=(), enable_employee_tools=False,
                  identity_name=None, asset_write_scope=None, database=None):
    """Builds a fresh Server instance whose tier-filtered tools are all
    bound to `clearance`. Each identity (stdio/local, or one HTTP/SSE
    secret path) gets its OWN Server instance from this -- clearance is
    baked in at construction time via functools.partial, never read from
    a request, so nothing an MCP client sends can change which rows it
    can see.

    extra_redact_categories: passed straight through to every
    redaction.check_and_redact() call for this identity -- content-based
    restrictions with no access_tier equivalent (e.g. the intern
    identity's "no monetary amounts", same row-level access as
    GENERAL_CLEARANCE otherwise). See mcp_server/redaction.py.

    enable_employee_tools: gates the ENTIRE employees.py tool set (read
    and write alike) onto this identity -- deliberately not tied to
    `clearance` at all, since employees has no access_tier and 'general'
    shares HR_CLEARANCE's clearance list with 'hr' for other tools but
    must NOT get employee access. Only the `full` and `hr` identities pass
    True for this (see http_server.py's IDENTITIES). Write tools
    (EMPLOYEE_WRITE_TOOLS) get `changed_by` bound to identity_name here,
    the same construction-time-binding pattern as `clearance` -- never
    part of a tool's inputSchema, so a caller can't spoof who made a
    change.

    asset_write_scope: gates mcp_server/asset_writes.py's tools onto this
    identity -- the ONLY other write surface in this server besides
    employees.py, and deliberately the last one (explicit instruction: no
    other table gets a write path). Three states:
      - None (default) -- no asset write tools at all (general/intern).
      - "all" -- both create_asset and update_asset, unrestricted by slug
        (the `full` identity only).
      - any other iterable -- ONLY update_asset, and only for slugs in that
        set (the `hr` identity, bound to {'eoxs-salary-details'} today).
        create_asset is never bound for a restricted scope -- adding a
        brand-new document is a `full`-only action, not something a
        slug-restriction could safely narrow.
    Like `changed_by` above, both `changed_by` and the slug restriction are
    bound here via functools.partial, never taken from the tool call's own
    arguments.

    database: None (default -- live eoxs_wiki, every existing identity) or
    "staging" (routes every query this identity's tools make, read AND
    write, to eoxs_wiki_staging instead -- see mcp_server/db.py's
    use_database()/ContextVar). Used exclusively by the `staging_qa`
    identity (http_server.py), a QA sandbox for testing employee/asset
    write behavior without any risk to live data, and structurally
    invisible to wiki_ingestion (which only ever calls
    ingestion.db.get_live_conn(), never touches eoxs_wiki_staging at all --
    confirmed by grep, zero references anywhere in wiki_ingestion/)."""
    tools = {
        tool_name: (functools.partial(func, clearance=clearance) if tool_name in TIER_FILTERED_TOOLS else func)
        for tool_name, func in TOOLS.items()
    }
    if enable_employee_tools:
        who = identity_name or name
        tools.update({
            tool_name: (functools.partial(func, changed_by=who) if tool_name in EMPLOYEE_WRITE_TOOLS else func)
            for tool_name, func in EMPLOYEE_TOOLS.items()
        })
    if asset_write_scope is not None:
        who = identity_name or name
        tools["update_asset"] = functools.partial(
            ASSET_WRITE_TOOLS["update_asset"], changed_by=who,
            _allowed_slugs=None if asset_write_scope == "all" else frozenset(asset_write_scope),
        )
        if asset_write_scope == "all":
            tools["create_asset"] = functools.partial(ASSET_WRITE_TOOLS["create_asset"], changed_by=who)
    srv = Server(name)

    @srv.list_tools()
    async def list_tools():
        return _tool_defs(enable_employee_tools, asset_write_scope)

    @srv.call_tool()
    async def call_tool(tool_name, arguments):
        if tool_name not in tools:
            return [TextContent(type="text", text=f"Unknown tool: {tool_name}")]
        func = tools[tool_name]
        try:
            with use_database(database):
                result = func(**(arguments or {}))
        except Exception as e:
            result = {"error": f"{type(e).__name__}: {e}"}
        else:
            # Query-time redaction safety net (mcp_server/redaction.py) --
            # a SECOND, independent check on top of the access_tier SQL
            # filtering above, catching cases where the original tier
            # CLASSIFICATION was wrong. Skipped for FULL_CLEARANCE, which
            # has nothing to check against. Never runs on an already-
            # errored result -- nothing to redact from an error message.
            if "tier1" not in clearance:
                result = await redaction.check_and_redact(
                    result, clearance, tool_name, clearance_name=name, extra_categories=extra_redact_categories,
                )
        if tool_name in WRITE_TOOL_NAMES and isinstance(result, dict):
            # Stamped last, after redaction, so it's never at risk of being
            # touched by it -- this field is server-asserted ground truth,
            # not caller-provided or model-generated, and must reach the
            # model unmodified on every single call, success or error alike.
            result["_environment"] = (
                f"STAGING (eoxs_wiki_staging via the '{identity_name or name}' identity) -- "
                "test data. This write is NOT live, will NEVER reach production, and will "
                "NEVER be picked up by wiki-ingestion."
                if database == "staging" else
                f"LIVE (eoxs_wiki via the '{identity_name or name}' identity) -- this write is "
                "real and reaches production."
            )
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    return srv


# Local/stdio access (Claude Code CLI, Claude Desktop) -- full clearance,
# since running this file at all already requires the .env Postgres
# credentials, i.e. trusted-equivalent access with no narrower boundary
# to enforce here. Employee and asset write tools included too, same
# reasoning -- also identity_name="full" so employee_change_log/
# asset_change_log attribute local-access writes the same way the `full`
# HTTP identity's are. The HTTP/SSE transport in http_server.py builds its
# own separate, narrower instance(s) via build_server() instead of using
# this one.
server = build_server(FULL_CLEARANCE, enable_employee_tools=True, identity_name="full", asset_write_scope="all")


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
