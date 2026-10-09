#!/usr/bin/env bash
# Scheduled-job health check for eoxs-wiki-db.
#
# WHY THIS EXISTS: on 2026-08-20 eoxs-wiki-pipeline failed on every single run
# for a full day (the `claude` CLI was missing after the host migration) and
# nothing alerted -- it was found by reading logs by hand. Separately, the
# isha_zoho Zoho 404 sat inside a sweep that *looked* successful, because the
# unit still exited 0. Plain uptime pinging catches neither: the box was up
# and nginx was serving the whole time.
#
# So this checks the two things uptime monitoring cannot:
#   1. DID IT RUN?      -- last activation within the expected window
#   2. DID IT SUCCEED?  -- unit result, plus per-source 'error' entries that
#                          do not fail the unit but do mean data is missing
#
# Exit 0 = healthy, 1 = problem (and prints what). Safe to run any time.
#
# Optional: set HEALTHCHECK_PING_URL to a Healthchecks.io (or equivalent)
# check URL and a healthy run pings it. Miss the ping and they alert you --
# the dead-man's-switch half. Without it this is still useful on its own.
set -uo pipefail

FAIL=0
note() { printf '%s\n' "$*"; }
bad()  { printf 'PROBLEM: %s\n' "$*"; FAIL=1; }

# Max age before we consider a timer to have silently stopped. Deliberately
# ~2x the cadence so ordinary jitter (RandomizedDelaySec) never trips it.
declare -A MAX_AGE_H=( [eoxs-sweep]=5 [eoxs-wiki-pipeline]=13 )

for unit in eoxs-sweep eoxs-wiki-pipeline; do
    if ! systemctl list-unit-files "${unit}.timer" >/dev/null 2>&1; then
        bad "${unit}.timer does not exist"; continue
    fi

    # A disabled timer is reported, not failed: it is disabled deliberately
    # during cut-over (see docs/migration-status.md) and alerting on that
    # would train people to ignore this script.
    if [ "$(systemctl is-enabled "${unit}.timer" 2>/dev/null)" != "enabled" ]; then
        note "NOTE: ${unit}.timer is disabled -- intentional during cut-over, but it is NOT running."
        continue
    fi

    # 1. Did it run recently enough?
    last=$(systemctl show "${unit}.service" -p ExecMainStartTimestamp --value 2>/dev/null)
    if [ -z "$last" ] || [ "$last" = "n/a" ]; then
        bad "${unit} has no record of ever running"
    else
        age_h=$(( ( $(date +%s) - $(date -d "$last" +%s) ) / 3600 ))
        if [ "$age_h" -gt "${MAX_AGE_H[$unit]}" ]; then
            bad "${unit} last ran ${age_h}h ago (expected within ${MAX_AGE_H[$unit]}h) -- timer may have silently stopped"
        else
            note "OK: ${unit} ran ${age_h}h ago"
        fi
    fi

    # 2. Did the last run actually succeed?
    if [ "$(systemctl is-failed "${unit}.service" 2>/dev/null)" = "failed" ]; then
        bad "${unit} last run FAILED -- journalctl -u ${unit}.service -n 50"
    fi
done

# 3. Per-source errors that do NOT fail the unit. The sweep catches a fetcher
#    exception per source and carries on, so the unit exits 0 with an
#    "'error': ..." entry buried in the summary line -- invisible to anything
#    that only checks exit status.
if err=$(journalctl -u eoxs-sweep.service --since '6 hours ago' --no-pager 2>/dev/null \
         | grep -oE "'[a-z_]+': \{'error'[^}]*\}" | head -3) && [ -n "$err" ]; then
    bad "sweep reported per-source errors (unit still exited 0):"
    printf '  %s\n' "$err"
fi

# 4. The services that must always be up.
for svc in eoxs-ingestion eoxs-mcp eoxs-wiki-mcp eoxs-frontend-threads nginx postgresql; do
    [ "$(systemctl is-active "$svc" 2>/dev/null)" = "active" ] || bad "$svc is not active"
done

if [ "$FAIL" -eq 0 ]; then
    note "All checks passed."
    [ -n "${HEALTHCHECK_PING_URL:-}" ] && curl -fsS -m 10 --retry 3 "$HEALTHCHECK_PING_URL" >/dev/null 2>&1
    exit 0
fi
# Deliberately do NOT ping on failure: silence is the alert.
exit 1
