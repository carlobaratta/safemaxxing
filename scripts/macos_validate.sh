#!/usr/bin/env bash
# Collect raw evidence for TESTLOG.md on a real Mac: doctor, a live pf block, a log stream
# sample and the live pytest suite (Tasks 1-4 in TESTLOG.md).
#
#   scripts/macos_validate.sh            # from any directory; asks for sudo once
#
# Needs macOS, `uv` on PATH and an admin account. Interactive: before the log sample it waits
# for Enter on the terminal, then expects Photo Booth and Voice Memos to be opened.
#
# Writes testlogs/<stamp>-macos.log (commit it) and testlogs/<stamp>-sample.jsonl (raw unified
# log, git-ignored; do not publish it).
#
# Env: SAFEMAXXING_LIVE_IP (default 1.1.1.1), SAMPLE_S (log sample seconds, default 15),
#      PF_DISABLED_TEST=1 to `pfctl -d` first and check that `block` re-enables pf.
# The block test adds and always removes one IP in the safemaxxing_block table. The first
# block loads the anchor rule and enables pf; both stay that way afterwards. Root-owned
# .pytest_cache and __pycache__ directories are chowned back to you.
set -u

[[ "$(uname -s)" == Darwin ]] || { echo "needs macOS (Darwin)" >&2; exit 1; }
cd "$(dirname "$0")/.."

UV="$(command -v uv)" || { echo "uv not found" >&2; exit 1; }
PFCTL=/sbin/pfctl
ANCHOR=com.apple/safemaxxing
TABLE=safemaxxing_block
TARGET_IP="${SAFEMAXXING_LIVE_IP:-1.1.1.1}"
SAMPLE_S="${SAMPLE_S:-15}"
PF_DISABLED_TEST="${PF_DISABLED_TEST:-0}"

mkdir -p testlogs
STAMP="$(date +%Y%m%d-%H%M)"
OUT="testlogs/$STAMP-macos.log"
SAMPLE_JSONL="testlogs/$STAMP-sample.jsonl"

run() {
    echo
    echo "\$ $*"
    "$@" 2>&1
    echo "[exit $?]"
}

probe() {  # curl with a short timeout; prints the HTTP code (000 = no connection)
    run curl -sS -o /dev/null -w '%{http_code} in %{time_total}s\n' --max-time 3 "https://$TARGET_IP/"
}

sudo -v || exit 1
# Earlier `sudo pytest` runs leave root-owned caches that break or slow the non-root run.
[[ -d .pytest_cache ]] && sudo chown -R "$(id -un)" .pytest_cache
sudo find src tests -name __pycache__ -user root -exec chown -R "$(id -un)" {} +
was_blocked=0
sudo "$PFCTL" -a "$ANCHOR" -t "$TABLE" -T show 2>/dev/null | grep -qx "[[:space:]]*$TARGET_IP" \
    && was_blocked=1
cleanup() { [[ $was_blocked == 0 ]] && sudo "$UV" run safemaxxing unblock "$TARGET_IP" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

{
    echo "# safemaxxing macOS validation $(date '+%Y-%m-%d %H:%M %z')"
    echo "## Environment"
    run sw_vers
    run uname -m
    run sysctl -n machdep.cpu.brand_string
    run id
    run git rev-parse --abbrev-ref HEAD
    run git rev-parse --short HEAD
    # Catches running stale code after an aborted pull (TESTLOG 2026-10-22 13:50).
    run git status -sb

    echo; echo "## Static checks"
    run "$UV" run ruff format --check .
    run "$UV" run ruff check
    run "$UV" run mypy
    run "$UV" run pytest -q

    echo; echo "## Task 1: doctor (non-root, then root)"
    run "$UV" run safemaxxing doctor
    run sudo "$UV" run safemaxxing doctor

    echo; echo "## Task 2: pf state and anchor before"
    run sudo "$PFCTL" -s info
    run sudo "$PFCTL" -a "$ANCHOR" -s rules
    run sudo "$PFCTL" -a "$ANCHOR" -t "$TABLE" -T show

    if [[ $was_blocked == 1 ]]; then
        echo; echo "## Task 2: live block SKIPPED: $TARGET_IP already blocked by the user"
    else
        echo; echo "## Task 2: live block of $TARGET_IP"
        probe
        if [[ $PF_DISABLED_TEST == 1 ]]; then
            echo "# PF_DISABLED_TEST: disabling pf; block must re-enable it"
            run sudo "$PFCTL" -d
            sudo "$PFCTL" -s info 2>&1 | grep '^Status'
        fi
        run sudo "$UV" run safemaxxing block "$TARGET_IP"
        run sudo "$PFCTL" -s info
        run sudo "$PFCTL" -a "$ANCHOR" -s rules
        run sudo "$PFCTL" -a "$ANCHOR" -t "$TABLE" -T show
        echo "# expected: 000 (no connection)"
        probe
        run sudo "$UV" run safemaxxing unblock "$TARGET_IP"
        run sudo "$PFCTL" -a "$ANCHOR" -t "$TABLE" -T show
        echo "# expected: an HTTP status code again"
        probe
    fi

    echo; echo "## Task 3: log stream sample (${SAMPLE_S}s, raw entries in $SAMPLE_JSONL)"
    # Start events are logged only once, when an app opens a sensor: the apps must be opened
    # *during* the sample, not before it.
    read -r -p ">>> Quit Photo Booth and Voice Memos. Press Enter, then within ${SAMPLE_S}s open \
Photo Booth (camera), record in Voice Memos (mic), and quit both " _ </dev/tty >/dev/tty 2>&1
    run sudo "$UV" run safemaxxing sample --seconds "$SAMPLE_S" --out "$SAMPLE_JSONL"
    sudo chown "$(id -un)" "$SAMPLE_JSONL" 2>/dev/null

    echo; echo "## Tasks 2-4: live pytest suite"
    run sudo SAFEMAXXING_LIVE=1 SAFEMAXXING_LIVE_IP="$TARGET_IP" "$UV" run pytest -m live -v -s -p no:cacheprovider
} 2>&1 | tee "$OUT"

echo
echo "Raw log written to $OUT"
