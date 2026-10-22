#!/usr/bin/env bash
# Collect raw evidence for TESTLOG.md on a real Mac (Tasks 1-4 of the macOS validation plan).
#
#   scripts/macos_validate.sh            # asks for sudo once; writes testlogs/<stamp>-macos.log
#
# Env: SAFEMAXXING_LIVE_IP (default 1.1.1.1), SAMPLE_S (log sample seconds, default 8),
#      PF_DISABLED_TEST=1 to `pfctl -d` first and check that `block` re-enables pf.
# The block test adds and always removes one IP in the safemaxxing_block table.
set -u

[[ "$(uname -s)" == Darwin ]] || { echo "needs macOS (Darwin)" >&2; exit 1; }
cd "$(dirname "$0")/.."

UV="$(command -v uv)" || { echo "uv not found" >&2; exit 1; }
PFCTL=/sbin/pfctl
ANCHOR=com.apple/safemaxxing
TABLE=safemaxxing_block
TARGET_IP="${SAFEMAXXING_LIVE_IP:-1.1.1.1}"
SAMPLE_S="${SAMPLE_S:-8}"
PF_DISABLED_TEST="${PF_DISABLED_TEST:-0}"

mkdir -p testlogs
OUT="testlogs/$(date +%Y%m%d-%H%M)-macos.log"

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
# Earlier `sudo pytest` runs leave a root-owned cache that breaks the non-root run.
[[ -d .pytest_cache ]] && sudo chown -R "$(id -un)" .pytest_cache
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

    echo; echo "## Static checks"
    run "$UV" run ruff check
    run "$UV" run mypy --strict
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

    echo; echo "## Task 3: log stream sample (${SAMPLE_S}s)"
    read -r -p ">>> Open Photo Booth (camera), start a Voice Memos recording (mic), then Enter " \
        _ </dev/tty >/dev/tty 2>&1
    run sudo "$UV" run safemaxxing sample --seconds "$SAMPLE_S"

    echo; echo "## Tasks 2-4: live pytest suite"
    run sudo SAFEMAXXING_LIVE=1 SAFEMAXXING_LIVE_IP="$TARGET_IP" "$UV" run pytest -m live -v -s -p no:cacheprovider
} 2>&1 | tee "$OUT"

echo
echo "Raw log written to $OUT"
