#!/usr/bin/env bash
# sarctl — start/stop/status helper for the sarek server
# Author: David R. Smith

set -euo pipefail

SAREK_HOME=/mnt/c/Users/daves/OneDrive/Desktop/SAREK

SAREK_BIN="${SAREK_BIN:-$SAREK_HOME/sarek/build/sarek}"
SAREK_CONFIG="${SAREK_CONFIG:-$SAREK_HOME/sarek/tmp/sarek.yml}"
SAREK_CERT="${SAREK_CERT:-$SAREK_HOME/sarek/tmp/cert.pem}"
SAREK_KEY="${SAREK_KEY:-$SAREK_HOME/sarek/tmp/key.pem}"
SAREK_LOG="${SAREK_LOG:-$SAREK_HOME/sarek/tmp/sarek.log}"
SAREK_PID="${SAREK_PID:-$SAREK_HOME/sarek/tmp/sarek.pid}"

usage() {
    cat <<EOF
Usage: sarctl {start|stop|restart|status}

Environment variables (override defaults):
  SAREK_BIN     Path to sarek binary     [${SAREK_BIN}]
  SAREK_CONFIG  Path to sarek.yml        [${SAREK_CONFIG}]
  SAREK_CERT    Path to TLS cert PEM     [${SAREK_CERT:-(none, dev mode)}]
  SAREK_KEY     Path to TLS key PEM      [${SAREK_KEY:-(none, dev mode)}]
  SAREK_LOG     stdout/stderr log file   [${SAREK_LOG}]
  SAREK_PID     PID file path            [${SAREK_PID}]
EOF
}

pid_running() {
    local pid="$1"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

# Read the http.port value from the YAML config (simple grep, no yaml parser needed)
config_port() {
    grep -E '^\s*port\s*:' "$SAREK_CONFIG" 2>/dev/null | awk -F: '{print $2}' | tr -d ' \t\r' | head -1
}

port_in_use() {
    local port="$1"
    [[ -n "$port" ]] && ss -tlnH "sport = :${port}" 2>/dev/null | grep -q .
}

read_pid() {
    if [[ -f "$SAREK_PID" ]]; then
        cat "$SAREK_PID"
    fi
}

cmd_start() {
    local existing_pid
    existing_pid="$(read_pid)"
    if pid_running "$existing_pid"; then
        echo "sarek is already running (pid $existing_pid)" >&2
        return 1
    fi

    if [[ ! -x "$SAREK_BIN" ]]; then
        echo "sarek binary not found or not executable: $SAREK_BIN" >&2
        return 1
    fi

    if [[ ! -f "$SAREK_CONFIG" ]]; then
        echo "config file not found: $SAREK_CONFIG" >&2
        return 1
    fi

    local port
    port="$(config_port)"
    if port_in_use "$port"; then
        echo "port ${port} is already in use — is another sarek instance running?" >&2
        echo "  (check: ss -tlnp sport = :${port})" >&2
        return 1
    fi

    # Build argument list
    local args=("--config" "$SAREK_CONFIG")
    if [[ -n "$SAREK_CERT" && -n "$SAREK_KEY" ]]; then
        args+=("--cert" "$SAREK_CERT" "--key" "$SAREK_KEY")
    else
        echo "Warning: no cert/key configured — starting in --dev mode" >&2
        args+=("--dev")
    fi

    # Ensure log directory exists
    local log_dir
    log_dir="$(dirname "$SAREK_LOG")"
    mkdir -p "$log_dir"

    local pid_dir
    pid_dir="$(dirname "$SAREK_PID")"
    mkdir -p "$pid_dir"

    # Launch in background, redirect output
    echo "Starting sarek..." >&2
    "$SAREK_BIN" "${args[@]}" >>"$SAREK_LOG" 2>&1 &
    local pid=$!

    # Brief pause to catch immediate startup failures
    sleep 0.3
    if ! pid_running "$pid"; then
        echo "sarek exited immediately — check $SAREK_LOG" >&2
        return 1
    fi

    echo "$pid" > "$SAREK_PID"
    echo "sarek started (pid $pid), logging to $SAREK_LOG"
}

cmd_stop() {
    local pid
    pid="$(read_pid)"
    if ! pid_running "$pid"; then
        echo "sarek is not running" >&2
        [[ -f "$SAREK_PID" ]] && rm -f "$SAREK_PID"
        return 0
    fi

    echo "Stopping sarek (pid $pid)..." >&2
    kill -TERM "$pid"

    # Wait up to 10 seconds for graceful shutdown
    local i
    for i in $(seq 1 20); do
        if ! pid_running "$pid"; then
            rm -f "$SAREK_PID"
            echo "sarek stopped"
            return 0
        fi
        sleep 0.5
    done

    echo "sarek did not stop after 10 s; sending SIGKILL" >&2
    kill -KILL "$pid" 2>/dev/null || true
    rm -f "$SAREK_PID"
    echo "sarek killed"
}

cmd_status() {
    local pid
    pid="$(read_pid)"
    if pid_running "$pid"; then
        echo "sarek is running (pid $pid)"
        return 0
    else
        echo "sarek is not running"
        [[ -f "$SAREK_PID" ]] && echo "  (stale PID file: $SAREK_PID)"
        return 1
    fi
}

case "${1:-}" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    restart) cmd_stop || true; sleep 1; cmd_start ;;
    status)  cmd_status ;;
    *)       usage; exit 1 ;;
esac
