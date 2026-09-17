#!/bin/sh
set -e

# ============================================================================
# open-terminal service bootstrap (replaces the old lockdown entrypoint).
#
# Decision 2026-09-17 (user call "C"): the network cage is REMOVED. Rationale:
# the framework is the scope-lined gateway to the outside world, the only
# consumer the cage ever actually restricted was the secretary chat loop
# (barely used), and the cage collided with the workbench topology — the
# gateway+brain now live inside this container, so LOCKDOWN_NETWORK caged the
# framework's own target lanes (inspect_host, amass, ZAP, nmap) along with
# the shell. Scope enforcement stays in-process (check_scope / .scope files /
# RoE headers); there is no iptables backstop anymore.
#
# Root is kept ONLY for first-boot volume chores, then services and the
# open-terminal server run as `user`. No NET_ADMIN capability is needed.
# ============================================================================

file_env() {
    local var="$1"
    local fileVar="${var}_FILE"
    local val
    eval local currentVal="\${$var:-}"
    eval local fileVal="\${$fileVar:-}"
    if [ -n "$fileVal" ]; then
        val="$(cat "$fileVal")"
    else
        val="$currentVal"
    fi
    [ -n "$val" ] && export "$var"="$val"
    unset "$fileVar" 2>/dev/null || true
}
file_env 'OPEN_TERMINAL_API_KEY'

FRAMEWORK_ROOT="/opt/framework"
VENV_PYTHON="/opt/framework-venv/bin/python3"

# --- First-boot volume chores (root-only, best-effort) ---
if [ "$(id -u)" = "0" ]; then
    home="/home/user"
    owner_uid=$(stat -c '%u' "$home" 2>/dev/null || echo "1000")
    if [ "$owner_uid" != "1000" ]; then
        chown -R user:user "$home" 2>/dev/null || true
    fi
    mkdir -p "$home/.local/bin"
    [ ! -f "$home/.bashrc" ] && [ -f /etc/skel/.bashrc ] && cp /etc/skel/.bashrc "$home/.bashrc" 2>/dev/null || true
    [ ! -f "$home/.profile" ] && [ -f /etc/skel/.profile ] && cp /etc/skel/.profile "$home/.profile" 2>/dev/null || true
    mkdir -p "$FRAMEWORK_ROOT/.memory/chroma"
    chown -R user:user "$FRAMEWORK_ROOT/.memory" 2>/dev/null || true
    chown -R user:user "$home" 2>/dev/null || true
    export HOME="/home/user"
    export PATH="/home/user/.local/bin:/opt/framework-venv/bin:${PATH}"
fi

# --- Framework services (as user) ---
if [ -f "$FRAMEWORK_ROOT/listeners/thebrain.py" ]; then
    echo "Starting Brain sidecar..." >&2
    cd "$FRAMEWORK_ROOT"
    gosu user "$VENV_PYTHON" listeners/thebrain.py &
    sleep 2
    cd /app
fi

if [ -f "$FRAMEWORK_ROOT/dockered/start_gateway.py" ]; then
    echo "Starting API gateway..." >&2
    cd "$FRAMEWORK_ROOT"
    gosu user "$VENV_PYTHON" dockered/start_gateway.py &
    sleep 1
    cd /app
fi

# --- Hand off to the open-terminal server as the unprivileged user ---
if [ "$(id -u)" = "0" ] && command -v gosu >/dev/null 2>&1; then
    exec gosu user open-terminal "$@"
else
    exec open-terminal "$@"
fi