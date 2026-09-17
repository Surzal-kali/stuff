#!/bin/sh
set -e

# ============================================================================
# Custom entrypoint: network lockdown + framework services + open-terminal
# ============================================================================

# --- Docker secrets support ---
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

# --- Fix home directory permissions ---
fix_home() {
    local home="/home/user"
    local owner_uid
    owner_uid=$(stat -c '%u' "$home" 2>/dev/null || stat -f '%u' "$home" 2>/dev/null || echo "1000")
    if [ "$owner_uid" != "1000" ]; then
        chown -R user:user "$home" 2>/dev/null || true
    fi
    mkdir -p "$home/.local/bin"
    [ ! -f "$home/.bashrc" ] && [ -f /etc/skel/.bashrc ] && cp /etc/skel/.bashrc "$home/.bashrc" 2>/dev/null || true
    [ ! -f "$home/.profile" ] && [ -f /etc/skel/.profile ] && cp /etc/skel/.profile "$home/.profile" 2>/dev/null || true
    chown -R user:user "$home" 2>/dev/null || true
}

# --- Network lockdown via iptables ---
# Forces the agent to reach the outside world only through the framework's API
# routes (gateway on loopback) instead of shelling out directly. Allowed:
# loopback, the Docker subnet (ChromaDB + compose services), and Ollama.
# Everything else is dropped. This is the network backstop behind the scope
# layer — keep it on open-terminal (the gated agent runtime).
setup_firewall() {
    if ! command -v iptables >/dev/null 2>&1; then
        echo "WARNING: iptables not found — NO network isolation!" >&2
        return 1
    fi

    local SUBNET="${DOCKER_SUBNET:-172.28.0.0/16}"
    local OLLAMA_IP="${OLLAMA_HOST:-10.0.0.245}"
    local OLLAMA_PORT="${OLLAMA_PORT:-11434}"

    iptables -F OUTPUT 2>/dev/null || true
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -d "$SUBNET" -j ACCEPT
    iptables -A OUTPUT -p tcp -d "$OLLAMA_IP" --dport "$OLLAMA_PORT" -j ACCEPT
    iptables -A OUTPUT -j DROP

    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -F OUTPUT 2>/dev/null || true
        ip6tables -A OUTPUT -o lo -j ACCEPT
        ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        ip6tables -A OUTPUT -j DROP
    fi

    echo "=== Network lockdown active ===" >&2
    echo "  Allowed: loopback, $SUBNET (Docker services), $OLLAMA_IP:$OLLAMA_PORT (Ollama)" >&2
    echo "  Blocked: all other outbound (IPv4 + IPv6)" >&2
    return 0
}

# ============================================================================
# Main
# ============================================================================
fix_home

export HOME="/home/user"
export PATH="/home/user/.local/bin:/opt/framework-venv/bin:${PATH}"

# Lock down the network (as root, before dropping privileges).
# Gated by LOCKDOWN_NETWORK so the same image can run an open "regular
# terminal" instance (LOCKDOWN_NETWORK=0, no NET_ADMIN) alongside the
# gated agent runtime. Default is on to preserve the security backstop.
if [ "${LOCKDOWN_NETWORK:-1}" = "1" ]; then
    setup_firewall || true
else
    echo "=== Network lockdown DISABLED (LOCKDOWN_NETWORK=0) ===" >&2
    echo "  This instance is an OPEN terminal — full outbound network." >&2
fi

# Start framework services in the background (as user, after firewall is up)
FRAMEWORK_ROOT="/opt/framework"
VENV_PYTHON="/opt/framework-venv/bin/python3"

# Fix ownership on mounted volumes (entrypoint runs as root, services as user)
mkdir -p "$FRAMEWORK_ROOT/.memory/chroma"
chown -R user:user "$FRAMEWORK_ROOT/.memory" 2>/dev/null || true

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

# Drop CAP_NET_ADMIN (so the agent cannot undo the firewall) and run
# open-terminal as the unprivileged user.
if command -v capsh >/dev/null 2>&1; then
    exec capsh --drop=cap_net_admin -- -c "exec gosu user open-terminal $*"
else
    exec gosu user open-terminal "$@"
fi
