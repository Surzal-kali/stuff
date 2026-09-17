#!/bin/sh
set -e

# =============================================================================
# Jupyter entrypoint: network lockdown (loopback + Docker subnet + Ollama only)
# then start the notebook server as jovyan. Mirrors open-terminal firewall so
# the tool nursery reaches the outside world only via the framework gateway on
# the subnet, closing the agent-pivot bypass. jovyan has no CAP_NET_ADMIN, so
# kernels cannot undo these rules.
# =============================================================================

setup_firewall() {
    if ! command -v iptables >/dev/null 2>&1; then
        echo "WARNING: iptables not found — NO network isolation!" >&2
        return 1
    fi
    SUBNET="${DOCKER_SUBNET:-172.28.0.0/16}"
    OLLAMA_IP="${OLLAMA_HOST:-10.0.0.245}"
    OLLAMA_PORT="${OLLAMA_PORT:-11434}"

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

    echo "=== Jupyter network lockdown active ===" >&2
    echo "  Allowed: loopback, $SUBNET (Docker services), $OLLAMA_IP:$OLLAMA_PORT (Ollama)" >&2
    echo "  Blocked: all other outbound (IPv4 + IPv6)" >&2
    return 0
}

setup_firewall || true

# Drop to jovyan (non-root, no CAP_NET_ADMIN) and start the notebook server.
exec gosu "${NB_USER:-jovyan}" start-notebook.sh "$@"
