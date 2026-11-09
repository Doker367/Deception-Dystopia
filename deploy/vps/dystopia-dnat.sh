#!/usr/bin/env bash
# VPS only: eight TCP honeypots. NO SNAT/MASQUERADE (preserve the client IP).
# Install at /usr/local/sbin/dystopia-dnat.sh; run via the unit, as root.
set -euo pipefail

CHAIN=DYSTOPIA_DNAT
TARGET=10.66.0.3
PORTS=12222,12223,13022,13080,14021,15021,16379,17222

fail() { printf 'dystopia-dnat: %s\n' "$*" >&2; exit 1; }

stop() {
    while iptables -w -t nat -C PREROUTING -j "$CHAIN" 2>/dev/null; do
        iptables -w -t nat -D PREROUTING -j "$CHAIN"
    done
    if iptables -w -t nat -S "$CHAIN" >/dev/null 2>&1; then
        iptables -w -t nat -F "$CHAIN"
        iptables -w -t nat -X "$CHAIN"
    fi
}

preflight() {
    : "${WAN_IF:?Set WAN_IF to the VPS public-facing interface}"
    : "${VPS_INGRESS_IP:?Set VPS_INGRESS_IP to its local IPv4 destination}"
    # VPS_INGRESS_IP is the address seen on the VPS interface, not necessarily
    # the advertised public IP if the provider does upstream NAT.
    ip -o -4 addr show dev "$WAN_IF" | awk '{split($4, parts, "/"); print parts[1]}' \
        | grep -Fxq "$VPS_INGRESS_IP" || fail 'ingress address is not assigned to WAN_IF'
    [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || fail 'enable net.ipv4.ip_forward first'
    ip -4 route get "$TARGET" | grep -Eq ' dev wg0( |$)' || fail 'no route to honeypot via wg0'
    iptables -w -t nat -S "$CHAIN" >/dev/null 2>&1 && fail 'owned chain already exists; stop it first'
    return 0
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail 'root required'
for tool in ip iptables sysctl awk grep; do command -v "$tool" >/dev/null || fail "missing $tool"; done

case "${1:-}" in
    check) preflight ;;
    start)
        preflight
        iptables -w -t nat -N "$CHAIN"
        trap stop ERR
        iptables -w -t nat -A "$CHAIN" -i "$WAN_IF" -d "$VPS_INGRESS_IP" \
            -p tcp -m multiport --dports "$PORTS" -j DNAT --to-destination "$TARGET"
        iptables -w -t nat -I PREROUTING 1 -j "$CHAIN"
        trap - ERR
        ;;
    stop) stop ;;
    *) fail 'usage: dystopia-dnat.sh check|start|stop' ;;
esac
