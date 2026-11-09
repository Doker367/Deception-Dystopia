#!/usr/bin/env bash
# Linux server only: policy-route replies to WG-forwarded honeypot sessions.
# Mark conntrack ONLY for the eight inbound WG ports. Mark packets ONLY in the
# reply direction on a Compose Docker bridge (br-*); never mark WG ingress.
set -euo pipefail

CHAIN=DYSTOPIA_WG_RETURN
PORTS=12222,12223,13022,13080,14021,15021,16379,17222
MARK=0x6600/0x0000ff00
TABLE=100
PRIORITY=10010

fail() { printf 'dystopia-wg-return: %s\n' "$*" >&2; exit 1; }

stop() {
    while iptables -w -t mangle -C PREROUTING -j "$CHAIN" 2>/dev/null; do
        iptables -w -t mangle -D PREROUTING -j "$CHAIN"
    done
    if iptables -w -t mangle -S "$CHAIN" >/dev/null 2>&1; then
        iptables -w -t mangle -F "$CHAIN"
        iptables -w -t mangle -X "$CHAIN"
    fi
    ip -4 rule del pref "$PRIORITY" fwmark "$MARK" lookup "$TABLE" 2>/dev/null || true
    ip -4 route del default dev wg0 table "$TABLE" 2>/dev/null || true
    # Do not reset rp_filter blindly: restore the pre-deployment value from
    # the operator's snapshot (it may have been loose before this change).
}

preflight() {
    ip link show dev wg0 >/dev/null || fail 'wg0 not present'
    [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || fail 'server cannot forward wg0 to Docker'
    wg show wg0 allowed-ips | grep -Eq '(^|[[:space:]])0\.0\.0\.0/0([[:space:]]|$)' \
        || fail 'WG peer must accept the public client IPs (AllowedIPs 0.0.0.0/0)'
    [[ -z "$(ip -4 route show table "$TABLE")" ]] || fail "table $TABLE already contains routes"
    if ip -4 rule show | grep -Eq "(^|[[:space:]])${PRIORITY}:"; then
        fail "routing priority $PRIORITY already used"
    fi
    iptables -w -t mangle -S "$CHAIN" >/dev/null 2>&1 && fail 'owned chain already exists; stop it first'
    return 0
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail 'root required'
for tool in ip iptables sysctl wg grep; do command -v "$tool" >/dev/null || fail "missing $tool"; done

case "${1:-}" in
    check) preflight ;;
    start)
        preflight
        # Loose RPF on WG only: the Internet source's main reverse route
        # normally points at the server WAN, not at wg0.
        old_rpf=$(sysctl -n net.ipv4.conf.wg0.rp_filter)
        # Restore the original RPF value even when startup fails halfway.
        trap 'stop || true; sysctl -w net.ipv4.conf.wg0.rp_filter="$old_rpf" >/dev/null' ERR
        sysctl -w net.ipv4.conf.wg0.rp_filter=2 >/dev/null
        ip -4 route add default dev wg0 table "$TABLE"
        ip -4 rule add pref "$PRIORITY" fwmark "$MARK" lookup "$TABLE"
        iptables -w -t mangle -N "$CHAIN"
        iptables -w -t mangle -A "$CHAIN" -i wg0 -d 10.66.0.3 -p tcp \
            -m multiport --dports "$PORTS" \
            -m conntrack --ctstate NEW --ctdir ORIGINAL \
            -j CONNMARK --set-xmark "$MARK"
        # Compose creates bridge interfaces br-<id>; no host or management
        # reply may inherit this mark via an unrelated local interface.
        iptables -w -t mangle -A "$CHAIN" -i 'br-+' \
            -m conntrack --ctstate ESTABLISHED --ctdir REPLY \
            -m connmark --mark "$MARK" -j MARK --set-xmark "$MARK"
        iptables -w -t mangle -I PREROUTING 1 -j "$CHAIN"
        trap - ERR
        ;;
    stop) stop ;;
    *) fail 'usage: dystopia-wg-return.sh check|start|stop' ;;
esac
