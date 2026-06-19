#!/bin/bash
# Egress allowlist for the analysis sandbox.
# Default-DROP everything outbound except DNS, loopback, established flows, and
# an explicit allowlist of domains (positional args, space-separated).
#
# Rootless-safe: uses direct iptables -d <ip> rules (no ipset, which can't open
# a netlink socket in a rootless container). Fail-CLOSED: the DROP policy is set
# before any allow rule, so a mid-script error leaves egress blocked, not open.
set -euo pipefail

# Domains as positional args (no `sudo -E` needed); fall back to env, then bare.
if [ "$#" -gt 0 ]; then
    ALLOWED_DOMAINS="$*"
else
    ALLOWED_DOMAINS="${ALLOWED_DOMAINS:-api.anthropic.com}"
fi
# api.anthropic.com is mandatory regardless of what was passed.
case " $ALLOWED_DOMAINS " in *" api.anthropic.com "*) ;; *) ALLOWED_DOMAINS="api.anthropic.com $ALLOWED_DOMAINS" ;; esac

echo "[firewall] flushing rules"
iptables -F

# 1. Fail-closed FIRST: default DROP before any allow exists.
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  DROP

# 2. Loopback
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 3. Established/related return traffic
iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 4. DNS (needed to resolve the allowlist itself)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# 5. Resolve each allowed domain and permit its IPs directly.
for domain in $ALLOWED_DOMAINS; do
    echo "[firewall] resolving $domain"
    ips=$(dig +short A "$domain" | grep -E '^[0-9.]+$' || true)
    if [ -z "$ips" ]; then
        echo "[firewall] WARNING: could not resolve $domain (will remain blocked)"
        continue
    fi
    for ip in $ips; do
        echo "[firewall]   allow $domain -> $ip"
        iptables -A OUTPUT -d "$ip" -j ACCEPT
    done
done

echo "[firewall] active (default DROP). allowed: $ALLOWED_DOMAINS"
