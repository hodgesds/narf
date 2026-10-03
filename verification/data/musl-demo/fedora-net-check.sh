#!/bin/bash
# Focused distro integration gate: prove the qemu-net static bring-up gives
# stock Fedora userspace a WORKING off-box network, not just a configured
# one. Three independent probes, strongest last:
#
#   iface — the virtio NIC registered as vnet0 and is visible through the
#           Linux-compat /proc/net/dev surface the distro reads.
#   tcp   — curl fetches a token from the host across the SLIRP gateway
#           (guest 10.0.2.2:<port> lands on host 127.0.0.1:<port>). This is
#           the full datapath: ARP, IPv4 route, TCP handshake, payload.
#   dns   — glibc resolves a real name through the SLIRP DNS proxy at
#           10.0.2.3 (per /etc/resolv.conf), i.e. the UDP datapath plus the
#           host's recursive resolver behind it.
#   netns — unshare(CLONE_NEWNET) works (systemd's PrivateNetwork= depends
#           on it) and actually isolates: the host round-trip that just
#           succeeded must fail from inside a fresh network namespace.
#
# Exactly one verdict line lands on the console; `cargo xtask systemd-pid1`
# keys its success/failure markers to it. Keep the prefix stable.

set -u

port=18080
for tok in $(cat /proc/cmdline 2>/dev/null); do
    case "$tok" in
    narf_net_check_port=*) port=${tok#*=} ;;
    esac
done

fail() {
    echo "NARF-NET-CHECK: FAIL $1"
    exit 1
}

# --- iface: vnet0 registered and exported via /proc/net/dev ---------------
grep -q 'vnet0' /proc/net/dev 2>/dev/null || fail "iface vnet0 missing from /proc/net/dev"

# --- tcp: round-trip a token from the xtask listener on the host ----------
# A few retries cover the boot-time window where the first ARP/route use
# races the gateway's own bring-up; each one is cheap and bounded.
tcp_ok=0
for attempt in 1 2 3; do
    body=$(curl --silent --show-error --max-time 10 "http://10.0.2.2:${port}/" 2>&1)
    if [ "$body" = "narf-net-ok" ]; then
        tcp_ok=1
        break
    fi
    echo "narf-net-check: tcp attempt ${attempt} failed: ${body}"
    sleep 2
done
[ "$tcp_ok" = 1 ] || fail "tcp no round-trip to host 10.0.2.2:${port}"

# --- dns: resolve a real name through the SLIRP proxy at 10.0.2.3 ---------
# Bound the resolver so a dead proxy fails in seconds, not the glibc
# default of five tries at five seconds each.
dns_ok=0
for attempt in 1 2 3; do
    if RES_OPTIONS="timeout:3 attempts:2" getent hosts fedoraproject.org >/dev/null 2>&1; then
        dns_ok=1
        break
    fi
    echo "narf-net-check: dns attempt ${attempt} failed"
    sleep 2
done
[ "$dns_ok" = 1 ] || fail "dns cannot resolve through 10.0.2.3"

# --- netns: CLONE_NEWNET exists and actually isolates ---------------------
# A fresh network namespace holds only its own loopback, so the host
# round-trip that just succeeded MUST fail in there. unshare ships with
# util-linux on this image; its absence is a staging bug, not a skip.
unshare -n true 2>/dev/null || fail "netns unshare(CLONE_NEWNET) unavailable"
if unshare -n curl --silent --max-time 3 "http://10.0.2.2:${port}/" >/dev/null 2>&1; then
    fail "netns isolation breached: host reachable from a fresh netns"
fi

echo "NARF-NET-CHECK: OK iface=ok tcp=ok dns=ok netns=ok port=${port}"
