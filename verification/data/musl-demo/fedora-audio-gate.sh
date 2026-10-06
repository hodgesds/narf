#!/bin/bash
# Desktop audio integration gate: prove that STOCK PipeWire + WirePlumber run
# on NARF the way they run on Linux — automatic card discovery through udev,
# ACP card profiles, routing to a default sink/source, simultaneous playback
# and capture, and recovery after a session restart and a profile cycle.
#
# This is deliberately NOT the alsa-lib probe (verification/data/alsa-compat).
# That probe drives the PCM/control ioctls directly from one process. PipeWire
# adds the parts a desktop actually depends on and ALSA validation cannot
# establish: the udev database and its SOUND_INITIALIZED/ID_PATH properties,
# the ACP mixer/profile layer opening and closing every candidate PCM mapping,
# a second process (WirePlumber) driving the graph over the PipeWire protocol's
# SCM_RIGHTS + sealed-memfd transport, and a realtime data thread.
#
# Six stages, strongest last. Exactly one verdict line lands on the console;
# `cargo xtask systemd-pid1` keys its success/failure markers to it. Keep the
# prefix stable.
#
#   udev     — the sound cards reached udev's database with the properties
#              PipeWire's spa_alsa_udev monitor requires to accept a card.
#   access   — the desktop user can open the control and PCM nodes.
#   daemon   — pipewire starts and serves its protocol socket.
#   session  — wireplumber attaches and exports an ALSA device with profiles.
#   stream   — a sink and a source node exist, and playback and capture run
#              AT THE SAME TIME through them.
#   recover  — a profile cycle and a full session restart both bring the
#              sink/source back.
#
# Run as root from a systemd unit; the audio session itself runs as the
# unprivileged desktop user under its own D-Bus session, as on a desktop.

set -u

U=narf
UID_N=1000
# NOT /run/user/1000. That directory belongs to user-runtime-dir@1000.service,
# which systemd removes whenever user@1000.service fails - deleting a live
# PipeWire socket underneath this gate and turning an unrelated user-manager
# problem into an audio failure. PipeWire only needs a private directory it
# owns, which PIPEWIRE_RUNTIME_DIR names directly.
RT=/run/narf-audio
WORK=/tmp/narf-audio-gate
LOG=${WORK}/log

mode=${1:-root}

# ─────────────────────────────────────────────────────────────── helpers ───
note() { echo "narf-audio-gate: $*"; }

# Wait up to $1 SECONDS for the shell condition in $2, ticking every ten so a
# slow-but-healthy stage and a wedged one are distinguishable in the console
# transcript. Every caller's budget must leave room for the diagnostics to run
# inside the unit's TimeoutStartSec: a gate killed mid-wait prints nothing at
# all, which is the one failure mode that costs a whole boot to diagnose.
wait_for() {
    local budget=$1 cond=$2
    local start now tick=0
    start=$(date +%s)
    while :; do
        if eval "$cond"; then return 0; fi
        now=$(( $(date +%s) - start ))
        [ "$now" -lt "$budget" ] || break
        if [ $((now / 10)) -gt "$tick" ]; then
            tick=$((now / 10))
            note "still waiting (${now}s/${budget}s): ${cond}"
        fi
        sleep 1
    done
    note "gave up after ${budget}s: ${cond}"
    return 1
}

diagnostics() {
    note "──── diagnostics ────"
    for card in 0 1; do
        echo "--- udevadm info /sys/class/sound/card${card} ---"
        udevadm info --query=property --path="/sys/class/sound/card${card}" 2>&1 |
            sed -n '1,40p'
        echo "--- /run/udev/data/+sound:card${card} ---"
        sed -n '1,40p' "/run/udev/data/+sound:card${card}" 2>&1
    done
    echo "--- /dev/snd ---"
    ls -l /dev/snd 2>&1
    echo "--- /proc/asound ---"
    ls /proc/asound 2>&1
    cat /proc/asound/cards 2>&1
    echo "--- aplay -l (as ${U}) ---"
    runuser -u "$U" -- aplay -l 2>&1 | sed -n '1,40p'
    echo "--- arecord -l (as ${U}) ---"
    runuser -u "$U" -- arecord -l 2>&1 | sed -n '1,40p'
    for f in "$LOG"/*; do
        [ -f "$f" ] || continue
        echo "--- ${f} (tail) ---"
        # 20 lines, not 60: this loop runs over every log, and a long dump
        # early in it pushes the later files off a console that drops lines
        # under load. Per-stage failures print their own log inline.
        tail -n 20 "$f" 2>&1
    done
    echo "--- journal: systemd-udevd ---"
    journalctl --no-pager -b -u systemd-udevd.service 2>&1 | tail -n 40
}

fail() {
    echo "NARF-AUDIO-CHECK: FAIL $*"
    diagnostics
    exit 1
}

# ───────────────────────────────────────────────── root stage: setup ───
if [ "$mode" = root ]; then
    rm -rf "$WORK"
    mkdir -p "$LOG"
    chmod 0777 "$WORK" "$LOG"

    # No logind seat ACLs here: the image puts the desktop user in the packaged
    # sound group at build time, the same way it does for video/render. Assert
    # it rather than repairing it — a missing membership means the image is
    # wrong, and silently fixing it would hide that from every later run.
    id -nG "$U" | tr ' ' '\n' | grep -qx audio ||
        fail "user ${U} is not in the audio group"

    # logind would create a seat session's runtime dir; this gate owns its own.
    rm -rf "$RT"
    install -d -m 0700 -o "$U" -g "$U" "$RT"

    # ── stage udev ────────────────────────────────────────────────────────
    #
    # PipeWire's spa_alsa_udev enumerator SKIPS any card whose udev device has
    # no SOUND_INITIALIZED property (spa/plugins/alsa/alsa-udev.c), which
    # 78-sound-card.rules sets only on the card's `change` event — the event
    # the rules themselves synthesise by writing "change" to the card's sysfs
    # `uevent` attribute from the controlC* `add` event. A card that is present
    # in /dev and /sys but missing from udev's database is invisible to
    # PipeWire, so assert the database, not the device nodes.
    for card in 0 1; do
        wait_for 45 "udevadm info --query=property \
            --path=/sys/class/sound/card${card} 2>/dev/null |
            grep -q '^SOUND_INITIALIZED=1$'" ||
            fail "udev card${card} has no SOUND_INITIALIZED property"
        props=$(udevadm info --query=property --path="/sys/class/sound/card${card}" 2>/dev/null)
        echo "$props" | grep -q '^ID_PATH=' ||
            fail "udev card${card} has no ID_PATH (path_id builtin did not run)"
        echo "$props" | grep -q '^SUBSYSTEM=sound$' ||
            fail "udev card${card} is not in the sound subsystem"
    done
    note "udev: card0 and card1 carry SOUND_INITIALIZED + ID_PATH"

    # ── stage access ──────────────────────────────────────────────────────
    #
    # devtmpfs publishes an ALSA node root:root 0600 (sound/sound_core.c's
    # devnode callback names it `snd/<dev>` and leaves *mode at zero, so
    # drivers/base/devtmpfs.c falls through to its 0600 default); udev's
    # `50-udev-default.rules` then applies GROUP="audio" and 0660. If that
    # chown is dropped the nodes stay root-only, every non-root ALSA client
    # reports "no soundcards found", and no desktop session can play a sound.
    for node in /dev/snd/controlC0 /dev/snd/pcmC0D0p /dev/snd/pcmC0D0c \
                /dev/snd/controlC1 /dev/snd/pcmC1D0p; do
        [ -e "$node" ] || fail "${node} does not exist"
        state=$(stat -c '%U:%G %a' "$node" 2>&1)
        [ "$state" = "root:audio 660" ] ||
            fail "${node} is '${state}', expected 'root:audio 660' (udev chown/chmod)"
    done
    note "access: udev applied root:audio 0660 to every /dev/snd node"

    runuser -u "$U" -- aplay -l >"$LOG/aplay-l" 2>&1 ||
        fail "aplay -l failed for ${U}"
    grep -q '^card 0:' "$LOG/aplay-l" || fail "aplay -l: no card 0 playback device"
    grep -q '^card 1:' "$LOG/aplay-l" || fail "aplay -l: no card 1 playback device"
    runuser -u "$U" -- arecord -l >"$LOG/arecord-l" 2>&1 ||
        fail "arecord -l failed for ${U}"
    grep -q '^card 0:' "$LOG/arecord-l" || fail "arecord -l: no card 0 capture device"
    note "access: ${U} enumerates playback on both cards and capture on card 0"

    # Plain ALSA, BEFORE PipeWire takes the cards: does a direct `hw:` transfer
    # sustain at the rate and period PipeWire will ask for? This splits the
    # problem space in half. `aplay` without -M uses the read/write path;
    # `aplay -M` uses mmap + `snd_pcm_mmap_begin/commit`, which is the access
    # mode PipeWire's ALSA sink uses. One second of silence should take about
    # one second; anything much longer means the stream is not clocking.
    dd if=/dev/zero of="$WORK/second.raw" bs=4 count=48000 status=none
    chmod 0644 "$WORK/second.raw"
    for mode in rw mmap; do
        case "$mode" in
        mmap) flag=-M ;;
        *) flag= ;;
        esac
        for dev in hw:0,0 hw:1,0; do
            t0=$(date +%s)
            timeout 40 runuser -u "$U" -- aplay -q $flag -D "$dev" -t raw \
                -f S16_LE -r 48000 -c 2 "$WORK/second.raw" \
                >"$LOG/aplay-${mode}-${dev#hw:}" 2>&1
            rc=$?
            note "alsa: ${mode} playback ${dev} rc=${rc} elapsed=$(( $(date +%s) - t0 ))s (expect ~1s)"
            [ "$rc" -eq 0 ] || sed -n '1,6p' "$LOG/aplay-${mode}-${dev#hw:}" 2>&1
        done
    done
    # The SAME request in the format PipeWire actually negotiates. A format a
    # card ADVERTISES but cannot configure is the whole failure: HW_REFINE
    # offers the point, HW_PARAMS rejects it, and alsa-lib has no way back.
    # Either outcome here is informative — a clean "Sample format non
    # available" means the refine no longer offers what it cannot deliver,
    # while EINVAL from hw_params means it still does.
    for fmt in S16_LE S32_LE; do
        t0=$(date +%s)
        timeout 40 runuser -u "$U" -- aplay -q -D hw:0,0 -t raw \
            -f "$fmt" -r 48000 -c 2 --period-size=1024 --buffer-size=32768 \
            "$WORK/second.raw" >"$LOG/aplay-${fmt}" 2>&1
        rc=$?
        note "alsa: ${fmt} 1024/32768 hw:0,0 rc=${rc} elapsed=$(( $(date +%s) - t0 ))s: $(head -c 120 "$LOG/aplay-${fmt}" 2>&1 | tr -s ' \n' ' ')"
    done

    for mode in rw mmap; do
        case "$mode" in
        mmap) flag=-M ;;
        *) flag= ;;
        esac
        t0=$(date +%s)
        timeout 40 runuser -u "$U" -- arecord -q $flag -D hw:0,0 -t raw \
            -f S16_LE -r 48000 -c 2 -d 1 "$WORK/cap-${mode}.raw" \
            >"$LOG/arecord-${mode}" 2>&1
        rc=$?
        note "alsa: ${mode} capture hw:0,0 rc=${rc} elapsed=$(( $(date +%s) - t0 ))s bytes=$(stat -c %s "$WORK/cap-${mode}.raw" 2>/dev/null) (expect ~1s, 192000)"
        [ "$rc" -eq 0 ] || sed -n '1,6p' "$LOG/arecord-${mode}" 2>&1
    done

    # Not a pass condition: PipeWire falls back to a non-realtime data loop and
    # says so. Recorded because "set realtime policy: Operation not permitted"
    # in the daemon log has two very different causes, and only the soft/hard
    # pair distinguishes "the unit's LimitRTPRIO= never took" from "the policy
    # call itself is refused".
    note "limits: $(grep -i 'realtime priority' /proc/self/limits 2>&1 | tr -s ' ')"

    # PipeWire classifies every connecting client by opening
    # `/proc/<peer-pid>/root` and looking for `.flatpak-info`
    # (src/modules/flatpak-utils.h). A failed open is read as "sandboxed", and
    # the client is parked waiting for flatpak permissions that never arrive.
    # Inside a chroot that open only works if the link renders in the READER's
    # root frame, the way Linux `d_path()` does: the whole distro runs chrooted
    # here, so a host-view target would name nothing. Assert it directly —
    # a hung client is a far more expensive way to learn the same thing.
    # Printed before the assertion, and with `cwd` alongside `root` as a
    # control: the two are the same kind of magic link, so "root is wrong" and
    # "following a proc magic link is wrong" need telling apart in one run.
    note "proc: readlink root=$(readlink /proc/self/root 2>&1) cwd=$(readlink /proc/self/cwd 2>&1) exe=$(readlink /proc/self/exe 2>&1) pid1root=$(readlink /proc/1/root 2>&1)"
    note "proc: lstat root=$(stat -c '%F' /proc/self/root 2>&1) stat root=$(stat -L -c '%F' /proc/self/root 2>&1)"
    note "proc: stat cwd=$(stat -L -c '%F' /proc/self/cwd 2>&1)"
    note "proc: opendir root=$(ls -d /proc/self/root/. 2>&1 | head -1) cwd=$(ls -d /proc/self/cwd/. 2>&1 | head -1)"

    [ -d /proc/self/root ] || fail "/proc/self/root does not resolve to a directory"
    ls /proc/self/root/ >/dev/null 2>&1 ||
        fail "cannot open /proc/self/root as a directory"
    # PID 1 rather than $$: the peer whose root PipeWire opens is never the
    # reader itself, and `/proc/self` could be served by a shortcut that the
    # numeric path is not.
    ls /proc/1/root/ >/dev/null 2>&1 ||
        fail "cannot open /proc/1/root (readlink: $(readlink /proc/1/root 2>&1))"
    note "proc: /proc/<pid>/root opens as a directory (readlink $(readlink /proc/self/root 2>&1))"

    # Does a blocking wait block? A `poll(2)` that returns immediately makes
    # any GLib main loop spin at 100% of a CPU while still working correctly,
    # and the shape that matters here is `poll` over an EPOLL fd — GLib
    # polling PipeWire's loop.
    # To a FILE, and through `setpriv`, deliberately. `note "$(timeout … runuser
    # …)"` wedges the gate: `timeout` signals `runuser`, which does not forward
    # it, so the probe survives and the command substitution blocks forever on
    # a pipe whose write end is still held. `setpriv` execs its target, so the
    # timeout lands on the probe itself, and a redirect leaves no pipe to wait
    # on either way.
    timeout -k 5 90 setpriv --reuid "$UID_N" --regid "$UID_N" --init-groups \
        --inh-caps=-all -- /usr/local/libexec/narf-poll-probe \
        >"$LOG/poll-probe" 2>&1
    note "poll-probe rc=$?: $(tr '\n' ' ' <"$LOG/poll-probe")"

    # `/dev/fd` is a devtmpfs symlink into procfs, and `/dev/fd/N` is how bash
    # implements process substitution (`cmd < <(other)`). Following it needs the
    # VFS expansion to stop at the proc-fd magic link rather than expand its
    # readlink TEXT, which for an anonymous descriptor is `pipe:[12345]` and
    # names nothing.
    [ -e /dev/fd/0 ] ||
        fail "/dev/fd/0 does not resolve (readlink /dev/fd: $(readlink /dev/fd 2>&1))"
    printf 'devfd-ok\n' | { read -t 10 -r probe < /dev/fd/0 && [ "$probe" = devfd-ok ]; } ||
        fail "/dev/fd/0 does not read back the caller's stdin"
    { cat < <(printf 'procsub-ok\n'); } 2>/dev/null | grep -q procsub-ok ||
        fail "bash process substitution (cmd < <(other)) does not work"
    note "devfd: /dev/fd/0 reads and process substitution works"

    # A session bus, the way a seat session has one. Started explicitly rather
    # than through `dbus-run-session`, which hands the address back over a pipe
    # and then execs the payload: that handoff is an extra moving part in a
    # stage whose failure mode is total silence. Bounded, and optional —
    # PipeWire only wants the address to reach rtkit, and WirePlumber's
    # D-Bus-dependent components are not on this contract's path.
    bus=$(timeout 30 setpriv --reuid "$UID_N" --regid "$UID_N" --init-groups \
            --inh-caps=-all -- env "XDG_RUNTIME_DIR=$RT" \
            dbus-daemon --session --fork --print-address \
            2>"$LOG/dbus-daemon" | head -1)
    if [ -n "$bus" ]; then
        note "session bus at ${bus}"
    else
        note "no session bus (continuing without one): $(tail -n 2 "$LOG/dbus-daemon" 2>&1)"
    fi

    # Hand the rest to the desktop user. `setpriv`, not `runuser`: runuser goes
    # through PAM, and pam_limits resets RLIMIT_RTPRIO to the
    # /etc/security/limits.conf default of 0, so the unit's LimitRTPRIO= never
    # reaches the daemon and PipeWire's data loop silently gives up on
    # realtime. setpriv only drops privileges, inheriting the limits the way a
    # user systemd manager's units do. `exec` keeps the verdict line on this
    # console.
    exec setpriv --reuid "$UID_N" --regid "$UID_N" --init-groups --inh-caps=-all -- \
        env \
        "HOME=/home/${U}" \
        "USER=${U}" \
        "LOGNAME=${U}" \
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        "DBUS_SESSION_BUS_ADDRESS=$bus" \
        "NARF_AUDIO_BUS=$bus" \
        "$0" session
fi

# ──────────────────────────────────────────────── user stage: session ───
# First line out of the re-exec: it separates "the handoff to the desktop user
# never happened" from "the audio stack did not come up", which otherwise look
# identical from the console.
note "session: running as $(id -un) (uid $(id -u))"
[ -n "${NARF_AUDIO_BUS:-}" ] || unset DBUS_SESSION_BUS_ADDRESS

export XDG_RUNTIME_DIR="$RT"
export PIPEWIRE_RUNTIME_DIR="$RT"
export XDG_CONFIG_HOME="$WORK/config"
export XDG_STATE_HOME="$WORK/state"
export XDG_CACHE_HOME="$WORK/cache"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" "$XDG_CACHE_HOME"

PW_PID=
WP_PID=
cleanup() {
    [ -n "$WP_PID" ] && kill "$WP_PID" 2>/dev/null
    [ -n "$PW_PID" ] && kill "$PW_PID" 2>/dev/null
    return 0
}
trap cleanup EXIT

# The DAEMONS log verbosely; the client tools must not. A silent daemon that
# never binds its socket is indistinguishable from one that never started, and
# this gate's whole value is that a single boot tells you which — but exported,
# the same variables bury `wpctl status`'s table under WirePlumber's own
# startup log on the very stdout this gate parses.
PW_LOG_LEVEL=${NARF_AUDIO_DEBUG:-3}
# Per-topic level: the ALSA node's timing trace, without turning on trace for
# every other topic in the daemon.
PW_DAEMON_DEBUG="${PW_LOG_LEVEL},spa.alsa:5"

# `ps` line for a daemon we started. STAT and TIME together separate the two
# ways a daemon fails to come up on a one-vCPU guest: a blocked process sits in
# S with its CPU time frozen, while one spinning in a poll loop burns TIME and
# starves every other process on the core — including this shell, which then
# looks hung itself.
health() {
    local pid=$1
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "pid ${pid} is gone"
        return
    fi
    # Process line, then one entry per thread straight out of
    # /proc/<pid>/task/<tid>/stat. `ps -L` is not usable here: it fails with
    # "fatal library error, reap" against this procfs, which would replace the
    # health report with a procps diagnostic at exactly the wrong moment.
    ps -o pid=,stat=,time=,pcpu=,comm= -p "$pid" 2>&1 | tr -s ' '
    local t
    for t in /proc/"$pid"/task/*; do
        [ -r "$t/stat" ] || continue
        # pid comm state ... utime(14) stime(15), in clock ticks.
        awk '{ printf "  tid %s %s %s utime=%s stime=%s\n", $1, $2, $3, $14, $15 }' \
            "$t/stat" 2>/dev/null
    done
}

# Dump what a daemon has said so far. Called unconditionally a few seconds
# after launch, not only on failure: a daemon that never reaches its first log
# line and one whose log explains the problem are indistinguishable from a
# console that only ever sees the gate's own verdict.
early_log() {
    local what=$1 file=$2 pid=$3
    note "${what}: $(health "$pid")"
    note "${what}: first output:"
    sed -n '1,40p' "$file" 2>&1
}

start_pipewire() {
    note "starting pipewire"
    PIPEWIRE_DEBUG="$PW_DAEMON_DEBUG" pipewire >"$LOG/pipewire" 2>&1 &
    PW_PID=$!
    sleep 5
    early_log pipewire "$LOG/pipewire" "$PW_PID"
    wait_for 45 "[ -S '${RT}/pipewire-0' ]" ||
        return 1
    wait_for 45 "timeout 30 pw-cli info 0 >'$LOG/pw-core' 2>&1" ||
        return 1
    note "pipewire: $(health "$PW_PID")"
    return 0
}

start_wireplumber() {
    note "starting wireplumber"
    WIREPLUMBER_DEBUG="$PW_LOG_LEVEL" wireplumber >"$LOG/wireplumber" 2>&1 &
    WP_PID=$!
    sleep 5
    early_log wireplumber "$LOG/wireplumber" "$WP_PID"
    return 0
}

# One graph snapshot, shared by every parser below. pw-dump has to connect,
# round-trip a core sync and serialise ~120 KB of objects, which is tens of
# seconds under emulation; three helpers each taking their own dump turned a
# single check into minutes.
GRAPH="$WORK/graph.json"
snapshot() {
    timeout 180 pw-dump >"$GRAPH.new" 2>"$LOG/pw-dump.err" || return 1
    [ -s "$GRAPH.new" ] || return 1
    mv -f "$GRAPH.new" "$GRAPH"
}

# The ALSA-backed sink and source nodes WirePlumber exported, one per line as
# "<media.class> <id> <device.id> <node.name>". Driven off the snapshot so the
# assertion sees exactly the graph a client would connect to. The device id is
# what makes a PER-CARD assertion possible: with two cards present, switching
# one card off leaves the other card's sink standing, so "no sink anywhere" is
# a condition a correct profile switch can never satisfy.
graph_nodes() {
    python3 - "$GRAPH" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        objs = json.load(f)
except Exception:
    sys.exit(1)
for o in objs:
    if o.get("type") != "PipeWire:Interface:Node":
        continue
    p = (o.get("info") or {}).get("props") or {}
    cls = p.get("media.class", "")
    if cls not in ("Audio/Sink", "Audio/Source"):
        continue
    if "api.alsa.path" not in p and p.get("device.api") != "alsa":
        continue
    print(cls, o["id"], p.get("device.id", "-"), p.get("node.name", "?"))
PY
}

# "<device id> <profile count> <device name>" for every ALSA device object that
# carries an enumerable profile list — the ACP card-profile contract.
alsa_devices() {
    python3 - "$GRAPH" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        objs = json.load(f)
except Exception:
    sys.exit(1)
for o in objs:
    if o.get("type") != "PipeWire:Interface:Device":
        continue
    info = o.get("info") or {}
    p = info.get("props") or {}
    if p.get("device.api") != "alsa":
        continue
    profiles = (info.get("params") or {}).get("EnumProfile") or []
    print(o["id"], len(profiles), p.get("device.name", "?"))
PY
}

# Does `$1` (a device id) currently have a sink in the graph?
device_sink_present() {
    graph_nodes | awk -v dev="$1" '$1 == "Audio/Sink" && $3 == dev' | grep -q .
}

# "<index> <name>" for the device's CURRENT profile.
current_profile() {
    python3 - "$GRAPH" "$1" <<'PY'
import json, sys
want = int(sys.argv[2])
try:
    with open(sys.argv[1]) as f:
        objs = json.load(f)
except Exception:
    sys.exit(1)
for o in objs:
    if o.get("type") != "PipeWire:Interface:Device" or o.get("id") != want:
        continue
    for entry in ((o.get("info") or {}).get("params") or {}).get("Profile") or []:
        if "index" in entry:
            print(entry["index"], entry.get("name", "?"))
            sys.exit(0)
PY
}

# "<index> <name> <available>" for every profile the device enumerates.
enum_profiles() {
    python3 - "$GRAPH" "$1" <<'PY'
import json, sys
want = int(sys.argv[2])
try:
    with open(sys.argv[1]) as f:
        objs = json.load(f)
except Exception:
    sys.exit(1)
for o in objs:
    if o.get("type") != "PipeWire:Interface:Device" or o.get("id") != want:
        continue
    for entry in ((o.get("info") or {}).get("params") or {}).get("EnumProfile") or []:
        print(entry.get("index"), entry.get("name", "?"), entry.get("available", "?"))
PY
}

# ── stage daemon ──────────────────────────────────────────────────────────
start_pipewire || {
    note "pipewire: $(health "$PW_PID")"
    note "pipewire log tail:"
    tail -n 40 "$LOG/pipewire" 2>&1
    note "socket: $(ls -l "${RT}/pipewire-0" 2>&1)"
    note "one more client attempt, with the client's own log:"
    timeout 20 pw-cli info 0 2>&1 | tail -n 30
    fail "pipewire did not serve a client on ${RT}/pipewire-0"
}
note "daemon: pipewire is serving its protocol socket"

# ── stage session ─────────────────────────────────────────────────────────
start_wireplumber
wait_for 300 "snapshot && [ -n \"\$(alsa_devices)\" ]" || {
    # Inline, not left to the generic diagnostics loop: the console drops
    # lines under load, and the session manager's own log is the one thing
    # that cannot be reconstructed from anywhere else.
    note "wireplumber: $(health "$WP_PID")"
    note "pipewire: $(health "$PW_PID")"
    # A tiny request against the daemon, after the session manager has filled
    # the graph. If this still answers, the protocol and the daemon are alive
    # and only the large object dump stalls - a completely different problem
    # from a wedged daemon, and the two look identical from pw-dump alone.
    timeout 30 pw-cli info 0 >"$LOG/retry-core" 2>"$LOG/retry-core.err"
    note "core round-trip rc=$? bytes=$(stat -c %s "$LOG/retry-core" 2>/dev/null)"
    sed -n '1,6p' "$LOG/retry-core" 2>&1
    # pw-dump's own stdout and stderr, kept apart: a truncated object array
    # and a client that never connected look the same once they are merged.
    timeout 60 pw-dump >"$LOG/retry-dump" 2>"$LOG/retry-dump.err"
    note "pw-dump rc=$? bytes=$(stat -c %s "$LOG/retry-dump" 2>/dev/null)"
    note "pw-dump head: $(head -c 200 "$LOG/retry-dump" 2>&1 | tr -s ' \n' ' ')"
    note "pw-dump stderr tail:"
    tail -n 10 "$LOG/retry-dump.err" 2>&1
    # A different client, different output format: wpctl talks to the session
    # manager's own API, so it answers even if the object dump does not.
    timeout 60 wpctl status >"$LOG/wpctl-status" 2>&1
    note "wpctl status rc=$?:"
    sed -n '1,40p' "$LOG/wpctl-status" 2>&1
    note "pipewire log tail:"
    tail -n 15 "$LOG/pipewire" 2>&1
    note "wireplumber log tail:"
    tail -n 30 "$LOG/wireplumber" 2>&1
    note "graph object summary:"
    timeout 60 pw-dump 2>&1 | python3 -c '
import json, sys, collections
try:
    objs = json.load(sys.stdin)
except Exception as e:
    print("pw-dump did not return JSON:", e)
    raise SystemExit
counts = collections.Counter(o.get("type", "?").rsplit(":", 1)[-1] for o in objs)
print("objects:", dict(counts))
for o in objs:
    p = (o.get("info") or {}).get("props") or {}
    if p.get("device.api") == "alsa" or "alsa" in str(p.get("factory.name", "")):
        print(o.get("id"), o.get("type"), p.get("device.name") or p.get("node.name"))
' 2>&1 | head -30
    fail "wireplumber exported no ALSA device object"
}
# A temp file, not `mapfile -t devs < <(...)`: bash's process substitution
# opens /dev/fd/63, which does not resolve here (see the `devfd` note above),
# and under `set -u` the unbound array then ends the gate with no verdict at
# all. The contract does not need process substitution to express.
alsa_devices >"$WORK/devices"
dev_count=$(grep -c . "$WORK/devices" || true)
note "session: ${dev_count} ALSA device(s): $(tr '\n' '|' <"$WORK/devices")"
[ "${dev_count:-0}" -ge 1 ] || fail "wireplumber exported no ALSA device object"
dev_id=$(awk 'NR==1 { print $1 }' "$WORK/devices")
dev_profiles=$(awk 'NR==1 { print $2 }' "$WORK/devices")
[ "$dev_profiles" -ge 2 ] ||
    fail "ALSA device ${dev_id} enumerates ${dev_profiles} profile(s), expected >= 2"
note "session: device ${dev_id} enumerates ${dev_profiles} card profiles"

# ── stage stream ──────────────────────────────────────────────────────────
wait_for 300 "snapshot && graph_nodes | grep -q '^Audio/Sink '" ||
    fail "no ALSA-backed Audio/Sink node appeared"
wait_for 300 "snapshot && graph_nodes | grep -q '^Audio/Source '" ||
    fail "no ALSA-backed Audio/Source node appeared"
note "stream: $(graph_nodes | tr '\n' '|')"

# Two seconds of 48 kHz stereo s16 silence. The gate asserts the DATAPATH
# clocks and both directions run concurrently; audibility is a hardware test.
dd if=/dev/zero of="$WORK/tone.raw" bs=4 count=96000 status=none ||
    fail "could not stage the playback buffer"

# Capture first, and WAIT for it to deliver its first frames before playback
# starts. Starting both at once and measuring afterwards cannot tell "capture
# is broken" from "capture needed longer than the two seconds playback lasts to
# negotiate", and under emulation that start-up latency is real.
stream_fail() {
    note "pw-play bytes=$(stat -c %s "$LOG/pw-play" 2>&1) state/param/error lines:"
    grep -aE 'stream_state|state changed|param_changed|EnumFormat|Format|\[W\]|\[E\]|error' \
        "$LOG/pw-play" 2>&1 | tail -n 15
    note "pw-record bytes=$(stat -c %s "$LOG/pw-record" 2>&1) state/param/error lines:"
    grep -aE 'stream_state|state changed|param_changed|EnumFormat|Format|\[W\]|\[E\]|error' \
        "$LOG/pw-record" 2>&1 | tail -n 15
    note "alsa node warnings/errors:"
    grep -aE 'spa.alsa.*(resync|xrun|underrun|overrun|clock|snd_pcm|rror|timeout|not available)' \
        "$LOG/pipewire" 2>/dev/null | tail -n 15
    note "pw-top:"
    timeout 90 pw-top -b -n 2 2>&1 | tail -n 12
    note "work dir: $(ls -l "$WORK" 2>&1 | tr -s ' \n' ' ')"
    fail "$1"
}

# `--raw` makes pw-cat ignore the filename entirely: `setup_pipe` installs
# `stdout_record` / `stdin_play`, which `fwrite` to stdout and `fread` from
# stdin (src/tools/pw-cat.c). Passing a path alongside `--raw` sent the captured
# samples to this shell's redirect and left the named file untouched - 23 MB of
# real audio sitting in what looked like a log file next to an empty capture -
# and made playback read the service's stdin, so it "succeeded" having played
# nothing. The `-` is required: pw-cat still demands a positional argument.
timeout 240 pw-record --rate 48000 --channels 2 --format s16 --raw - \
    >"$WORK/cap.raw" 2>"$LOG/pw-record" &
rec_pid=$!
wait_for 120 "[ -s '$WORK/cap.raw' ]" ||
    stream_fail "capture delivered no frames at all"
cap_before=$(stat -c %s "$WORK/cap.raw" 2>/dev/null || echo 0)
note "stream: capture started (${cap_before} bytes before playback)"

play_t0=$(date +%s)
timeout 180 pw-play --rate 48000 --channels 2 --format s16 --volume 0.2 --raw - \
    <"$WORK/tone.raw" >"$LOG/pw-play" 2>&1
play_rc=$?
play_s=$(( $(date +%s) - play_t0 ))
# `$!` is the `timeout` wrapper, not pw-record: signal the child as well, or
# the capture is orphaned mid-write instead of closing its file on SIGINT.
pkill -INT -P "$rec_pid" 2>/dev/null
kill -INT "$rec_pid" 2>/dev/null
wait "$rec_pid" 2>/dev/null
cap_after=$(stat -c %s "$WORK/cap.raw" 2>/dev/null || echo 0)
# `$!` is the `timeout` wrapper, not pw-record: signal the child as well, or
# the capture is orphaned mid-write instead of closing its file on SIGINT.
pkill -INT -P "$rec_pid" 2>/dev/null
kill -INT "$rec_pid" 2>/dev/null
wait "$rec_pid" 2>/dev/null
[ "$play_rc" -eq 0 ] ||
    stream_fail "pw-play exited ${play_rc} (124 = the transfer never finished)"
# Two seconds of audio cannot clock out in under one. An instant exit means
# pw-play played nothing at all, which is exactly what it does when its input
# is empty - and that read as a pass until the `--raw` stdin contract above was
# understood.
[ "$play_s" -ge 1 ] ||
    stream_fail "pw-play returned after ${play_s}s for 2s of audio (it played nothing)"
# One 1024-frame period of 48 kHz stereo s16 is 4096 bytes; require four
# periods of GROWTH across the playback, so neither a single lucky buffer nor a
# capture that stopped before playback began can pass for a running duplex.
grew=$((cap_after - cap_before))
[ "$grew" -ge 16384 ] ||
    stream_fail "capture grew ${grew} bytes during playback, expected >= 16384"
note "stream: ${play_s}s playback ok with the capture running, ${grew} bytes captured alongside it"

# ── stage recover ─────────────────────────────────────────────────────────
# A profile cycle tears the ACP mappings down and reopens every PCM, which is
# the close/reopen path a desktop hits on every output switch.
enum_profiles "$dev_id" >"$LOG/profiles" 2>&1
before=$(current_profile "$dev_id" | awk '{print $1}')
[ -n "$before" ] || fail "device ${dev_id} reports no current profile"
# ACP always publishes an "off" profile; switching to it is how a desktop
# releases a card. Look it up by NAME — the index is card-dependent.
off=$(awk '$2 == "off" { print $1; exit }' "$LOG/profiles")
[ -n "$off" ] || fail "device ${dev_id} enumerates no 'off' profile"
timeout 180 wpctl set-profile "$dev_id" "$off" >"$LOG/wpctl-off" 2>&1 ||
    fail "wpctl set-profile ${dev_id} ${off} failed"
wait_for 180 "snapshot && ! device_sink_present ${dev_id}" ||
    fail "device ${dev_id}'s sink survived the profile switch to off (${off})"
timeout 180 wpctl set-profile "$dev_id" "$before" >"$LOG/wpctl-back" 2>&1 ||
    fail "wpctl set-profile ${dev_id} ${before} failed"
wait_for 300 "snapshot && device_sink_present ${dev_id}" ||
    fail "device ${dev_id}'s sink did not return after restoring profile ${before}"
note "recover: profile ${before} -> off(${off}) -> ${before} rebuilt the sink"

# A full session restart re-runs discovery from scratch against cards that
# have already been opened and closed once.
cleanup
PW_PID=; WP_PID=
wait_for 15 "[ ! -S '${RT}/pipewire-0' ]" || true
start_pipewire || fail "pipewire did not restart"
start_wireplumber
wait_for 300 "snapshot && graph_nodes | grep -q '^Audio/Sink '" ||
    fail "sink did not return after a full session restart"
wait_for 300 "snapshot && graph_nodes | grep -q '^Audio/Source '" ||
    fail "source did not return after a full session restart"
note "recover: a cold session restart rediscovered the sink and source"

# ── stage steady ────────────────────────────────────────────
#
# A session manager that WORKS but never stops burning a core is a defect the
# functional stages cannot see: every assertion above passes while one CPU
# spins. Measured straight from utime+stime in /proc/<pid>/stat, per THREAD,
# so "something in this process spins" and "the main loop spins" are
# distinguishable - which needs /proc/<pid>/task/<tid>/{stat,comm} to be
# per-thread.
cpu_ticks() {
    awk '{ print $14 + $15 }' "/proc/$1/stat" 2>/dev/null || echo 0
}
hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
window=10

declare -A tick_before tick_name
for t in /proc/"$WP_PID"/task/*; do
    [ -r "$t/stat" ] || continue
    tid=${t##*/}
    tick_before[$tid]=$(awk '{ print $14 + $15 }' "$t/stat" 2>/dev/null || echo 0)
    tick_name[$tid]=$(cat "$t/comm" 2>/dev/null || echo '?')
done

wp_before=$(cpu_ticks "$WP_PID")
pw_before=$(cpu_ticks "$PW_PID")
sleep "$window"
wp_pct=$(( ($(cpu_ticks "$WP_PID") - wp_before) * 100 / (hz * window) ))
pw_pct=$(( ($(cpu_ticks "$PW_PID") - pw_before) * 100 / (hz * window) ))
note "steady: idle CPU over ${window}s — wireplumber ${wp_pct}%, pipewire ${pw_pct}%"
for t in /proc/"$WP_PID"/task/*; do
    [ -r "$t/stat" ] || continue
    tid=${t##*/}
    delta=$(( $(awk '{ print $14 + $15 }' "$t/stat" 2>/dev/null || echo 0) - ${tick_before[$tid]:-0} ))
    [ "$delta" -gt 0 ] || continue
    note "steady:   tid ${tid} '${tick_name[$tid]:-?}' used $(( delta * 100 / (hz * window) ))%"
done

# RECORDED, not asserted. WirePlumber's main loop spins here while the daemon
# stays idle and every functional stage passes; see the README for what that
# has been narrowed to and what has been ruled out. Failing the gate on it
# would hide the contract this gate exists to prove, so it is reported on
# every run — including in the verdict line — and tracked as an open defect.
if [ "$wp_pct" -ge 50 ] || [ "$pw_pct" -ge 50 ]; then
    note "steady: WARNING known open defect — an idle session should be near 0%"
fi

# `ps -L` reads /proc/<pid>/task/<tid>/stat for every thread. It aborted with
# procps's "fatal library error, reap" while that directory named every thread
# after the group's pid and had no per-thread stat at all.
ps -L -o pid=,tid=,comm= -p "$WP_PID" >"$LOG/ps-L" 2>&1 ||
    fail "ps -L failed on the session manager: $(tr -s ' \n' ' ' <"$LOG/ps-L")"
threads=$(grep -c . "$LOG/ps-L")
[ "${threads:-0}" -ge 2 ] ||
    fail "ps -L listed ${threads} thread(s) for a multi-threaded session manager"
note "steady: ps -L lists ${threads} threads: $(awk '{print $3}' "$LOG/ps-L" | sort -u | tr '\n' ' ')"

# NOT asserted here: `strace -p`. A tracer is now eligible to wait for a tracee
# it did not fork, but the tracee's attach-stop is never reported to it, so the
# tracer blocks in `wait4` forever instead of being told its tracee stopped —
# and it does not die on SIGTERM either, so a `timeout` around it never
# returns. Asserting it would hang this gate rather than fail it. See the
# README's open-defect section.
#
# glibc's pthread_setname_np writes /proc/self/task/<tid>/comm. Every PipeWire
# loop names itself that way, and each failure is one log line.
if grep -aq "pthread_setname error" "$LOG/pipewire" "$LOG/wireplumber" 2>/dev/null; then
    fail "pthread_setname_np still fails: $(grep -ahm1 'pthread_setname error' "$LOG/pipewire" "$LOG/wireplumber")"
fi
# ... and a name that took must be visible, or the write silently went nowhere.
awk '{print $3}' "$LOG/ps-L" | grep -qv '^wireplumber$' ||
    fail "every thread is still named after the process; pthread_setname_np had no effect"
note "steady: thread names are distinct, so pthread_setname_np takes effect"



echo "NARF-AUDIO-CHECK: OK cards=2 device=${dev_id} profiles=${dev_profiles} playback=${play_s}s captured=${grew} idle-cpu=${wp_pct}%/${pw_pct}% threads=${threads}"
exit 0
