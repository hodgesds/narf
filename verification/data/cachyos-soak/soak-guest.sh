#!/bin/bash
# Guest side of the QEMU soak (run-soak.sh): a desktop-like load on the
# CachyOS root, and samplers that date a stall on the serial console.
#
# Started by narf-soak.service as root. Everything it reports goes to the
# serial console as one line per event, prefixed SOAK-, so the kernel's own
# lines (watchdog:, nvme:, btrfs:, oom:) stay readable between them.
#
# The samplers use shell builtins and /proc only: on the hardware hang
# /proc and fork+exec of a small binary kept working after file and bus
# calls had stopped, so a sampler that forks `ps` or calls `loginctl` would
# go quiet with the thing it is watching.
#   SOAK-PULSE   every second: uptime, load, free and available memory
#   SOAK-CPU     every 2 s: per-CPU busy/system percent; `f` marks a CPU
#                whose counters did not advance (no timer tick), BUSY-STREAK
#                lists CPUs that have been fully busy for 5 samples or more
#   SOAK-PROBE   every 3 s: milliseconds for a loginctl call, a busctl call,
#                a systemctl call, a cold file read, a write+fsync, an exec
#                and a directory listing; STUCK(<s>) while one has not come
#                back
#   SOAK-SAMPLE  every 5 s: meminfo, pressure, task states, what tasks are
#                waiting in (SOAK-FSWAIT names the ones inside munmap, msync,
#                fsync, truncate, rename, unlink or exit), the busiest and
#                largest tasks, worker progress
#
# Before the load, SOAK_DIRECTED=1 runs single operations one at a time on
# the quiet system, each bracketed by SOAK-EPISODE lines, so the samples and
# the kernel's lockup reports between two brackets belong to one operation:
# exits and fork+execs of a process with dirty shared pages, long single
# system calls that touch no mapping (large writes and reads, fsync, cp,
# unlink), and the journal readers an ordinary boot runs.
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
D=/run/narf-soak
# shellcheck disable=SC1090
[ -r "$D/soak-settings.env" ] && . "$D/soak-settings.env"
: "${SOAK_SECS:=1200}" "${SOAK_HEAVY_SECS:=420}" "${SOAK_HTTP_PORT:=42080}"
: "${SOAK_TLS_PORT:=42443}" "${SOAK_UDP_PORT:=42053}" "${SOAK_LISTEN_PORT:=5201}"
: "${SOAK_VIRTIO_NET:=10.0.2}" "${SOAK_E1000_NET:=10.0.3}" "${SOAK_POWEROFF:=1}"
: "${SOAK_DROP_SECS:=30}" "${SOAK_BIG_MB:=0}" "${SOAK_XFER_MB:=100}"
: "${SOAK_DIRECTED:=1}" "${SOAK_DIRTYEXIT:=0}" "${SOAK_SHARED_MAPS:=1}" "${SOAK_DURABLE:=0}"
: "${SOAK_SETTLE:=cpu}"
# <MiB>:<exit|kill> rounds of a process that dies with dirty shared pages.
: "${SOAK_EXITWB:=8:exit 32:exit 32:kill}"
# <window seconds>:<dirty MiB>:<forks per second> rounds of the forking parent.
# A fourth field `clean` makes the mapping read-only-touched (nothing dirty).
: "${SOAK_FORKFLUSH:=10:1:1 10:16:1 3:48:1}"
# Files the host checks after the run live in @ itself, outside the soak's
# scratch directories (which are removed at the end).
DATA=/narf-soak-data
W=/var/tmp/narf-soak
TREE=/home/narf/src/narf
HB=$D/hb
PY="python3 $D/soak-guest.py"
NATIVE=$D/soak-native
mkdir -p "$HB" "$D/err" "$D/out" "$D/probe" "$W"
exec 7> /dev/ttyS0 || exec 7> /dev/console

say() { printf '%s\n' "$*" >&7; }
# Sets UP to the uptime without a fork.
stamp() { read -r UP _ < /proc/uptime; }

# Sleeping without a fork: a timed read on a FIFO nobody writes to. Without
# that, bash's loadable sleep builtin, and only then sleep(1).
NAP_FIFO=0
[ -e "$D/tick" ] || mkfifo "$D/tick" 2> /dev/null
if exec 9<> "$D/tick"; then
  read -r -t 0.01 <&9
  (($? > 128)) && NAP_FIFO=1
fi 2> /dev/null
((NAP_FIFO)) || enable -f /usr/lib/bash/sleep sleep 2> /dev/null
nap() {
  if ((NAP_FIFO)); then
    read -r -t "$1" <&9
  else
    sleep "$1"
  fi
}

# ── samplers ────────────────────────────────────────────────────────

pulse() {
  local k v free avail load
  while :; do
    free=0 avail=0
    while read -r k v _; do
      case $k in
        MemFree:) free=$v ;;
        MemAvailable:) avail=$v ;;
      esac
    done < /proc/meminfo
    read -r load < /proc/loadavg
    stamp
    say "SOAK-PULSE up=$UP free_kb=$free avail_kb=$avail load=$load"
    nap 1
  done
}

cpu_sampler() {
  local -A ptotal pidle psys
  local name user nice system idle iowait irq softirq steal _ total d line stuck
  local -A sysrun
  while :; do
    line=""
    stuck=""
    while read -r name user nice system idle iowait irq softirq steal _; do
      case $name in cpu[0-9]*) ;; *) continue ;; esac
      total=$((user + nice + system + idle + iowait + irq + softirq + steal))
      if [ -n "${ptotal[$name]}" ]; then
        d=$((total - ptotal[$name]))
        if ((d <= 0)); then
          line+=" ${name#cpu}:f"
        else
          local busy=$((100 - 100 * (idle + iowait - pidle[$name]) / d))
          local sys=$((100 * (system + irq + softirq - psys[$name]) / d))
          line+=" ${name#cpu}:$busy/$sys"
          # A captured CPU is busy in every sample from then on. What the
          # time is charged to says little: kernel work done for no task
          # is not reliably system time.
          if ((busy >= 99)); then
            sysrun[$name]=$((${sysrun[$name]:-0} + 1))
            ((sysrun[$name] >= 5)) && stuck+=" ${name#cpu}x${sysrun[$name]}"
          else
            sysrun[$name]=0
          fi
        fi
      fi
      ptotal[$name]=$total
      pidle[$name]=$((idle + iowait))
      psys[$name]=$((system + irq + softirq))
    done < /proc/stat
    stamp
    [ -n "$line" ] && say "SOAK-CPU up=$UP busy/sys%$line${stuck:+ BUSY-STREAK$stuck}"
    nap 2
  done
}

probe_loginctl() { loginctl list-sessions --no-legend --no-pager; }
probe_busctl() {
  busctl --system --no-pager call org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus GetId
}
probe_systemctl() { systemctl is-system-running; :; }
probe_coldread() { cat "$W/cold/f$((PROBE_SEQ % 3000))"; }
probe_fsync() { printf '%s\n' "$PROBE_SEQ" > "$W/probe-fsync" && sync "$W/probe-fsync"; }
probe_exec() { /usr/bin/true; }
probe_lsdir() { ls -l "$TREE/userspace/src"; }

probes() {
  local names=(loginctl busctl systemctl coldread fsync exec lsdir)
  local -A launched started
  local n=0 name seq ms rc line now
  while :; do
    n=$((n + 1))
    for name in "${names[@]}"; do
      seq=0
      [ -r "$D/probe/$name" ] && read -r seq ms rc < "$D/probe/$name"
      if [ -z "${launched[$name]}" ] || [ "$seq" = "${launched[$name]}" ]; then
        launched[$name]=$n
        started[$name]=$SECONDS
        (
          PROBE_SEQ=$n
          t0=${EPOCHREALTIME/./}
          "probe_$name" > /dev/null 2>&1
          rc=$?
          t1=${EPOCHREALTIME/./}
          printf '%s %s %s\n' "$n" $(((t1 - t0) / 1000)) "$rc" > "$D/probe/$name"
        ) &
      fi
    done
    nap 3
    stamp
    line="SOAK-PROBE up=$UP ms:"
    now=$SECONDS
    for name in "${names[@]}"; do
      seq=0 ms=0 rc=0
      [ -r "$D/probe/$name" ] && read -r seq ms rc < "$D/probe/$name"
      if [ "$seq" = "${launched[$name]}" ]; then
        line+=" $name=$ms"
        [ "$rc" != 0 ] && line+="(rc$rc)"
      else
        line+=" $name=STUCK($((now - started[$name]))s)"
      fi
    done
    say "$line"
  done
}

# Keep the six largest (value, label) pairs in the arrays named $1 and $2.
top_insert() {
  local -n values=$1 labels=$2
  local v=$3 i j
  for ((i = 0; i < 6; i++)); do
    if ((v > ${values[i]:-0})); then
      for ((j = 5; j > i; j--)); do
        values[j]=${values[j - 1]:-0}
        labels[j]=${labels[j - 1]:-}
      done
      values[i]=$v
      labels[i]=$4
      return
    fi
  done
}

sampler() {
  local n=0 k v line task stat rest state wchan comm pid tid key i
  local -A prev_cpu
  while :; do
    n=$((n + 1))
    stamp
    line="SOAK-SAMPLE n=$n up=$UP mem:"
    while read -r k v _; do
      line+=" ${k%:}=$v"
    done < /proc/meminfo
    say "$line"
    if ((n % 12 == 0)) && [ -r /proc/narf/slab ]; then
      line="SOAK-SLAB n=$n"
      while read -r k v; do
        [ "$v" = 0 ] || line+=" $k=$v"
      done < <(cat /proc/narf/slab /proc/narf/rcu 2> /dev/null)
      say "$line"
    fi
    ((n % 36 == 0)) && slab_sites "n=$n"
    for k in cpu memory io; do
      [ -r /proc/pressure/$k ] || continue
      while read -r line; do say "SOAK-PSI $k $line"; done < /proc/pressure/$k
    done
    # One pass over every thread: state counts, what each is waiting in,
    # CPU time since the last pass and resident size.
    local -A states=() waits=() now_cpu=()
    local odd="" nodd=0 total=0 fswait="" nfs=0
    local -a f cpu_v=() cpu_l=() rss_v=() rss_l=()
    for task in /proc/[0-9]*/task/[0-9]*; do
      read -r stat 2> /dev/null < "$task/stat" || continue
      tid=${task##*/}
      pid=${task#/proc/}
      pid=${pid%%/*}
      comm=${stat#*(}
      comm=${comm%)*}
      rest=${stat##*) }
      # shellcheck disable=SC2206
      f=($rest)
      state=${f[0]}
      total=$((total + 1))
      states[$state]=$((${states[$state]:-0} + 1))
      wchan=-
      read -r wchan 2> /dev/null < "$task/wchan"
      [ -z "$wchan" ] && wchan=-
      waits[$wchan]=$((${waits[$wchan]:-0} + 1))
      now_cpu[$tid]=$((f[11] + f[12]))
      local d=$((now_cpu[$tid] - ${prev_cpu[$tid]:-${now_cpu[$tid]}}))
      ((d > 0)) && top_insert cpu_v cpu_l "$d" "$comm/$tid"
      [ "$tid" = "$pid" ] && top_insert rss_v rss_l "${f[21]}" "$comm/$pid"
      if [ "$state" = D ] && ((nodd < 12)); then
        key=-
        read -r key _ 2> /dev/null < "$task/syscall"
        odd+=" $comm/$tid:$wchan:sys$key"
        nodd=$((nodd + 1))
      fi
      # Who is inside the filesystem: the one in munmap, msync or exit is
      # usually what the ones in openat and fsync are waiting for.
      case $wchan in
        munmap | msync | fsync | fdatasync | ftruncate | truncate | exit | exit_group | unlinkat | renameat | rename)
          ((nfs < 16)) && fswait+=" ${comm// /_}/$tid:$wchan"
          nfs=$((nfs + 1))
          ;;
      esac
    done
    prev_cpu=()
    for k in "${!now_cpu[@]}"; do prev_cpu[$k]=${now_cpu[$k]}; done
    line="SOAK-TASKS n=$n threads=$total states:"
    for k in "${!states[@]}"; do line+=" $k=${states[$k]}"; done
    line+=" waits:"
    for k in "${!waits[@]}"; do line+=" $k=${waits[$k]}"; done
    say "$line"
    [ -n "$odd" ] && say "SOAK-BLOCKED n=$n$odd"
    [ -n "$fswait" ] && say "SOAK-FSWAIT n=$n count=$nfs$fswait"
    line="SOAK-TOP n=$n cpu_ticks:"
    for i in "${!cpu_v[@]}"; do line+=" ${cpu_l[i]// /_}=${cpu_v[i]}"; done
    line+=" rss_pages:"
    for i in "${!rss_v[@]}"; do line+=" ${rss_l[i]// /_}=${rss_v[i]}"; done
    say "$line"
    line="SOAK-HB n=$n"
    for k in "$HB"/*; do
      [ -r "$k" ] || continue
      read -r v < "$k"
      line+=" ${k##*/}=${v// /,}"
    done
    say "$line"
    if ((n % 6 == 1)); then
      # What the memory cgroups are charged with, against what is in use.
      line="SOAK-CGROUP n=$n"
      for k in system.slice system.slice/narf-soak.service system.slice/ananicy-cpp.service \
        user.slice init.scope; do
        v=-
        [ -r "/sys/fs/cgroup/$k/memory.current" ] && read -r v < "/sys/fs/cgroup/$k/memory.current"
        line+=" ${k##*/}=$v"
      done
      for k in /sys/fs/cgroup/system.slice/ananicy-cpp.service/memory.events \
        /sys/fs/cgroup/system.slice/narf-soak.service/memory.events; do
        [ -r "$k" ] || continue
        while read -r a b; do [ "$a" = max ] && line+=" ${k%/memory.events}:max_events=$b"; done < "$k"
      done
      say "${line//\/sys\/fs\/cgroup\//}"
      while read -r line; do
        case $line in *eth* | *lo:*) say "SOAK-NETDEV n=$n $line" ;; esac
      done < /proc/net/dev
      while read -r line; do say "SOAK-IRQ n=$n $line"; done < /proc/interrupts
    fi
    nap 5
  done
}

# ── workers ─────────────────────────────────────────────────────────

fail() { # name message
  local n=0
  [ -r "$D/err/$1.count" ] && read -r n < "$D/err/$1.count"
  n=$((n + 1))
  printf '%s\n' "$n" > "$D/err/$1.count"
  stamp
  ((n <= 12)) && say "SOAK-ERR $1 #$n up=$UP: $2"
}

# Run a command over and over until the load deadline; a failing exit is
# reported with the last line it wrote to stderr.
worker() { # name command...
  local name=$1 rc last
  shift
  (
    while ((SECONDS < END)); do
      "$@" >> "$D/out/$name.log" 2>> "$D/err/$name.log"
      rc=$?
      if ((rc != 0)) && ((SECONDS < END)); then
        last=""
        while read -r line; do last=$line; done < "$D/err/$name.log"
        fail "$name" "exit $rc: $last"
      fi
      nap 1
    done
  ) &
}

left() { local s=$((END - SECONDS)); ((s < 1)) && s=1; printf '%s' "$s"; }
hb() { printf '%s\n' "$2" > "$HB/$1"; }

w_trees() {
  local n=0
  while ((SECONDS < END)); do
    rg -c 'unsafe' "$TREE" > /dev/null
    git -c safe.directory="$TREE" -C "$TREE" status --short > /dev/null || return 1
    git -c safe.directory="$TREE" -C "$TREE" grep -c spin_lock > /dev/null
    find "$TREE" -type f -name '*.rs' -size +4k > /dev/null
    grep -r -l 'narf_scheduler' "$TREE/drivers" > /dev/null
    pacman -Qk > /dev/null 2>&1
    n=$((n + 1))
    hb trees "$n"
  done
}

w_journal() {
  local n=0 pad i
  pad=$(printf 'x%.0s' {1..300})
  while ((SECONDS < END)); do
    # The loop body is one side of a pipe, so it cannot count for us.
    for i in 1 2 3 4 5 6 7 8 9 10; do
      printf 'soak journal line %s %s\n' "$((n + i))" "$pad"
    done | systemd-cat -t narf-soak || return 1
    n=$((n + 10))
    ((n % 500 == 0)) && { journalctl -n 20 --no-pager > /dev/null || return 1; }
    hb journal "$n"
    nap 0.2
  done
}

w_dropcache() {
  local n=0
  ((SOAK_DROP_SECS > 0)) || return 0
  while ((SECONDS < END)); do
    nap "$SOAK_DROP_SECS"
    echo 1 > /proc/sys/vm/drop_caches
    n=$((n + 1))
    hb dropcache "$n"
  done
}

w_forkexec() {
  local n=0 x
  while ((SECONDS < END)); do
    for _ in 1 2 3 4 5 6 7 8 9 10; do /usr/bin/true; done
    x=$(ls /usr/bin | wc -l)
    [ "$x" -gt 100 ] || return 1
    echo hello | cat | cat | tr a-z A-Z | grep -c HELLO > /dev/null || return 1
    bash -c 'exit 3'
    env -i /usr/bin/printenv > /dev/null
    (exec sleep 0.01) &
    wait $!
    n=$((n + 1))
    ((n % 20 == 0)) && hb "forkexec$1" "$n"
  done
}

w_script() {
  local n=0
  while ((SECONDS < END)); do
    script -qec 'ls -la /usr/bin | tail -n 300; stty -a; tty' /dev/null > /dev/null || return 1
    n=$((n + 1))
    hb script "$n"
  done
}

w_tmux() {
  local n=0 t="tmux -L soak"
  while ((SECONDS < END)); do
    $t new-session -d -s "s$n" -x 200 -y 50 \
      'while :; do ls -la /usr/lib | tail -n 60; date; sleep 0.1; done' || return 1
    $t split-window -t "s$n" 'while :; do cat /proc/loadavg /proc/meminfo; sleep 0.2; done'
    $t send-keys -t "s$n" q
    nap 2
    $t capture-pane -p -t "s$n" > /dev/null
    $t kill-session -t "s$n" || return 1
    n=$((n + 1))
    hb tmux "$n"
  done
  $t kill-server 2> /dev/null
  :
}

w_dbus() {
  local n=0
  while ((SECONDS < END)); do
    busctl --system --no-pager call org.freedesktop.DBus /org/freedesktop/DBus \
      org.freedesktop.DBus ListNames > /dev/null || return 1
    systemctl list-units --no-pager --no-legend > /dev/null || return 1
    systemctl show sshd.service -p MainPID > /dev/null
    loginctl list-sessions --no-legend > /dev/null
    hostnamectl status > /dev/null 2>&1
    ((n % 10 == 0)) && systemd-run --wait --quiet --collect /usr/bin/true
    n=$((n + 1))
    hb dbus "$n"
    nap 0.2
  done
}

w_killtools() {
  local n=0 pid
  mkdir -p "$W/kill"
  while ((SECONDS < END)); do
    case $((n % 7)) in
      0) dd if=/dev/zero of="$W/kill/dd" bs=1M count=256 conv=fsync 2> /dev/null & ;;
      1) cat "$W/big.bin" > /dev/null & ;;
      2) tar cf - "$TREE" 2> /dev/null > /dev/null & ;;
      3) rg -c fn "$TREE" > /dev/null & ;;
      4) sha256sum "$W/big.bin" > /dev/null & ;;
      5) cp -r "$TREE/userspace" "$W/kill/cp$((n % 3))" 2> /dev/null & ;;
      6) git -c safe.directory="$TREE" -C "$TREE" status > /dev/null 2>&1 & ;;
    esac
    pid=$!
    nap "0.$((RANDOM % 9))$((RANDOM % 10))"
    kill -9 "$pid" 2> /dev/null
    wait "$pid" 2> /dev/null
    ((n % 21 == 20)) && rm -rf "$W/kill"/cp*
    n=$((n + 1))
    hb killtools "$n"
  done
}

w_cores() {
  local n=0 orig
  mkdir -p "$W/cores"
  cd "$W/cores" || return 1
  ulimit -c unlimited
  read -r orig < /proc/sys/kernel/core_pattern
  while ((SECONDS < END)); do
    # The distribution's pattern first (a pipe to systemd-coredump), then a
    # file pattern so a core is really written to the btrfs root.
    (bash -c 'kill -SEGV $$') 2> /dev/null
    printf '%s\n' "$W/cores/core.%e.%p" > /proc/sys/kernel/core_pattern
    ($PY crash 64) 2> /dev/null
    (bash -c 'kill -ABRT $$') 2> /dev/null
    hb cores "$n files=$(ls | wc -l)"
    rm -f core.*
    printf '%s\n' "$orig" > /proc/sys/kernel/core_pattern
    n=$((n + 1))
    nap 4
  done
}

w_anon() {
  local n=0 mb=$((MEM_MB / 10))
  while ((SECONDS < END)); do
    python3 -c "
import time
b = bytearray($mb << 20)
for i in range(0, len(b), 4096): b[i] = 1
time.sleep(1)" || return 1
    n=$((n + 1))
    hb "anon$1" "$n"
  done
}

w_curl() {
  local n=0 host=$1
  while ((SECONDS < END)); do
    curl -sS -m 120 -o /dev/null "http://$host:$SOAK_HTTP_PORT/down?mb=50" || return 1
    curl -sS -m 120 -o /dev/null -T "$W/up.bin" "http://$host:$SOAK_HTTP_PORT/up" || return 1
    curl -sS -k -m 120 -o /dev/null "https://$host:$SOAK_TLS_PORT/down?mb=20" || return 1
    n=$((n + 1))
    hb "curl-$2" "$n"
  done
}

# A process that dirties a shared file mapping and exits (or is killed)
# without msync, over and over; each round's measurements go to the console.
w_dirtyexit() { # id mode
  local n=0 mib=$((MEM_MB / 128)) line
  ((mib > 256)) && mib=256
  ((mib < 16)) && mib=16
  nap "$(($1 * 7))"
  while ((SECONDS < END)); do
    line=$(DIRTYEXIT_WINDOW_MS=3000 "$NATIVE" dirtyexit "$mib" "$W/dirty$1.bin" "$2" \
      "$TREE/userspace") || return 1
    n=$((n + 1))
    hb "dirtyexit$1" "$n"
    stamp
    say "SOAK-DIRTYEXIT up=$UP id=$1 ${line#dirtyexit: }"
    nap 3
  done
}

w_idlers() {
  local i
  for i in $(seq 1 30); do
    (while ((SECONDS < END)); do nap "0.$((RANDOM % 9 + 1))"; done) &
  done
  wait
}

# ── directed episodes ───────────────────────────────────────────────

# Highest busy percentage of any CPU over the next second.
busiest_cpu() {
  local name user nice system idle iowait irq softirq steal _ total d
  local -A t0 i0
  while read -r name user nice system idle iowait irq softirq steal _; do
    case $name in cpu[0-9]*) ;; *) continue ;; esac
    t0[$name]=$((user + nice + system + idle + iowait + irq + softirq + steal))
    i0[$name]=$((idle + iowait))
  done < /proc/stat
  nap 1
  BUSIEST=0
  while read -r name user nice system idle iowait irq softirq steal _; do
    case $name in cpu[0-9]*) ;; *) continue ;; esac
    total=$((user + nice + system + idle + iowait + irq + softirq + steal))
    d=$((total - t0[$name]))
    ((d > 0)) || continue
    d=$((100 - 100 * (idle + iowait - i0[$name]) / d))
    ((d > BUSIEST)) && BUSIEST=$d
  done < /proc/stat
}

# Run one command alone and bracket it on the console. A process that has
# exited can leave work behind it (its address space is torn down later, on
# whichever CPU drops it), so the episode lasts until no CPU has been busy
# for three seconds, and says how long that took.
episode() { # name command...
  local name=$1 t0 t1 t2 rc line quiet=0
  shift
  stamp
  say "SOAK-EPISODE begin $name up=$UP"
  t0=${EPOCHREALTIME/./}
  "$@" > "$D/out/episode-$name.log" 2>&1
  rc=$?
  t1=${EPOCHREALTIME/./}
  stamp
  say "SOAK-EPISODE returned $name up=$UP ms=$(((t1 - t0) / 1000)) rc=$rc"
  while read -r line; do
    say "SOAK-EPISODE out $name: ${line:0:330}"
  done < <(tail -n 6 "$D/out/episode-$name.log")
  # SOAK_SETTLE=cpu waits until no CPU has been busy for three seconds (up to
  # five minutes), from /proc/stat; a number waits that many seconds. Use a
  # number on a kernel whose per-CPU /proc/stat counters are not monotonic
  # (tickless idle), and read captures from the host's vCPU samples.
  if [ "$SOAK_SETTLE" = cpu ]; then
    while ((quiet < 3 && (${EPOCHREALTIME/./} - t1) / 1000000 < 300)); do
      busiest_cpu
      if ((BUSIEST >= 60)); then quiet=0; else quiet=$((quiet + 1)); fi
    done
  else
    nap "$SOAK_SETTLE"
  fi
  t2=${EPOCHREALTIME/./}
  stamp
  say "SOAK-EPISODE end $name up=$UP busy_after_return_ms=$(((t2 - t1) / 1000 - 3000))"
}

# Time a command five times in a row.
five_times() {
  local i t0
  for i in 1 2 3 4 5; do
    t0=${EPOCHREALTIME/./}
    "$@" > /dev/null 2>&1
    echo "run $i: $(((${EPOCHREALTIME/./} - t0) / 1000)) ms rc=$?"
  done
}

journal_fill() { # MiB
  local n=0 pad lines=$(($1 * 2048))
  pad=$(printf 'x%.0s' {1..440})
  local i
  while ((n < lines)); do
    # The loop body is one side of a pipe, so it cannot count for us.
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
      printf 'soak journal fill %s %s\n' "$((n + i))" "$pad"
    done | systemd-cat -t narf-soak-fill
    n=$((n + 16))
  done
  journalctl --disk-usage --no-pager
}

# Shell `>` redirections onto tmpfs (each one an open with O_TRUNC), timed,
# while a mapper churns in the background.
redirect_storm() { # secs mib
  local i t0 t worst=0 slow=0 n=0
  "$NATIVE" mapchurn "$1" "$2" "$W/ep/churn.bin" &
  local churn=$!
  local end=$((SECONDS + $1))
  while ((SECONDS < end)); do
    t0=${EPOCHREALTIME/./}
    printf 'x%s\n' "$n" > "/tmp/soak-redir-$((n % 8))"
    t=$(((${EPOCHREALTIME/./} - t0) / 1000))
    ((t > worst)) && worst=$t
    ((t > 100)) && slow=$((slow + 1))
    n=$((n + 1))
  done
  wait "$churn"
  echo "redirect-storm: redirections=$n slower_than_100ms=$slow worst_ms=$worst"
}

# The durability check: data written through shared mappings and left
# behind in different ways, then a hard stop the host performs on
# SOAK-HARDSTOP. The host reads the files back from the image.
durable_run() {
  mkdir -p "$DATA/dur"
  rm -f "$DATA/dur"/*
  sync
  local line
  for spec in exit:A:101 kill:B:102; do
    IFS=: read -r mode name seed <<< "$spec"
    line=$("$NATIVE" durable "$DATA/dur/$name.bin" 32 "$mode" "$seed" 2>&1)
    stamp
    say "SOAK-DURABLE up=$UP $line"
  done
  stamp
  say "SOAK-DURABLE up=$UP waiting 40 s with the guest idle for the flusher"
  nap 40
  for spec in nosync:E:105 msync:C:103 fsync:D:104; do
    IFS=: read -r mode name seed <<< "$spec"
    line=$("$NATIVE" durable "$DATA/dur/$name.bin" 32 "$mode" "$seed" 2>&1)
    stamp
    say "SOAK-DURABLE up=$UP $line"
  done
  stamp
  say "SOAK-HARDSTOP up=$UP"
  while :; do nap 60; done
}

w_integrity() {
  mkdir -p "$DATA" || return 1
  # The exit status is the tool's, not the pipe's last stage.
  set -o pipefail
  "$NATIVE" integrity "$1" "$DATA/integ" 4 "$HB/integrity" 2>&1 |
    while read -r line; do say "SOAK-INTEG $line"; done
}

directed() {
  local spec window mib rate kind
  mkdir -p "$W/ep"
  # The operations that leave nothing behind come first. An exit with dirty
  # shared pages can keep a CPU and the filesystem busy for minutes after
  # it, and whatever ran next would be measuring that instead of itself.
  # One large munmap of a dirty shared mapping, the first touch of a clean
  # one, and truncating opens on tmpfs while another process maps, dirties
  # and unmaps 256 MiB over and over.
  episode munmap-128m "$NATIVE" munmapbig 128 "$W/ep/munmap.bin"
  episode firsttouch-256m "$NATIVE" firsttouch 256 "$W/ep/touch.bin"
  episode redirect-storm redirect_storm 30 256
  # (c) long system calls that touch no mapping.
  episode write-256x1m $PY bigwrite "$W/ep/w1" 1 256 nofsync
  episode write-4x64m $PY bigwrite "$W/ep/w2" 64 4 nofsync
  episode write-1x256m $PY bigwrite "$W/ep/w3" 256 1 nofsync
  episode write-128x1m-fsync $PY bigwrite "$W/ep/w4" 1 128 fsync
  episode read-256x1m dd if="$W/ep/w1" of=/dev/null bs=1M
  episode read-4x64m dd if="$W/ep/w2" of=/dev/null bs=64M
  episode cp-256m cp --reflink=never "$W/ep/w1" "$W/ep/copy"
  episode sha256-256m sha256sum "$W/ep/w3"
  episode git-status git -c safe.directory="$TREE" -C "$TREE" status --short
  episode rg-tree rg -c unsafe "$TREE"
  episode truncate-256m truncate -s 0 "$W/ep/w3"
  episode unlink-256m rm -f "$W/ep/w1"
  episode write-1x1024m $PY bigwrite "$W/ep/w5" 1024 1 nofsync
  episode unlink-1024m rm -f "$W/ep/w5"
  episode rm-rest rm -rf "$W/ep"
  # (d) what an ordinary boot does: readers of journald's mapped journal.
  episode journal-fill journal_fill 4
  (while :; do
    printf 'soak journal trickle %s\n' "$SECONDS" | systemd-cat -t narf-soak-fill
    nap 0.5
  done) &
  local trickle=$!
  survey_shared journal
  episode journalctl-n1 five_times journalctl -n 1 --no-pager
  episode systemctl-status five_times systemctl status sshd.service --no-pager
  episode loginctl-sessions five_times loginctl list-sessions --no-pager
  episode journalctl-unit five_times journalctl -b -u sshd.service --no-pager
  kill "$trickle" 2> /dev/null
  mkdir -p "$W/ep"
  # (b) a process dies with dirty shared pages.
  for spec in $SOAK_EXITWB; do
    # The capture after the exit is read from the host's samples; the tool's
    # own /proc/stat watch is only kept for ten seconds.
    episode "die-${spec##*:}-${spec%%:*}m" env DIRTYEXIT_WINDOW_MS=10000 "$NATIVE" dirtyexit \
      "${spec%%:*}" "$W/ep/dirty.bin" \
      "${spec##*:}" "$TREE/userspace"
  done
  # (a) a long-lived parent keeps N MiB of a shared mapping dirty and forks
  # a child that execs /usr/bin/true once per period.
  for spec in $SOAK_FORKFLUSH; do
    IFS=: read -r window mib rate kind <<< "$spec"
    if [ "$kind" = clean ]; then
      episode "forkexec-clean-${mib}m" env FORKPARENT_CLEAN=1 "$NATIVE" forkparent "$window" \
        "$mib" "$rate" "$W/ep/forkparent.bin" "$HB/forkparent"
    else
      episode "forkexec-dirty-${mib}m" "$NATIVE" forkparent "$window" "$mib" "$rate" \
        "$W/ep/forkparent.bin" "$HB/forkparent"
    fi
  done
  rm -f "$HB/forkparent"
}

# ── run ─────────────────────────────────────────────────────────────

net_up() {
  local dev name mac drv addr
  for dev in /sys/class/net/*; do
    name=${dev##*/}
    [ "$name" = lo ] && continue
    read -r mac < "$dev/address"
    drv=$(ethtool -i "$name" 2> /dev/null | sed -n 's/^driver: //p')
    # QEMU numbers its NICs in command-line order: e1000 first, virtio-net second.
    case "$drv:$mac" in
      virtio*:* | :52:54:00:12:34:57) addr=$SOAK_VIRTIO_NET ;;
      e1000*:* | :52:54:00:12:34:56) addr=$SOAK_E1000_NET ;;
      *) addr="" ;;
    esac
    say "SOAK-NET $name mac=$mac driver=${drv:-?} -> ${addr:-unused}"
    [ -n "$addr" ] || continue
    ip link set "$name" up || say "SOAK-ERR net: ip link set $name up failed"
    ip addr add "$addr.15/24" dev "$name" || say "SOAK-ERR net: ip addr add on $name failed"
  done
  ip route add default via "$SOAK_VIRTIO_NET.2" 2> /dev/null
  HOSTS=()
  for addr in "$SOAK_VIRTIO_NET" "$SOAK_E1000_NET"; do
    if curl -sS -m 10 -o /dev/null "http://$addr.2:$SOAK_HTTP_PORT/ping" 2> "$D/err/net.log"; then
      say "SOAK-NET host $addr.2 reachable"
      HOSTS+=("$addr.2")
    else
      say "SOAK-ERR net: host $addr.2 unreachable: $(tail -n 1 "$D/err/net.log")"
    fi
  done
}

# Which processes hold shared file mappings (the pages a fork, an exec or an
# exit may have to write back), from /proc/<pid>/maps.
survey_shared() { # label
  local maps pid comm range perms path n=0 shown
  for maps in /proc/[0-9]*/maps; do
    pid=${maps#/proc/}
    pid=${pid%/maps}
    comm=?
    read -r comm 2> /dev/null < "/proc/$pid/comm"
    shown=0
    while read -r range perms _ _ _ path; do
      case $perms in *s) ;; *) continue ;; esac
      case $path in '' | /dev/* | /memfd:* | /SYSV* | '['*) continue ;; esac
      n=$((n + 1))
      shown=$((shown + 1))
      ((shown <= 8)) || continue
      say "SOAK-SHMAP $1 $comm/$pid $perms $(((16#${range#*-} - 16#${range%-*}) / 1024))K $path"
    done < "$maps" 2> /dev/null
    ((shown > 8)) && say "SOAK-SHMAP $1 $comm/$pid ... $shown shared file mappings in all"
  done
  say "SOAK-SHMAP $1 total=$n"
}

# Who holds the heap (NARF only): the live bytes per allocation site, top 30,
# as .text offsets to symbolize against the run's kernel.
slab_sites() { # label
  local n=0 line
  [ -r /proc/narf/slab_sites ] || return 0
  while read -r line; do
    n=$((n + 1))
    ((n <= 33)) && say "SOAK-SITES $1 $line"
  done < /proc/narf/slab_sites
}

settle_meminfo() { # label
  local k v line
  sync
  echo 3 > /proc/sys/vm/drop_caches
  nap 3
  stamp
  line="$1 up=$UP"
  while read -r k v _; do
    case $k in MemTotal: | MemFree: | MemAvailable: | Cached: | Slab: | SUnreclaim: | AnonPages: | Shmem: | KernelStack: | PageTables:)
      line+=" ${k%:}=$v" ;;
    esac
  done < /proc/meminfo
  say "$line"
  # Where the kernel heap's frames are (NARF only): live objects against
  # frames per size class separates a leak from retained free memory.
  if [ -r /proc/narf/slab ]; then
    line="SOAK-SLAB $1"
    while read -r k v; do
      [ "$v" = 0 ] || line+=" $k=$v"
    done < <(cat /proc/narf/slab /proc/narf/rcu 2> /dev/null)
    say "$line"
  fi
  slab_sites "$1"
}

read -r _ MEM_KB _ < /proc/meminfo
MEM_MB=$((MEM_KB / 1024))
# Buffered writes run at some tens of MiB/s here, and nothing read stays
# cached, so a larger file buys a longer setup and no colder reads.
((SOAK_BIG_MB > 0)) || SOAK_BIG_MB=1024
read -r cmdline < /proc/cmdline
stamp
say "SOAK-START up=$UP nap_fifo=$NAP_FIFO mem_mb=$MEM_MB cpus=$(nproc) secs=$SOAK_SECS heavy=$SOAK_HEAVY_SECS big_mb=$SOAK_BIG_MB"
say "SOAK-CMDLINE $cmdline"
say "SOAK-UNAME $(uname -a)"

# The samplers stay on the last CPU when the kernel honours affinity, so a
# CPU captured elsewhere cannot silence them; everything else stays off it.
LAST_CPU=$(($(nproc) - 1))
KEEP=" $$ "
pulse &
KEEP+="$! "
PINNED="$!"
cpu_sampler &
KEEP+="$! "
PINNED+=" $!"
if ((LAST_CPU > 0)) && taskset -cp "0-$((LAST_CPU - 1))" $$ > /dev/null 2>&1; then
  for pid in $PINNED; do taskset -cp "$LAST_CPU" "$pid" > /dev/null 2>&1; done
  say "SOAK-NOTE samplers on cpu $LAST_CPU, load on 0-$((LAST_CPU - 1)): $(taskset -cp $$ 2>&1)"
else
  say "SOAK-NOTE no CPU affinity: samplers share CPUs with the load"
fi
net_up
# Arm the heap allocation-site audit before the baseline (NARF only).
[ -w /proc/narf/slab_sites ] && echo 1 > /proc/narf/slab_sites
settle_meminfo SOAK-BASELINE

stamp
say "SOAK-PHASE prep up=$UP"
mkdir -p "$W/cold" "$W/shared" "$W/scratch" /home/narf/soak-shared
python3 - "$W" "$SOAK_BIG_MB" << 'EOF' || say "SOAK-ERR prep: data files failed"
import os, sys
w, big_mb = sys.argv[1], int(sys.argv[2])
block = bytearray(os.urandom(1 << 20))
with open(f"{w}/big.bin", "wb") as f:
    for i in range(big_mb):
        block[:8] = i.to_bytes(8, "little")
        f.write(block)
with open(f"{w}/up.bin", "wb") as f:
    for i in range(50):
        f.write(block)
for i in range(3000):
    with open(f"{w}/cold/f{i}", "wb") as f:
        f.write(block[: 4096 + (i * 97) % 60000])
EOF
sync
echo 3 > /proc/sys/vm/drop_caches
stamp
say "SOAK-PHASE prep-done up=$UP $(df -P / | tail -n 1)"

sampler &
KEEP+="$! "
taskset -cp "$LAST_CPU" $! > /dev/null 2>&1
probes &
KEEP+="$! "
taskset -cp "$LAST_CPU" $! > /dev/null 2>&1

survey_shared boot
if [ "$SOAK_DURABLE" = 1 ]; then
  stamp
  say "SOAK-PHASE durable up=$UP"
  durable_run
fi
if [ "$SOAK_DIRECTED" = 1 ]; then
  stamp
  say "SOAK-PHASE directed up=$UP"
  directed
fi

END=$((SECONDS + SOAK_SECS))
HEAVY_END=$((SECONDS + SOAK_HEAVY_SECS))

# The heavy mix first, alone: threaded processes on the same files, killed
# and exiting mid-operation; threads faulting a large mapping; threads
# reading a source tree; journal-like fsync+rename; parallel uploads.
stamp
say "SOAK-PHASE heavy up=$UP"
NATIVE_SECS=$((SOAK_SECS > 60 ? SOAK_SECS - 25 : SOAK_SECS))
# SOAK_SHARED_MAPS=0 leaves out the workers that map files shared (dirtying
# them and dying with them, or faulting a large one in), to see what the
# rest of the load does on its own.
if [ "$SOAK_SHARED_MAPS" = 1 ]; then
  worker shared-tmp "$NATIVE" shared "$NATIVE_SECS" 3 12 "$W/shared" "$HB/shared-tmp"
  worker shared-home "$NATIVE" shared "$NATIVE_SECS" 2 16 /home/narf/soak-shared "$HB/shared-home"
  worker killstorm "$NATIVE" killstorm "$NATIVE_SECS" 10 "$W/big.bin" "$TREE" "$W/scratch" "$HB/killstorm"
  worker mmapfault "$NATIVE" mmapfault "$NATIVE_SECS" 4 "$W/big.bin" "$HB/mmapfault"
fi
worker readtree "$NATIVE" readtree "$NATIVE_SECS" 4 "$TREE" "$HB/readtree"
worker lookups "$NATIVE" lookups "$NATIVE_SECS" 6 "$TREE" "$HB/lookups"
if [ "$SOAK_DIRTYEXIT" = 1 ]; then
  worker dirtyexit1 w_dirtyexit 1 exit
  worker dirtyexit2 w_dirtyexit 2 kill
  worker dirtyexit3 w_dirtyexit 3 exit
fi
worker trees w_trees
worker integrity w_integrity "$NATIVE_SECS"
worker fsio1 $PY fsio "$HB/fsio1" "$W/fsio1" "$SOAK_SECS"
worker fsio2 $PY fsio "$HB/fsio2" /home/narf/soak-fsio "$SOAK_SECS"
worker journal w_journal
worker dropcache w_dropcache
worker listen $PY listen "$HB/listen" "$SOAK_LISTEN_PORT"
i=0
for host in "${HOSTS[@]}"; do
  i=$((i + 1))
  worker "tls$i" $PY tcp "$HB/tls$i" "$host" "$SOAK_TLS_PORT" tls "$SOAK_XFER_MB" "$SOAK_SECS"
  worker "tcp$i" $PY tcp "$HB/tcp$i" "$host" "$SOAK_HTTP_PORT" plain "$SOAK_XFER_MB" "$SOAK_SECS"
done

if [ -r "$D/narf-hang-sampler" ]; then
  setpriv --reuid=1000 --regid=1000 --clear-groups env HOME=/home/narf \
    NARF_SAMPLER_OUT=/home/narf/narf-hang-sampler-soak.log \
    bash "$D/narf-hang-sampler" 2 eth0 2> /dev/null &
fi

while ((SECONDS < HEAVY_END && SECONDS < END)); do nap 1; done

survey_shared load
# Then the rest of a desktop session on top of it.
stamp
say "SOAK-PHASE all up=$UP"
worker forkexec1 w_forkexec 1
worker forkexec2 w_forkexec 2
worker script w_script
worker pty $PY pty "$HB/pty" "$(left)"
worker tmux w_tmux
worker dbus w_dbus
worker unix $PY unix "$HB/unix" "$(left)"
worker timers $PY timers "$HB/timers" "$(left)"
worker killtools w_killtools
worker cores w_cores
worker anon1 w_anon 1
worker idlers w_idlers
i=0
for host in "${HOSTS[@]}"; do
  i=$((i + 1))
  worker "udp$i" $PY udp "$HB/udp$i" "$host" "$SOAK_UDP_PORT" "$(left)"
  worker "curl$i" w_curl "$host" "$i"
done

while ((SECONDS < END)); do nap 1; done

stamp
say "SOAK-PHASE stop up=$UP"
# Everything in this unit's cgroup except this shell, its samplers and
# their children.
IFS=: read -r _ _ cg < /proc/self/cgroup
cg=/sys/fs/cgroup$cg/cgroup.procs
for _ in 1 2 3 4 5; do
  [ -r "$cg" ] || break
  while read -r pid; do
    stat=""
    read -r stat 2> /dev/null < "/proc/$pid/stat"
    stat=${stat##*) }
    read -r _ ppid _ <<< "$stat"
    case "$KEEP" in *" $pid "* | *" $ppid "*) ;; *) kill -9 "$pid" 2> /dev/null ;; esac
  done < "$cg"
  nap 2
done
tmux -L soak kill-server 2> /dev/null
for f in "$D"/out/*.log; do
  while read -r line; do say "SOAK-OUT ${f##*/}: $line"; done < "$f"
done
line="SOAK-ERRCOUNT"
for f in "$D"/err/*.count; do
  [ -r "$f" ] || continue
  read -r v < "$f"
  f=${f##*/}
  line+=" ${f%.count}=$v"
done
say "$line"
f=/home/narf/narf-hang-sampler-soak.log
if [ -r "$f" ]; then
  say "SOAK-SAMPLER blocks=$(grep -c '^=====' "$f") bytes=$(stat -c %s "$f") stuck_notes=$(grep -c '^disk:' "$f")"
  n=0
  while read -r line; do
    n=$((n + 1))
    ((n <= 14)) && say "SOAK-SAMPLER ${line:0:300}"
  done < <(tac "$f" | sed '/^=====/q' | tac)
fi
rm -rf "$W" /home/narf/soak-shared /home/narf/soak-fsio "$f"
settle_meminfo SOAK-FINAL
stamp
say "SOAK-END up=$UP"
if [ "$SOAK_POWEROFF" = 1 ]; then
  systemctl poweroff
fi
