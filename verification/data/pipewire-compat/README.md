# Desktop audio integration gate — stock PipeWire + WirePlumber

`../musl-demo/fedora-audio-gate.sh` runs the unmodified Fedora 43 packages
(PipeWire 1.4.x, WirePlumber 0.5.x, `pipewire-utils`, `alsa-utils`) inside the
Fedora KDE image and asserts the contract a desktop actually depends on.

This is deliberately not the alsa-lib probe in `../alsa-compat/`. That probe
drives the PCM and control ioctls directly from one process. PipeWire adds the
parts ALSA validation cannot establish:

| Stage | What only this can show |
| --- | --- |
| `udev` | the cards reached udev's **database** with `SOUND_INITIALIZED` and `ID_PATH`; `spa_alsa_udev` skips any card without them |
| `access` | udev's `GROUP="audio"` + `0660` landed on nodes devtmpfs published root-only, so a non-root desktop user can open them |
| `proc` | `/proc/<pid>/root` OPENS as a directory — PipeWire's access module reads a failed open as "client is sandboxed" and parks the connection |
| `daemon` | the daemon serves a client over its protocol socket (SCM_RIGHTS + sealed memfd transport) |
| `session` | WirePlumber attaches as a **second process** and exports an ALSA device with ACP card profiles |
| `stream` | a sink and a source node exist and playback and capture run **at the same time** through them |
| `recover` | a profile cycle and a cold session restart both rebuild that device's sink |
| `steady` | the idle session does not burn a CPU, `ps -L` lists its threads, and `pthread_setname_np` takes effect |

Before PipeWire starts, the `access` stage also drives plain ALSA directly:
`aplay`/`arecord` in both read/write and `-M` (mmap) modes on both cards, and
an `-f S32_LE` request at PipeWire's own period and buffer size. That last one
splits the problem space in half whenever the graph misbehaves — it separates
"the PCM driver cannot sustain a transfer" from "the format PipeWire
negotiated is one the card advertises but cannot configure".

One verdict line reaches the console, `NARF-AUDIO-CHECK: OK` or
`... FAIL <reason>`, and `cargo xtask systemd-pid1` keys its success and
failure markers to it.

## Running it

The gate is opt-in via the `narf_audio_check` kernel cmdline flag, so ordinary
graphical boots never run it. It needs the Fedora KDE image, which installs the
audio stack itself:

```sh
bash verification/data/musl-demo/REGEN_fedora_kde_rootfs.sh

NARF_VBLK_IMG=target/narf-fedora-vblk.img \
  XTASK_QEMU_APPEND=narf_audio_check \
  XTASK_SYSTEMD_PID1_TIMEOUT_SECS=2100 \
  XTASK_SYSTEMD_PID1_SUCCESS_MARKER="NARF-AUDIO-CHECK: OK" \
  XTASK_SYSTEMD_PID1_FAILURE_MARKER="NARF-AUDIO-CHECK: FAIL" \
  cargo xtask systemd-pid1 --arch=x86_64
```

The x86_64 QEMU profile provides HDA as card 0 and VirtIO sound as card 1;
capture is on card 0. The gate fails if either card is absent.

## Harness notes worth keeping

These are not kernel findings. They are places where a plausible-looking
harness silently measured the wrong thing, each of which cost a boot:

- **Budgets are wall-clock.** `pw-dump` serialises ~120 KB of graph and takes
  tens of seconds under emulation. A retry loop that counts iterations gives a
  "60 second" budget to a single attempt.
- **One graph snapshot per check.** Three helpers each taking their own
  `pw-dump` turned one assertion into minutes.
- **Every PipeWire client call is `timeout`-bounded.** An unbounded one inside
  a retry condition wedges the gate with no output at all, which is the one
  failure mode that cannot be diagnosed without another boot.
- **`setpriv`, not `runuser`, to drop privileges.** `runuser` goes through PAM,
  and `pam_limits` resets `RLIMIT_RTPRIO` to the `limits.conf` default of 0, so
  the unit's `LimitRTPRIO=` never reaches the daemon and PipeWire quietly gives
  up on a realtime data loop.
- **The runtime directory is `/run/narf-audio`, not `/run/user/1000`.** The
  latter belongs to `user-runtime-dir@1000.service`, which systemd removes
  whenever `user@1000.service` fails — deleting a live PipeWire socket and
  turning an unrelated user-manager problem into an audio failure.
- **The daemons log at `PIPEWIRE_DEBUG`/`WIREPLUMBER_DEBUG` 3; the client tools
  must not.** Exported, the same variables bury `wpctl status`'s table under
  WirePlumber's startup log on the stdout the gate parses.
- **`dbus-run-session` is not used.** It hands the bus address back over a pipe
  and then execs the payload; the gate starts `dbus-daemon --fork
  --print-address` itself, bounded.
- **`pw-cat`'s `--raw` mode ignores the filename.** `setup_pipe` installs
  `stdout_record`/`stdin_play`, so `pw-record --raw FILE` writes the samples to
  STDOUT and leaves `FILE` untouched, and `pw-play --raw FILE` reads STDIN and
  plays nothing while exiting 0. Redirect instead, and assert that playback
  took about as long as the audio is.
- **Assert per DEVICE, not globally.** With two cards present, switching one
  card's profile to `off` cannot make "no sink anywhere" true, so that
  condition can never be satisfied by a correct profile switch.
- **A `timeout` around `strace -p` needs `-k`.** A plain `timeout` sends
  SIGTERM, and an strace parked in `wait4` on its tracee does not die on that,
  so the timeout itself never returns and the run hangs instead of failing.
  `timeout -k 5 35` escalates to SIGKILL and bounds it either way. (`strace -p`
  itself works now — see the ptrace section below.)
- **Plasma does not run on an audio-check boot.** The gate does not want a
  compositor, and leaving the session to start anyway is not merely noisy: a
  Plasma process taking a fatal fault twice left the guest spinning on a dozen
  vCPUs with the serial stream dead, losing the gate's own result to an
  unrelated crash. `narf-plasma.service` carries
  `ConditionKernelCommandLine=!narf_audio_check`; ordinary graphical boots are
  untouched.
- **Never wrap a `timeout`'d helper in a command substitution** unless the
  helper is `exec`ed into. `note "$(timeout 60 runuser -u u -- probe)"` wedges
  the gate: `timeout` signals `runuser`, which does not forward it, the probe
  survives, and the substitution blocks forever on a pipe whose write end is
  still held. Redirect to a file, and drop privileges with `setpriv`, which
  execs its target so the timeout lands on the probe itself.

## Oracles

Contracts are checked against the local Linux 7.3-rc4 sources under
`/usr/src/linux`:

| Contract | Linux source |
| --- | --- |
| Device-node default owner and mode (root:root 0600) | `drivers/base/devtmpfs.c`, `sound/sound_core.c` |
| A card's PCM formats come from the codec, not a fixed list | `sound/pci/hda/hda_codec.c` (`snd_hda_query_supported_pcm`) |
| `poll(2)` reports `POLLERR`/`POLLHUP` without being asked | `fs/select.c` |
| `GROUP="audio"`, `0660`, `uaccess` tagging | `/usr/lib/udev/rules.d/50-udev-default.rules`, `70-uaccess.rules` |
| `SOUND_INITIALIZED` on the card `change` event | `/usr/lib/udev/rules.d/78-sound-card.rules` |
| Magic-link target rendered in the reader's root | `fs/proc/base.c` (`proc_pid_readlink`), `fs/d_path.c` |
| `/proc/<pid>/task/` named by thread id | `fs/proc/base.c` (`proc_task_readdir`) |
| `/proc/<pid>/task/<tid>/comm` mode | `fs/proc/base.c` (`tid_base_stuff`) |
| A ptrace-stop report names the THREAD, not the group leader | `kernel/signal.c` (`do_notify_parent_cldstop`) |
| A syscall-entry stop shows `rax == -ENOSYS` | `arch/x86/entry/entry_64.S` (`PUSH_AND_CLEAR_REGS rax=$-ENOSYS`) |
| A stopped task reports `t` / `T`, not `R` | `fs/proc/array.c` (`task_state_array`) |
| A traced exec reports EVENT_EXEC, else a legacy SIGTRAP | `fs/exec.c` (`begin_new_exec`), `include/linux/ptrace.h` (`ptrace_event`) |
| A signal-stop dequeues from the shared set too | `kernel/signal.c` (`dequeue_signal`) |
| `poll(2)` returns 0 only when a timeout expired | `fs/select.c` (`do_sys_poll`, `poll_schedule_timeout`) |
| An empty-set `poll` still waits out its timeout | `fs/select.c` (`do_sys_poll` with `nfds == 0`) |

PipeWire's own requirements are read from its sources: `spa/plugins/alsa/
alsa-udev.c` (which card properties are mandatory), `src/modules/
flatpak-utils.h` and `src/modules/module-access.c` (the `/proc/<pid>/root`
check), and `src/modules/module-rt.c` (the realtime policy path).

`fedora-ptrace-probe.py` has its own gate, opt-in via the `narf_ptrace_check`
kernel cmdline flag so an iteration costs a bare multi-user boot rather than a
run of this one:

```sh
NARF_VBLK_IMG=target/narf-fedora-vblk.img \
  XTASK_QEMU_APPEND=narf_ptrace_check \
  XTASK_SYSTEMD_PID1_SUCCESS_MARKER="PTRACE-PROBE: OK" \
  XTASK_SYSTEMD_PID1_FAILURE_MARKER="PTRACE-PROBE: FAIL" \
  cargo xtask systemd-pid1 --arch=x86_64
```

It covers the door `strace -p` uses, which is not the one the musl strace
smoke covers (that one is TRACEME + exec on the tracer's own child):
PTRACE_ATTACH to a running task — spinning and parked in a blocking syscall,
as the tracer's own child and as a non-child sibling, waited for by tid and by
`waitpid(-1, __WALL)` — and finally to every thread of a non-child THREAD
GROUP, which is what `strace -p` really does. Every case runs on the build
host first, so the expected answer is Linux's own.

`fedora-poll-probe.py` runs alongside the gate, and has its own
`narf_poll_check` gate for the same reason the ptrace probe does — a bare
multi-user boot rather than a twenty-minute run. It asserts that a blocking
wait actually blocks — `poll` and `ppoll`, with a finite timeout and with an
indefinite one, with no fds, on an eventfd, on a timerfd, on an epoll fd, each
of those alone and all together, with GLib's exact `POLLIN|POLLERR|POLLHUP`
mask, on each primitive after its level has been consumed, and on an ALSA
control fd with mixer events subscribed.
A kernel that returns from any of those early makes every GLib main loop spin
at 100% of a CPU while still behaving correctly, which is invisible to a
functional test.

## Closed defect: the session manager spun

WirePlumber's MAIN thread used ~100% of one CPU once the graph was built,
while the PipeWire daemon sat at 0% and every functional stage passed. It
emitted nothing at `WIREPLUMBER_DEBUG=4`, so it was a silent dispatch loop
rather than repeated work. The gate now ASSERTS an idle session is idle; for
as long as the cause was unknown it only recorded a warning, because failing
would have hidden the contract the gate exists to prove.

Finding it needed a tracer, so it needed the two ptrace fixes above first.
With `strace -p` working, the answer was immediate and quantitative: the main
thread was in `ppoll` **1,654,732 times in 35 seconds**, every call returning
with nothing ready.

That pointed at `ppoll`, but the probe found something broader. Two kernel
defects, both pinned by `fedora-poll-probe.py`:

1. **A nested epoll fd's readiness cell never fell.** `push_ready` raises an
   epoll instance's own cell when a child becomes ready, but the only place
   that lowered it was `collect_ready` — the DIRECT-wait path — reasoning that
   a purely-nested instance is judged by `poll_readiness` instead. `poll(2)`'s
   park breaks that: it arms the cell and takes `any_ready` as the answer,
   returning `poll_scan`'s count without consulting the timeout. So an epoll
   fd whose child had ever gone ready and then been DRAINED stayed latched
   high forever, and every later `poll`/`ppoll` over it returned 0
   immediately. Any loop that polls an epoll fd rather than calling
   `epoll_wait` on it then spins — and GLib over PipeWire's loop fd
   (`wp_loop_source_new`) is exactly that shape. The level query now
   reconciles the cell, a falling edge that wakes nobody.
2. **An empty-set `poll` did not wait.** `poll(NULL, 0, -1)` returned 0 at
   once, which poll(2) may only do when a timeout expired — and there is no
   timeout there to expire. The finite case busy-spun a whole core for the
   duration instead of parking. Both now take the ordinary park.

Two things about the measurement are worth keeping, because each cost a boot:

- **The existing probe could not have caught either one.** Every case passed a
  500 ms timeout, so the INDEFINITE wait an idle GLib loop actually makes was
  never measured; and Python's `select` exposes no `ppoll`, so the syscall
  GLib really waits in was never called. The ppoll and infinite-wait cases go
  through `ctypes`, and must: PEP 475 makes Python retry an EINTR'd syscall
  transparently, so a `select.poll().poll()` with no timeout would restart
  after the bounding alarm and block forever instead of reporting.
- **A single-fd probe would have missed it too.** `poll` on the eventfd alone
  and on the timerfd alone both blocked correctly; only the epoll fd was
  latched, and only after a child of it had gone ready and been drained. The
  per-fd bisect is what named it.

The caveat that used to live here — that a trace's return values were the
syscall NUMBER, which is why the spinning `ppoll` appeared to return `271`
(`__NR_ppoll`) — is fixed; see below.

## Syscall-stop registers, and what a stopped task looks like in /proc

Three more divergences, all found by extending `fedora-ptrace-probe.py` to
read what a tracer actually reads and comparing it against the same probe on
the build host:

1. **A syscall-ENTRY stop reported `rax` as the syscall number.** Linux presets
   it to `-ENOSYS` from the instant of entry — `pushq %rax` into `orig_ax`,
   then `PUSH_AND_CLEAR_REGS rax=$-ENOSYS` — and that is how an ATTACHING
   tracer tells an entry stop from an exit stop, since it cannot know which it
   is looking at. Getting it wrong is what made strace pair the stops off by
   one and print the number as a result.
2. **A syscall-EXIT stop reported `rax` as the syscall number too.** The real
   result could not be read from the saved user state: the exit asm folds the
   dispatcher's return into the snapshot's `rax` slot only AFTER the dispatcher
   returns, so inside the dispatch that state still holds the ENTRY register
   file. Both stops now carry a pinned value for the tracer, separate from
   what the tracee resumes with.
3. **A stopped task reported `R` in `/proc/<pid>/stat`.** `task_state_array`
   gives `T` for a job-control stop and `t` for a tracing stop, chosen by the
   highest set state bit. `/proc/<pid>/task/<tid>/stat` needed its own answer
   rather than the process's, because a stop is per-thread — a tracer stops
   one tid at a time.

And one that was not a register at all: **resuming a tracee raced its own
park.** `enter_ptrace_stopped` publishes the stop report to the tracer and only
THEN parks, so a tracer routinely resumed the tracee before it had parked. With
no park arm of its own, a ptrace-stop fell into the generic deadline park,
whose re-checked wake condition is "a deliverable signal is pending" — which a
ptrace resume does not set — so that one wake was dropped and the tracee
parked forever. Linux closes the same window from the tracer's side, with
`wait_task_inactive(child, __TASK_TRACED|TASK_FROZEN)` in
`ptrace_check_attach`. It presented as intermittency, which is the tell.

## Closed: a traced execve reported nothing

`strace -p` worked; `strace <cmd>` hung with its trace ending at
`--- stopped by SIGSTOP ---`, which is its startup handshake (TRACEME +
`raise(SIGSTOP)` in the forked child, so the tracer can set options before the
execve). NARF emitted the execve syscall-ENTRY stop and then nothing at all.

Rather than guess what a tracer waits for, the probe was made to REPORT the
sequence and the build host answered it. Stepping `PTRACE_SYSCALL` across
`execve("/bin/true")`, Linux gives (`sys:N` = a syscall-stop for syscall N):

```text
without TRACEEXEC:  sys:59, sys:59, sig:5,  <new image's syscalls>
with    TRACEEXEC:  sys:59, ev:4,   sys:59, <new image's syscalls>
```

So there are TWO reports, not one, and their ORDER depends on the option. The
execve syscall-EXIT stop happens either way — it is what prints
`execve(...) = 0` — and the exec report is a `PTRACE_EVENT_EXEC` stop BEFORE
it, or a legacy SIGTRAP AFTER it. The positions are not arbitrary:
`ptrace_event(PTRACE_EVENT_EXEC)` stops inside `begin_new_exec`, while
`send_sig(SIGTRAP, current, 0)` only queues a signal that is delivered later,
in the exit-to-user loop that runs after the syscall-exit work.

NARF now emits both, from `ptrace_report_exec`, placed after the point of no
return and before the jump into the new image. The exit stop had been missing
because the exec path DIVERGES into the new image instead of returning through
the syscall exit, so it has to be taken explicitly there.

Both halves had to land together, which is worth recording because the
intermediate state was measured: sending only the SIGTRAP turned the hang into
something worse — strace, still waiting for the exit stop, took the report for
an ordinary signal and injected it, killing the tracee with SIGTRAP.

Getting the sequence right then exposed one more, which the probe now guards
with a "no stray signals" assertion: **a signal-stop dequeued only the
thread's private pending bit.** A signal sent to the PROCESS lives in the
thread group's shared set, so `kill(getpid(), SIGSTOP)` — exactly what
strace's handshake does — stayed pending forever and was re-delivered at every
signal-delivery point. A tracer stepping its tracee saw a SIGSTOP stop after
every single syscall, and the tracee eventually faulted.

With all of it in place, `strace <cmd>` works: `write(1, "narf\n", 5) = 5`.

Audible quality and physical power transitions still require hardware tests.
