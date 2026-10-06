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

`fedora-poll-probe.py` runs alongside the gate. It asserts that a blocking
wait actually blocks — `poll` with no fds, on an eventfd, on an epoll fd, with
GLib's exact `POLLIN|POLLERR|POLLHUP` mask, on each primitive after its level
has been consumed, and on an ALSA control fd with mixer events subscribed.
A kernel that returns from any of those early makes every GLib main loop spin
at 100% of a CPU while still behaving correctly, which is invisible to a
functional test.

## Known open defect: the session manager spins

WirePlumber's MAIN thread uses ~100% of one CPU once the graph is built, while
the PipeWire daemon sits at 0% and every functional stage passes. The gate
reports it on every run (including in the verdict line) but does not fail on
it: failing would hide the contract this gate exists to prove.

Ruled out so far, all measured in-guest:

- the vDSO `CLOCK_MONOTONIC` (advances correctly, so GLib's timeouts are sane);
- `poll`/`ppoll`/`epoll_wait` blocking semantics, with and without fds;
- `POLLERR`/`POLLHUP` being treated as requested rather than output-only
  (`do_poll` gets this right, and the probe confirms it);
- `poll` over an epoll fd using GLib's exact mask — the shape
  `wp_loop_source_new` creates (lib/wp/core.c);
- a level not cleared on consume, for eventfd, Unix socketpair and timerfd,
  individually and inside an epoll;
- ALSA control-fd readiness, idle and with events subscribed;
- GLib itself: a bare `gdbus monitor` main loop idles at 0%.

It emits no log output at `WIREPLUMBER_DEBUG=4`, so it is a silent dispatch
loop rather than repeated work.

Narrowing it further wants a tracer, and `strace -p` now works: it attaches to
all seven WirePlumber threads and prints a syscall summary. Getting there took
two fixes, each found by the shape of what failed rather than by reading the
code:

1. A tracer was not eligible to wait for a tracee it had not forked, so
   `wait4(-1, …, __WALL)` answered `No child processes` — the first thing
   `strace -p` does after attaching. `is_tracer_of_any` compared a scheduler
   TaskId against a map keyed in the ptrace ABI's pid space, which diverge the
   moment a task forks, so the check silently never matched.
2. Attaching then succeeded and `strace` hung in `wait4` anyway, because a
   stop report named the thread GROUP rather than the stopping thread. The
   pending map is keyed parent → child_pid, so all seven threads' attach-stops
   collapsed into one slot filed under the leader's pid: a `waitpid(<worker
   tid>)` matched nothing, and strace waits for one stop per attached thread.
   `do_notify_parent_cldstop` is explicit that only a report to the real
   parent is rewritten to the group leader, while a report to the tracer names
   the thread.

Defect 2 is invisible to a single-threaded tracee, which is why the four
simpler probe cases passed throughout and only `sibling-threadgroup` caught
it. Its per-tid output is the diagnosis: `tids=3 stops=1 [121:stopped sig=19
123:NO REPORT 124:NO REPORT]`.

One caveat on the probe's own output: the `state=` it prints comes from
`/proc/<pid>/task/<tid>/stat`, which still renders the PROCESS state, so a
thread in a ptrace-stop reads `R` there where Linux shows `t`. The stop itself
is real — the wait reports it — so this is a separate `stat` rendering gap,
not a ptrace one.

Audible quality and physical power transitions still require hardware tests.
