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
| `recover` | a profile cycle and a cold session restart both rebuild the sink |

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
- **`ps -L` is unusable here** — it aborts with `fatal library error, reap`
  against this procfs — and `strace -p` cannot attach (`wait4(__WALL): No child
  processes`). Thread state is sampled from `/proc/<pid>/task/<tid>/stat`
  instead.

## Oracles

Contracts are checked against the local Linux 7.3-rc4 sources under
`/usr/src/linux`:

| Contract | Linux source |
| --- | --- |
| Device-node default owner and mode (root:root 0600) | `drivers/base/devtmpfs.c`, `sound/sound_core.c` |
| `GROUP="audio"`, `0660`, `uaccess` tagging | `/usr/lib/udev/rules.d/50-udev-default.rules`, `70-uaccess.rules` |
| `SOUND_INITIALIZED` on the card `change` event | `/usr/lib/udev/rules.d/78-sound-card.rules` |
| Magic-link target rendered in the reader's root | `fs/proc/base.c` (`proc_pid_readlink`), `fs/d_path.c` |
| `/proc/<pid>/task/` named by thread id | `fs/proc/base.c` (`proc_task_readdir`) |
| `/proc/<pid>/task/<tid>/comm` mode | `fs/proc/base.c` (`tid_base_stuff`) |

PipeWire's own requirements are read from its sources: `spa/plugins/alsa/
alsa-udev.c` (which card properties are mandatory), `src/modules/
flatpak-utils.h` and `src/modules/module-access.c` (the `/proc/<pid>/root`
check), and `src/modules/module-rt.c` (the realtime policy path).

Audible quality and physical power transitions still require hardware tests.
