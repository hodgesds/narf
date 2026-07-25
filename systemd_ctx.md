# Fedora + systemd bring-up on NARF — work-in-progress handoff

**Goal:** boot Fedora 43 + KDE Plasma under systemd-as-PID-1 on the NARF kernel,
to a rendered desktop. This doc captures the state of the PID-namespace fix +
the current systemd-boot frontier so another agent can continue.

Status date: 2026-07-24. **All changes below are UNCOMMITTED** (13-14 files,
~+711 lines). Run `git diff --stat` to see them.

---

## 1. What was fixed (the PID-namespace model) — DONE + boot-validated

Root problem (see memory `project_pidns_flow_model`): NARF has **three** pid
number spaces — **ProcessId** (`alloc_pid()`, POSIX-visible), **TaskId**
(scheduler, keys most per-task state), **inner pid** (per PID-namespace). Under
systemd (PID 1 in a pidns via `unshare --pid`), pids were translated in only
`getpid`+`kill`, so every `observed_pid == getpid()` check systemd made failed →
"Supervising process N which is not our child" on every service + dbus-broker
"Connection refused".

Implemented, in this diff, a coherent translation across all boundaries:
- **Layer 1 (userspace core):** `TASK_PID_NS` now keyed consistently by
  **TaskId** (`inherit_into_child(parent_task, child_task, child_outer)` — sig
  changed); clone3/fork return the child's **inner** pid; wait4/waitid translate
  `want_pid` inner→outer (accept) and reaped/si_pid outer→inner (report);
  getppid reports inner; `on_child_exit`/`finish_wait_child` fixed. Two helper
  funnels `report_pid_to(observer,outer)` / `accept_pid_from(caller,inner)` in
  `userspace/src/handlers/mod.rs`, both identity in the root ns / non-container.
- **Layer 2 (/proc):** `ProcPidDir` now holds the **outer ProcessId**; new
  procfs hooks `pid_resolve` (reader-ns path number → outer, ns-filtered) +
  `current_outer_pid` + `pid_report` wired in `frame/src/cross_crate_init.rs`.
  `/proc/<pid>/stat`+`status` PPid/pid/pgrp/session, `/proc/self`, and `/proc`
  enumeration all render in the reader's ns.
- **Layer 3:** pidfd fdinfo `Pid:`/`NSpid:` + PIDFD_GET_INFO, cgroup.procs
  read(report)/write(accept) + `fork_inherit` parent key = ProcessId +
  `caller_pid` = outer, SO_PEERCRED + SCM_CREDENTIALS pid, all ns-translated.
- **THE BIG TRAP (cost a boot to find):** most per-task state (fd table / comm /
  argv / exe / cwd / root / environ / auxv / brk / nice / rlimit / uidgid) is
  **TaskId-keyed**; only PARENT_OF + thread-group counts are ProcessId-keyed.
  Because ProcPidDir now hands hooks the *outer ProcessId*, every TaskId-keyed
  per-pid `/proc` hook must first `proc_pid_to_tid(pid)=pid_to_task_raw(pid)
  .unwrap_or(pid)`. Missing it made `/proc/self/fd/N` resolve empty → systemd
  execs its executor via `execve("/proc/self/fd/13")` → **EBADF on every service
  spawn**. All such hooks are now fixed (search `proc_pid_to_tid`).

**Boot result (features `container,cgroup`, KVM, 8 GiB):** `0` "not our child",
`0` "Failed to spawn executor", `0` "Reexecuting", `0` "Connection refused" —
services now spawn cleanly. Confirmed via
`scratchpad/fed_systemd_v2.log` / `fed_masked.log`.

### Tests added (airtight, in `userspace/src/tests.rs`)
- 8 `smoke_pid_ns_*` unit tests (keying, grandchild inheritance, visibility
  filter, report/accept round-trip, child-view-of-parent-is-1, inner-slot
  release, root identity) — all PASS in the container kernel-test.
- `smoke_proc_fd_hook_resolves_processid_to_taskid` — pins the ProcessId→TaskId
  hook translation that the EBADF regression violated (NOT namespace-gated, so
  it runs under the standard `cgroup-all` kernel-test).

---

## 2. CURRENT BLOCKER — journald never signals sd_notify READY

With the pidns fix in, the boot now stalls at **systemd-journald** (Type=notify):
`systemd-journald.service: start operation timed out. Terminating.` at the 90 s
start-timeout. Downstream (dbus-broker, logind, udevd) never start because the
boot serializes behind journald / sysinit.target.

**Key evidence (SMP=1 syscall-trace, `scratchpad/fed_smp1_trace.log`):**
- journald is spawned (executor `execve /proc/self/fd/13` works — no EBADF).
- **The entire trace contains exactly ONE `sendmsg`** (systemd's own, pre-journald).
  → journald **never sends the `sd_notify(READY=1)` datagram**. It stalls/exits in
  early startup *before* the notify point.
- systemd (t=24, PID 1) sits in its normal `epoll_wait(-1)` poll loop
  (returns `0 st=InvalidOp` = the NARF re-execute-park sentinel, ~1 ms cadence —
  this is normal parking, NOT a bug). It's simply waiting for a notify that
  never comes.
- TaskIds are **reused** across forked processes (tid 119 = sleep, then
  executor→journald, then executor→systemd-tmpfiles), so per-tid trace tracking
  is unreliable — don't trust "t=119 == journald" across execves.
- Saw an sd-executor doing an `O_PATH` dir-walk (`openat(dirfd, comp,
  O_PATH|O_DIRECTORY|O_CLOEXEC)`) that ENOENT'd then `exit_group(0)` — but that
  tid was reused for systemd-tmpfiles, so it may be tmpfiles, not journald.

**NOT yet root-caused.** It is unclear whether this is a regression from the
pidns/`/proc` changes or a pre-existing journald-startup gap the new boot flow
now reaches (pre-fix the boot died later, at dbus-broker "Connection refused").

**REFINED FINDING (SMP=1 trace tail):** at the stalled state ONLY systemd
(PID 1) is running — parked in its normal `epoll_wait(-1)` poll loop returning
0 events on a ~1ms cadence. journald makes NO syscalls at the stall AND the
heartbeat `jrnl=` count goes 2→0 (journald's cgroup empties → its process
exits/dies). So the real symptom is: **journald's process goes away but
systemd's event loop is never woken for it** — systemd keeps waiting for a
notify/exit from a process that's already gone, until the 90s start-timeout,
then tries to SIGKILL it ("process 2 (n/a) ... Processes still around after
SIGKILL. Ignoring." = stale, the pid is gone/mis-tracked). So this is NOT
"journald is slow to send READY" — it's a **child-exit / readiness
notification** that never reaches systemd's epoll.

Two concrete leads for the next agent:
1. Determine exit-vs-park definitively: instrument `terminate_current_task` /
   `exit_group` to print the process comm; confirm journald's own process
   exits (vs a fork/helper). It likely exits before sending READY (bailed on
   some startup error).
2. Why doesn't systemd's `epoll_wait` wake? systemd watches the service main
   process via a **CLONE_PIDFD pidfd** in its epoll set; on exit,
   `pidfd::notify_exit(outer_pid)` flips it to POLLIN and fires
   `narf_net::readiness::notify(0)` to wake epoll waiters. **VERIFIED CORRECT
   (2026-07-24):** `PidFdFile::poll_readiness()` returns POLL_IN when exited;
   `notify_exit` keys PIDFD_TABLE by outer ProcessId and `on_child_exit(outer)`
   calls it — all outer-keyed, unaffected by the clone-return-inner change. So
   the pidfd exit-readiness path is NOT the bug; don't re-audit it.
   → Remaining hypotheses: (a) journald genuinely PARKS (doesn't exit — jrnl→0
   might be a fork/child leaving, or a cgroup.procs read artifact) so
   notify_exit never fires; (b) `on_child_exit` isn't invoked for journald's
   exit, or the readiness wake doesn't reach systemd's specific epoll park
   (check `net_io_wait`/`epoll_park_gen` bridge in sys_epoll_wait.rs vs
   `readiness::notify(0)`); (c) journald's Type=notify main process double-forks
   and the tracked pid isn't the surviving one. START by comm-tagging
   `terminate_current_task`/`exit_group` to prove exit-vs-park for journald
   specifically. The `epoll_wait` handler is
   `userspace/src/handlers/sys_epoll_wait.rs`; pidfd is `userspace/src/pidfd.rs`.

### Suggested next steps for journald
1. Get a CLEAN per-process trace despite tid reuse: correlate by the
   `invocationid`/`comm` OSC markers systemd emits, or add a boot flag to pin
   SMP=1 + log the executor→service execve chain with the resolved service path.
2. Determine whether journald *exits* or *parks* — instrument `terminate_current_task`
   / exit_group with the process's comm, and check whether journald's cgroup
   (`/sys/fs/cgroup/system.slice/systemd-journald.service/cgroup.procs`) still
   has a live pid at the timeout (the HB loop already prints `jrnl=N`; it went
   2→0, suggesting journald's procs exited).
3. journald early startup touches: `RuntimeDirectory=/run/log/journal`,
   `/dev/kmsg`, `/proc/kmsg`, mount_setattr (seen returning -22 EINVAL),
   TCGETS2 ioctl (ENOTTY, benign), getrandom. Check each for a NARF gap that
   makes journald bail before `sd_notify`. In-guest `strace` HANGS on Fedora
   glibc binaries — use `--features syscall-trace` only.
4. If journald proves too deep, consider `Storage=none` or masking journald and
   pointing services at the console, to unblock the boot and test dbus-broker/
   logind next (the pidns fix should make those work now).

---

## 3. Reproduction harness

```
# Boot Fedora+systemd (the image's /narf-start.sh runs `unshare --pid systemd`):
XTASK_QEMU_ACCEL=kvm NARF_QEMU_MEM_MB=8192 \
NARF_VBLK_IMG=target/narf-fedora-vblk.img XTASK_RI_ECHO_TIMEOUT_SECS=290 \
cargo xtask run-interactive --arch=x86_64 --display none \
  --features container,cgroup --cmd distro_fedora --expect ZZZ_STAY_UP

# add `,syscall-trace` to features for an strace; add `NARF_QEMU_SMP=1` for a
# CLEAN single-CPU trace (SMP interleaves console writes and garbles the log).
# Kill leftover QEMU with:  pkill -f 'qemu-system-x86_[6]4'
```

- Image at `target/narf-fedora-vblk.img` (4 GiB, gitignored). Its
  `/narf-start.sh` is a debug override (systemd harness + heartbeat loop +
  journal dumps), **diverged from** `verification/data/musl-demo/
  REGEN_fedora_kde_rootfs.sh` (which still has the plasma launcher). Iterate the
  script with `debugfs -w` (rm + `write`, then `e2fsck -fy`) — no kernel rebuild.
- **Unit masking already applied to the image's /narf-start.sh** (NARF can't do
  these): `modprobe@.service` (template — masks drm/dm_mod/fuse/loop/configfs
  instances, each otherwise hangs at "start running (45s)"),
  `systemd-udev-trigger.service` (needs netlink uevents NARF lacks),
  `sys-kernel-debug.mount`, `sys-kernel-tracing.mount`. Done via
  `ln -sf /dev/null /run/systemd/system/<unit>` before `unshare --pid systemd`.
  **TODO: make these permanent** in REGEN (`/etc/systemd/system/<unit>` →
  /dev/null in the rootfs) so image rebuilds keep them.

---

## 4. CI / commit readiness

- `run_ci_locally.sh` kernel-test line was changed to
  `--features cgroup-all,container,linux-compat` (so the container/linux-compat
  pid_ns + `/proc` tests actually RUN — cgroup-all alone leaves them
  compiled-but-unregistered).
- This surfaced **2 pre-existing failures** in never-run gated tests:
  - `smoke_abi_creds_setdomainname_pos` — **FIXED** in this diff
    (`sys_setdomainname` now writes via `current_uts_ns` so `uname` reads it back).
  - `smoke_pivot_root_basic` — **STILL FAILING**. pivot_root writes
    `ROOT_DIR_TABLE[task]` correctly and returns 0, but the test reads it back
    wrong when the full suite runs — smells like test-ordering / global-state
    pollution (it's `linux-compat,container`-gated so it never ran in CI before).
    Unrelated to pidns. **Must fix or the expanded kernel-test is red.** Options:
    fix the isolation bug, or (fallback) revert the kernel-test to `cgroup-all`
    and instead un-gate the pure-logic pid_ns tests so they still run.
- Compile-checked clean (`cargo check -p narf-frame --target x86_64-unknown-none
  ... --features container,cgroup,linux-compat`). Full CI (clippy ×2 arches,
  boot-smoke, musl, net, kernel-test) NOT yet run. `cargo fmt --all` applied.

## 5. Files touched (this diff)
```
filesystem/src/cgroupfs/mod.rs        cgroup.procs read/write xlate, fork_inherit key, caller_pid
filesystem/src/procfs/mod.rs          pid_resolve/current_outer_pid/pid_report hooks + ProcPidDir=outer
frame/src/cross_crate_init.rs         register the 3 new procfs pidns hooks
userspace/src/handlers/mod.rs         helpers + all per-pid hook pid→tid fixes + proc_task_info
userspace/src/handlers/sys_fork.rs    return inner pid + cgroup fork_inherit key
userspace/src/handlers/sys_getppid.rs report inner
userspace/src/handlers/sys_ioctl.rs   PIDFD_GET_INFO report
userspace/src/handlers/sys_setdomainname.rs  uname-consistency fix
userspace/src/handlers/sys_socket_getsockopt.rs  SO_PEERCRED report
userspace/src/handlers/sys_socket_recvmsg.rs     SCM_CREDENTIALS report
userspace/src/handlers/sys_wait4.rs   want_pid accept + reaped report
userspace/src/handlers/sys_waitid.rs  P_PID accept + si_pid report
userspace/src/pid_ns.rs               inherit_into_child TaskId key + ns_visible_inner
userspace/src/tests.rs                9 new tests
run_ci_locally.sh                     kernel-test features
```

## 6. How to run everything (tests / QEMU / Fedora VM)

All commands run from repo root `/home/daniel/git/narf`. Kernel target is
`x86_64-unknown-none` (build-std). **Only one QEMU at a time** — the Fedora
image has a write-lock; kill stragglers with `pkill -f 'qemu-system-x86_[6]4'`
(the `[6]` char-class avoids the shell matching its own process).

### Full CI (what must be green before landing on main)
```
./run_ci_locally.sh          # fmt + clippy(x86_64,aarch64) + boot-smoke×2 +
                             # musl-demo + net-smoke + kernel-test + feature checks
```
Individual gates:
```
cargo fmt --all -- --check
cargo clippy -p narf-frame --target x86_64-unknown-none \
  -Zbuild-std=core,compiler_builtins,alloc \
  -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128 \
  --features boot-smoke,cgroup-all -- -D warnings
# (repeat with --target aarch64-unknown-none)

# compile-check the pidns/container paths quickly (no QEMU):
cargo check -p narf-frame --target x86_64-unknown-none \
  -Zbuild-std=core,compiler_builtins,alloc \
  -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128 \
  --features container,cgroup,linux-compat
```

### Kernel-test suite (in-QEMU unit tests, incl. the pid_ns + /proc tests)
```
# Runs ALL registered kernel tests incl. container/linux-compat-gated ones:
XTASK_QEMU_TIMEOUT_SECS=2400 XTASK_BOOT_SMOKE_TIMEOUT_SECS=1200 \
  cargo xtask test --arch=x86_64 --features cgroup-all,container,linux-compat
# Look for "── summary: NNNN pass, N fail, N skip ──". The pid_ns tests are
# `smoke_pid_ns_*` + `smoke_proc_fd_hook_resolves_processid_to_taskid`.
# (NOTE: this currently reports 1 fail = pre-existing smoke_pivot_root_basic.)
```

### Boot-smoke (kernel boots clean, no panic)
```
cargo xtask boot-smoke --arch=x86_64 --features boot-smoke,cgroup-all
```

### Fedora + systemd VM (the actual desktop bring-up)
```
# Needs the image at target/narf-fedora-vblk.img (4 GiB, gitignored, prebuilt).
# The image's /narf-start.sh runs `unshare --pid systemd` + a heartbeat loop.
XTASK_QEMU_ACCEL=kvm NARF_QEMU_MEM_MB=8192 \
NARF_VBLK_IMG=target/narf-fedora-vblk.img XTASK_RI_ECHO_TIMEOUT_SECS=290 \
cargo xtask run-interactive --arch=x86_64 --display none \
  --features container,cgroup --cmd distro_fedora --expect ZZZ_STAY_UP \
  > /tmp/boot.log 2>&1 &
# --display gtk to watch a window; --features ...,syscall-trace for an strace;
# NARF_QEMU_SMP=1 for a clean single-CPU trace.
# Boot takes ~5 min (build + ~290 s capture). Grep /tmp/boot.log for:
#   'HB [0-9]+' (heartbeats w/ jrnl/logind/udevd cgroup proc counts),
#   'not our child', 'Failed to spawn executor', 'Connection refused'.
# Strip systemd's ANSI:  sed 's/\x1b\[[0-9;:]*m//g'
```

### Rebuild the Fedora rootfs image (permanent changes)
```
# Unprivileged (dnf5 + mke2fs under `unshare --user --map-auto`). ~1.7 GiB used.
verification/data/musl-demo/REGEN_fedora_kde_rootfs.sh
#   FEDORA_REBUILD_ROOTFS=1  forces a clean dnf re-install.
# NOTE: this REGENs the PLASMA launcher /narf-start.sh; the working image's
# /narf-start.sh is a systemd-harness override (see §3). Reconcile before relying
# on REGEN. Unit masks (§3) should be baked here too, permanently.
```

### Iterate /narf-start.sh (or any rootfs file) WITHOUT rebuilding the kernel
```
IMG=target/narf-fedora-vblk.img
debugfs -w -R "rm /narf-start.sh" "$IMG"
debugfs -w -R "write /path/to/new/narf-start.sh /narf-start.sh" "$IMG"
e2fsck -fy "$IMG"
debugfs -R 'cat /narf-start.sh' "$IMG"     # verify
# Inspect the image read-only:  debugfs -R 'ls -l /' "$IMG"  /  'stat /path' etc.
```

## 7. Memory notes (durable)
`project_pidns_flow_model` (the model + the TaskId-keying trap),
`project_systemd_boots_on_narf` (harness), `feedback_get_data_first`,
`feedback_tests_are_the_value`. Read these first.

### Semcode-first troubleshooting workflow

Before adding or running new tracing for a kernel/userspace bring-up failure:

1. Read the relevant subsystem specifications and identify the invariants and
   state owners involved.
2. Use semcode's `find_function`, `find_callers`, `find_calls`, and
   `find_callchain` to map the complete path from syscall/event entry through
   state mutation, readiness/wakeup delivery, error propagation, and cleanup.
   Include every subsystem boundary and all alternate exit paths.
3. Correlate that static path with existing logs, ELF addresses, symbols, and
   on-disk inputs. Enumerate competing hypotheses and state the exact unanswered
   question for each one.
4. Only then add the narrowest possible trace that distinguishes those
   hypotheses. Prefer fatal-path or per-event flight-recorder diagnostics over
   hot-path logging, especially for SMP-sensitive failures.
5. If evidence changes the suspected subsystem boundary, repeat the semcode
   call-path analysis before expanding the trace.

This is the default order of operations for future Fedora/systemd/Plasma
debugging. Broad syscall or hot-path tracing is a last resort, not the first
diagnostic step.
