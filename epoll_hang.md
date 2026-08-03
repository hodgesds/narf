# Intermittent epoll/signalfd wake diagnosis

## Current conclusion

Two real epoll/timer wake defects were found and fixed, but the live all-CPU
Fedora freeze was a later cgroup-memory allocator recursion, not epoll failing
to report a level-triggered signalfd. A fork could grow `TASK_CGROUP` while its
IRQ-safe lock was held; the allocation charge hook resolved membership through
that same map and recursively acquired the lock. Both vCPUs then spun with
IRQs disabled, stopping timers, signal handling, and the Plasma probe. The
membership-map, controller-state-map, controller-read, and memory-limit-read
variants are now covered by deterministic re-entry tests; the focused
two-vCPU cgroupfs suite passes all 46 tests.

The environment is still not declared fully booted, but the latest narrow
traces clear the suspected epoll/poll and D-Bus wake path. The
`QDBusConnection` worker wakes from poll, completes the session-bus AUTH/
BEGIN exchange, sends `Hello`, wakes again, and receives the 258-byte reply.
The first post-epoll blocker was glibc secondary-arena creation: Qt repeatedly maps a
128-MiB `PROT_NONE` window, trims the prefix successfully, then gets `EINVAL`
from the suffix `munmap` and the following header `mprotect`, abandons the
arena, and retries indefinitely. NARF's `sys_munmap` ignored its length and
removed an entire VMA whose base matched the first trim. The range fix now
uses the existing transactional VMA-splitting path. A live post-fix syscall
capture shows both trims and the following `mprotect` succeeding, and the
properly registered userspace regression passes in a 363-pass/0-fail run.

An 8-GiB/SMP2 acceptance run proves that the KWin environment-update
gate also completes: every `org.kde.Startup.updateLaunchEnv`,
`UpdateActivationEnvironment`, and `SetEnvironment` call gets a matching
return or error, `org.kde.KWinWrapper` is acquired at guest time 263.391 s,
and KWin appears on the next probe. `plasmashell` is nevertheless absent after
the subsequent 120-second `org.freedesktop.portal.Desktop` activation timeout.
The original Documents portal attempt could not open `/dev/fuse` (`Operation
not permitted`). A replay with the synthetic device corrected to mode 0666
eliminates that denial and reaches the mount, where it exposes an independent
FUSE ABI failure (`fuse: mount failed: Bad address`). The exact KWin replay now
localizes the earlier session teardown: KWin's
`openat("/dev/dri/card0", O_RDWR|O_CLOEXEC)` returns `EPERM`, after which KWin
exits cleanly and drops `org.kde.KWinWrapper` before the kded/ksmserver phase.
This is a DRM device-metadata/credential-policy blocker, not an epoll or
page-cache capacity problem. A reviewed udev-metadata fix is now implemented
and unit-tested. The regenerated-image acceptance attempt did not get far
enough to exercise it: the new exact trace loses Qt's first D-Bus worker when
`prctl(PR_SET_NAME)` changes the comm and the diagnostic filter is rechecked
on syscall return. A corrected dual-comm replay is required at the synchronous
locale1 system-bus boundary. The environment still requires a later 8-GiB run
that proves the card open and reaches literal `PLASMA-READY`.

The farthest subsequent uninstrumented run now reaches `plasma_session`,
keeps KWin alive beyond that former DRM denial, completes the kcminit parent
wait, and briefly starts `kded6`. The apparent kcminit/portal `#GP` is now
symbolized as glibc `abort+0x8b`: the deliberate `hlt` fallback after both
self-`tgkill(SIGABRT)` attempts returned. A max-reasoning semcode review found
that a Linux-visible leader PID can collide with an unrelated raw
`CLONE_THREAD` TaskId; raw-task-first signal resolution then misroutes
`tkill` and makes `tgkill` return `ESRCH`. Self-resolution now compares the
caller's exact gettid value first, with a deterministic collision regression.
KWin and kded6 still exited before ksmserver or plasmashell in the pre-fix
capture, so a rebuilt live replay is still required before the literal
acceptance gate can be claimed.

Live profiles also explain why cold boot takes minutes under QEMU TCG: Qt/KDE
mmap materialization performs many synchronous 4-KiB ext2 reads through the
virtio block path. More RAM alone does not remove that I/O bottleneck. The ext2
read path now performs its page-cache lookup before the volume-wide miss lock,
retains the locked double-check for identical concurrent misses, and fills an
aligned full filesystem block directly into the caller's page. The focused
two-vCPU ext2 QEMU test and its boot smoke pass. The next acceptance gate is
still `PLASMA-READY` with stable KWin and plasmashell PIDs; until then, Plasma
startup remains incomplete.

The 2026-08-03 Wayland-only kcminit replays cross the former phase-zero gate:
the bounded xrdb calls return, `org.kde.kcminit` and `org.kde.kded6` are
acquired, and KWin stays live. They still do not launch ksmserver or
plasmashell. The second replay's bus monitor records the broadcast
`NameOwnerChanged("org.kde.kded6", "", ":1.5")`, but exact Plasma 6.7.3's
`StartServiceJob` watcher does not visibly advance to the following ksmserver
job. Enabling `org.kde.plasma.session.debug` produced no application debug
messages, so that logging category is itself unvalidated and cannot establish
whether Qt consumed the broadcast. Focused AF_UNIX/epoll regressions now pass
for a method reply followed by a queued broadcast and for a coalesced write
followed by a partial read. That rules out simple level-triggered redelivery of
unread stream bytes. No kernel poll change is justified unless the remaining
live scan-to-waiter-registration race can be reproduced deterministically; the
parallel source-level lead is the `StartServiceJob` state machine after the
observed broadcast.

A follow-up replay wrapped only `plasma_session` with `QDBUS_DEBUG=1`. The
wrapper was demonstrably active, but Fedora's Qt 6.10.3 emitted none of the
expected qdbus add/remove/dispatch records. The diagnostic also perturbed the
startup sequence: it remained at KWin plus both phase-zero kcminit processes
for 2m50s and never reached kded6. Therefore that replay is inconclusive about
the persistent kded watcher and the wrapper must not become part of the normal
image. The next test boundary is a separate GLib D-Bus name waiter, which can
verify delivery of the same `org.kde.kded6` ownership transition without
patching Qt or tracing the syscall hot path.

That independent test now passes in the normal-process image. An early
`gdbus wait --session org.kde.kded6` installs its match before startplasma;
when the bus publishes the kded name at guest time 79.411385 s, the parked
GLib client immediately returns and prints `PLASMA-GDBUS-WAIT kded observed`.
Plasma's own `StartServiceJob` still does not launch ksmserver. This clears the
complete NARF-to-GLib delivery path and moves the remaining boundary inside
Qt/Plasma's watcher, queued callback, or job-lifetime logic; another generic
kernel poll change is not supported by the evidence.

The next replay captures the exact QDBus match lifecycle and rules out an
absent or prematurely removed watcher. Plasma's connection `:1.3` adds the
kded registration rule at 42.541850 s and the ksmserver rule at 43.053070 s;
neither is removed before the kded broadcast at 89.527952 s or during the
following plateau. The earlier `MatchRuleNotFound` is for Qt's internal
`arg0='org.freedesktop.DBus'` removal, not kded. The unresolved boundary is
therefore signal dispatch/callback execution after a valid persistent match.

The Fedora-shipped `plasma_waitforname` now covers that generic Qt boundary:
it uses the same Qt 6.10.3 `QDBusServiceWatcher`, independently watches kded,
and prints `PLASMA-QT-WAIT kded observed` immediately after the same broadcast.
Its expected `RemoveMatch` follows on clean exit. Plasma's original job remains
pending. The remaining defect is therefore specific to `StartServiceJob`'s
object/signal/job context, not QDBusServiceWatcher or main-event dispatch in a
minimal Qt process. A scoped classic-session supervisor can bypass this one
proven callback gate while preserving KWin, kded, and the normal session bus.

The first supervisor replay crosses the original callback boundary and emits
`kded observed; launching ksmserver`, with ksmserver PID 117 visible at probe
23. That child exits before acquiring `org.kde.ksmserver` and is absent by
probe 24, so plasmashell is intentionally not launched and `PLASMA-READY` is
not reached. The next uncovered area is ksmserver's early process exit, not a
return to the kded/epoll path; the supervisor needs to race the child status
against the name waiter and report the exact exit result.

That race now reports `ksmserver exited before name status=134`, i.e. the
child terminates via `SIGABRT`, consistently after being visible for one probe
and before publishing its service. No fatal-fault record accompanies it. This
rules out an exec failure or quiet normal exit and makes the next untested area
ksmserver's early deliberate abort path. Source review and a focused startup
environment test are required before deciding whether to bypass ksmserver and
launch plasmashell directly.

Exact Plasma 6.7.3 source explains the abort dependency: ksmserver forcibly
sets `QT_QPA_PLATFORM=xcb`, constructs `QGuiApplication`, and immediately
dereferences the native X11 display before registering its D-Bus service. The
acceptance image's Xwayland still fails virtual-keyboard activation after its
zero-byte xkbcomp input, so a Wayland-only session cannot satisfy ksmserver's
X11 prerequisite. The next scoped test should retain the recorded ksm attempt
but launch native-Wayland plasmashell after status 134; this covers the actual
desktop goal without misclassifying an X11 compatibility failure as epoll.

For systemd PID 1, the important path is level-triggered, not edge-triggered:

1. `/data/systemd/src/core/manager.c::manager_setup_signals` blocks `SIGCHLD`
   with `sigprocmask(SIG_SETMASK, ...)`, creates a nonblocking signalfd, and
   registers it with `sd_event_add_io(..., EPOLLIN, ...)`.
2. `/data/systemd/src/libsystemd/sd-event/sd-event.c::source_io_register` adds
   only the requested events (plus `EPOLLONESHOT` for an explicitly one-shot
   source). `sd_event_add_io` initializes this source as `SD_EVENT_ON`, so the
   manager signalfd has neither `EPOLLET` nor `EPOLLONESHOT`.
3. `process_epoll` waits through `epoll_pwait2(..., NULL)` for finite timeouts
   or `epoll_wait` for an infinite timeout.
4. `manager_dispatch_signal_fd` reads one 128-byte `signalfd_siginfo`; a
   `SIGCHLD` enables systemd's deferred child-processing source.

The corresponding NARF call chain, confirmed with semcode, is:

```text
on_child_exit
  -> queue PENDING_EXITS[parent]
  -> SIGNAL_PENDING[parent] |= SIGCHLD
  -> wake_signal(parent)
  -> narf_net::readiness::notify(0)
       -> wake_io_waiters(0)
       -> wake_all_io_waiters()
       -> wake_one(parent, waker)

epoll_wait_common
  -> EpollInstance::collect_ready
  -> SignalFdFile::poll_readiness
  -> signal_pending_of(signalfd.owner_task) & signalfd.mask
  -> EPOLLIN

manager read(signalfd)
  -> SignalFdFile::read
  -> clear_signal_pending(signalfd.owner_task, SIGCHLD)
```

## Fedora KDE branch delta considered

`plasma-boot-part2` now has eleven diagnostic/fix commits above its original
base, plus the remaining uncommitted metadata/timer work. Across those commits
and the worktree, the latest accounting pass covers all 39 changed tracked
files plus the untracked monitor script and this note. Every entry was
reviewed for its effect on the Fedora KDE boot and this hang.

The verified subsets were checkpointed as:

```text
1f092388 filesystem: avoid cgroup charge recursion
1869f47d userspace: close epoll waiter registration race
234c4256 verification: gate Fedora boot on live Plasma
89991ac1 ext2: bypass miss lock on cached reads
e081489c userspace: honor partial munmap ranges
36b1a9ba filesystem: allow unprivileged fuse opens
65990088 userspace: follow directory symlinks in chdir
db8a6069 userspace: report EPIPE after pipe reader close
5435f629 filesystem: avoid cgroup read charge recursion
2899e50e time: retain deferred overflow timers
948aa535 userspace: resolve self tgkill before tid collisions
```

`epoll_hang.md` was intentionally not committed and remains the live lab
notebook. The proven deferred-overflow retention fix was split from the timer
work and committed independently after the exact staged snapshot passed
`cargo check -p narf-time --tests`, all 16 focused `time/wheel` QEMU tests,
and the automatic clean boot smoke. The remaining timer-wheel cache stays
uncommitted because its two-atomic publication can expose a stale later
deadline and skip a due wake; it still needs the review-requested SMP stress
or a single-atomic/versioned design. The ext2/VFS/
metadata-syscall group also remains uncommitted because stale cached inode
snapshots and ignored metadata persistence errors are unresolved review
findings; checkpointing those as finished would be misleading.

The page-cache checkpoint is intentionally limited to
`drivers/fs/ext2/src/volume.rs`: a cache hit now returns before the
volume-global asynchronous fill lock, while a miss takes that lock and repeats
the lookup before issuing I/O. This preserves identical-miss coalescing and
lets shared Qt/KDE pages avoid waiting behind unrelated cold reads. Existing
counted-device coverage proves a repeat ext2 data-block read does not issue a
second device request; the focused two-vCPU ext2 suite and boot smoke pass.
The aligned direct-to-destination read optimization is still mixed into the
dirty `node.rs` metadata series and was not smuggled into this commit.

The 128-MiB `DEFAULT_MAX_RESIDENT_PAGES` value is only a pre-boot fallback.
Before mounting the Fedora disk, `frame/src/bare_main.rs` replaces the default
with half of detected RAM and sets the low watermark to one thirty-second of
RAM. This 8-GiB run therefore has an approximately 4-GiB hard cache ceiling
and starts watermark-driven reclaim around 256 MiB of free frames, not a
128-MiB effective cache. Cache pages are buddy-frame backed, repeat hits share
an `Arc` without device I/O, clean pages are CLOCK-reclaimable, and ext2
registers the cache with the central shrinker.

Numerically, the guest reported 2,097,019 usable 4-KiB frames (about 8,121
MiB). The runtime cap is therefore about 1,048,509 pages, or 4,095.7 MiB, and
the one-thirty-second low watermark is about 65,531 pages, or 256 MiB. The
128-MiB constant is never the effective cap for this Fedora boot.

### QDBus trace: wake delivery works; partial munmap is the startup blocker

The narrow capture
`/tmp/narf-fedora-qdbus-worker-syscall-trace-8g-20260802.trace` follows only
the `QDBusConnection` worker. It supplies direct counter-evidence to the
remaining wake hypothesis:

1. The worker connects its AF_UNIX session-bus socket, sends the leading NUL
   and 24-byte AUTH request, and wakes to receive the 37-byte and 15-byte
   authentication responses.
2. It sends `BEGIN` and the 128-byte binary D-Bus `Hello` request.
3. Poll wakes again; `recvmsg` returns a 258-byte reply, followed by the
   expected `EAGAIN` after the socket has been drained.

Thus neither epoll/poll delivery nor the session bus is holding
`KUpdateLaunchEnvironmentJob`. The high-volume trace itself is too
perturbative for a boot-time measurement, but its syscall sequence identifies
the actual retry loop. On every glibc secondary-arena attempt:

```text
mmap(NULL, 0x8000000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS) = window
munmap(window, prefix_len)                                  = 0
munmap(aligned_heap + heap_size, suffix_len)                = EINVAL
mprotect(aligned_heap, 0x21000, PROT_READ|PROT_WRITE)       = EINVAL
... abandon and retry another 128-MiB window ...
```

The first call worked only because `window` was the region base. The old
`sys_munmap` discarded that whole region via `unmap_region(window)` and never
read `arg1`; the suffix and `mprotect` then correctly found no VMA. This is why
the failure looked like a stuck Qt D-Bus helper while its CPU and mapping
activity continued.

The quantified trace contains 675 successful 128-MiB reservations, 675 failed
header `mprotect` calls, and 1,351 failed `munmap` calls. That is about 84.4
GiB of monotonically consumed *virtual address space* during the perturbed
20-minute capture, not 84.4 GiB of physical memory and not page-cache use.
Socket/auth/Hello replies and eventfd callback writes succeed in the same
capture.

`userspace/src/handlers/sys_munmap.rs` now validates aligned base/non-zero
length, rounds length up as Linux does, checks overflow and the user-half
ceiling, and delegates to
`AddressSpace::punch_fixed`. That existing path atomically splits overlapping
VMAs, tears down only covered PTEs, flushes before frame reuse, and preserves
prefix/suffix backing. File-mapping owner metadata is split afterward with
`mapped_file::punch_current`, retaining the lifetime reference for surviving
fragments. The regression reproduces glibc's prefix trim, suffix trim, and
`mprotect(..., 0x21000, RW)` sequence and also pins non-page-multiple length
rounding. The native v1 `OpCode::Munmap` remains a base-only whole-VMA
operation in the ABI bridge; raw Linux syscall 11 alone takes the strict
range, avoiding an unversioned ABI break. No `memory/` TCB code needed to
change.

The first uninstrumented 8-GiB/SMP2 acceptance boot with the range fix is
captured in
`/tmp/narf-fedora-plasma-munmap-fix-8g-20260802.log`. It confirms 8,191 MiB
usable RAM and reaches `basic.target`, `multi-user.target`, a live
`startplasma-wayland`, and stable `kwin_wayland` PID 168. Through probe 136,
however, `plasmashell` is still absent and `org.freedesktop.portal.Desktop`
activation has timed out. Therefore the arena fix is real but is not yet a
complete Plasma boot; a new max-reasoning semcode review is analyzing this
post-munmap frontier. Do not treat this run as `PLASMA-READY`.

The live post-fix QDBus syscall trace then directly verifies the glibc arena
sequence on the real Fedora workload: a 128-MiB reservation succeeds, the
prefix and suffix `munmap` calls both return success, and the aligned 0x21000
RW `mprotect` returns success. The current userspace kernel-test rerun includes
the named `smoke_munmap_preserves_glibc_arena_middle` test and finishes 363
pass / 0 fail / 0 skip, followed by a clean boot smoke.

### Post-KWinWrapper D-Bus trace: all environment replies arrive

The regenerated image runs a narrowly filtered `dbus-monitor` on Plasma's own
fresh session bus before executing `startplasma-wayland`. This gives
serial/reply-serial evidence without syscall tracing. In the live 8-GiB/SMP2
run:

* the monitor itself becomes active before `startplasma` submits work;
* the initial environment batch receives immediate `ServiceUnknown` errors
  for the deliberately absent `org.kde.Startup`/`org.freedesktop.systemd1`
  services and successful returns from the bus daemon;
* KWin wrapper sender `:1.3` submits DISPLAY, WAYLAND_DISPLAY, and XAUTHORITY
  updates as serials 2 through 6;
* `UpdateActivationEnvironment` serial 5 returns, `SetEnvironment` serial 6
  returns `ServiceUnknown`, and `org.kde.Startup` returns each of serials 2,
  3, and 4;
* the bus then emits `NameOwnerChanged("org.kde.KWinWrapper", "", ":1.3")`
  at 263.391595 s, and probe 54 observes live `kwin_wayland` PID 173.

This rules out an unmatched environment-update callback as the current gate.
The next visible long wait is portal activation. PermissionStore activates;
Documents starts but exits after `/dev/fuse` open fails with `EPERM`; the
desktop portal activation finally returns `TimedOut` at 390.579658 s.
`startplasma` and KWin remain alive while `plasmashell` stays absent through
the continuing probe. A max-reasoning follow-up is localizing the exact
post-wrapper process/name wait before any portal workaround is made.

The follow-up max-reasoning source review identifies the exact classic-session
sequence after `KWinWrapper`: `plasma_session` synchronously waits for
`kcminit_startup` to exit, then for D-Bus names `org.kde.kded6` and
`org.kde.ksmserver`; only Phase0 then launches plasmashell. The monitor and
probe now cover those process/name transitions plus `plasma_session` itself.
This avoids incorrectly treating the unrelated portal timeout as the next
session gate.

The review also found a definite Fedora environment defect in that portal
path. NARF's stable synthetic `DevFuseNode` reported mode 0600, while Fedora's
`/usr/lib/tmpfiles.d/static-nodes-permissions.conf` requests `/dev/fuse` mode
0666. Synthetic-file chmod currently falls back to accepted-but-ignored, so
tmpfiles reported success while the mode remained 0600 and user `narf` got
`EPERM`. `DevFuseNode` now defaults to Linux-compatible 0666, with the static
device metadata test and filesystem §3 updated. The live replay confirms that
the open denial is gone: Documents proceeds to `mount(2)`, which now fails
with `Bad address`. That is a separate FUSE syscall/ABI defect and proves the
0666 change has the intended effect without proving the portal is healthy.
The focused x86_64 `filesystem/devfs` QEMU suite also passes 17/17, including
`smoke_dev_static_linux_metadata` with the Fedora-compatible mode assertion.

The same replay (`/tmp/narf-fedora-fuse-mode-fix-8g-20260802.log`) reaches
`plasma_session` at probe 54, KWin at probe 58, and `kcminit_startup` at probe
59. KWin stops making progress after probe 65 and is gone by probe 74.
`kcminit_startup` remains active through probe 74 and then completes; `kded6`
briefly reuses PID 175 at probe 75, but is gone by probe 76 without ever
reaching `org.kde.kded6`. `plasma_session` remains alive waiting on that
session gate while `ksmserver` and `plasmashell` never appear through probe
152, when the already-conclusive run was stopped. The next narrow capture
therefore targets the `kded6` exit first and the
earlier KWin exit second. No `PLASMA-READY` has been observed.

An exact-`kded6` syscall-trace replay
(`/tmp/narf-fedora-kded6-syscall-8g-20260802.trace`) did not reach `kded6` at
all, which is itself the stronger localization. The expanded probe showed one
`kcminit_startup` at probe 55 and both the forked child plus pipe-waiting parent
from probes 56 through 62. KWin was live over the same interval. At guest time
358.837 s the bus reported `org.kde.KWinWrapper` losing its owner; immediately
afterward `startplasma-wayland` printed `Shutting down`, and `plasma_session`,
KWin, and both kcminit processes disappeared by probe 63. Because no task ever
matched the trace selector, there are correctly no `kded6` syscall records.
This establishes the earlier KWin/wrapper exit as the next reproducible
prerequisite failure; the narrow trace target is now exact `kwin_wayland`.

The successful exact-KWin retry
(`/tmp/narf-fedora-kwin-syscall-retry-8g-20260802.trace`) names the failure.
KWin is active throughout startup (library mappings, config reads, DRM probes)
rather than blocked in epoll. Its decisive sequence is:

```text
openat(AT_FDCWD, "/dev/dri/card0", O_RDWR|O_CLOEXEC) = -EPERM
... orderly Qt/KWin cleanup ...
exit_group(1)
[process-exit] comm=kwin_wayland code=1
org.kde.KWinWrapper NameOwnerChanged :1.3 -> ""
```

The denial occurs because `DriCardFile` currently reports `0620 root:root`.
Fedora policy expects a `0660 root:video` primary node (and grants the desktop
user device access through the `video` group or a logind seat ACL); this image
deliberately has no logind seat manager. The same audit also exposed a general
DAC gap: NARF stores supplementary groups, but the open path's `Accessor`
contains only fsuid/fsgid, so a `video` supplementary membership would not be
considered. This is a device-policy/credential-access defect, not an epoll or
page-cache failure. The proposed fix is under max-reasoning review before
checkpointing because a generic driver must not simply hard-code Fedora's
numeric GIDs.

### Max-reasoning DRM/DAC review and the implemented narrow fix

The requested max-reasoning review used semcode over NARF and systemd's
credential setup. It rejected the first proposed hard-coded `video`/`render`
numeric GIDs as both distribution-specific and ineffective. systemd does run
the normal `exec_invoke -> get_supplementary_groups -> enforce_groups ->
setgroups/setresgid` chain, and NARF preserves a task's supplementary group
list across fork. However, NARF's filesystem `Accessor` currently contains
only fsuid/fsgid, so the open path never consults the supplementary list.

The review also rejected making supplementary groups authoritative as part of
this checkpoint. NARF currently accepts `setgroups` and several uid/gid/fsuid
transitions without Linux's privilege checks. Feeding that list into DAC now
would convert a formerly cosmetic, caller-writable value into filesystem
authority. Supplementary-aware DAC therefore remains a separate credential-
hardening change that must first enforce the corresponding privilege and user-
namespace rules.

The narrow boot fix instead follows Linux device policy:

* both DRM primary and render nodes begin at conservative devtmpfs metadata
  `0600 root:root`;
* each registered card owns shared metadata for its primary and render node,
  so a fresh `/dev/dri` lookup observes previous `set_owners` and `set_perms`
  changes;
* Fedora's existing udev rules set primary nodes to `root:video 0660` and
  render nodes to `root:render 0666`, with no distribution GIDs embedded in
  the driver;
* the verification-only `narf-plasma.service` uses primary `Group=video`.
  This works with NARF's current fs-gid DAC. The image also keeps `narf` in
  `video,render` for future supplementary-aware credential support.

The final review pass found a second, boot-critical metadata bug before the
image rebuild. systemd-udevd opens a device with `O_PATH`, then applies rules
through `fchownat`/`fchmodat2` using an empty path plus `AT_EMPTY_PATH`.
`sys_fchmodat` previously resolved the empty string as the caller's cwd,
potentially chmodding `/` while returning success and leaving the DRM node
unchanged. The empty-path arm now reshapes the request to fd-backed
`sys_fchmod`; empty paths without `AT_EMPTY_PATH` return `ENOENT`.

The final focused x86_64 QEMU run is captured in
`/tmp/narf-drm-metadata-tests-final-20260802.log`: 1,034 selected GPU/syscall
ABI tests pass with zero failures/skips, including persistent card/render
metadata, `smoke_abi_pathx_fchmodat2_empty_path_fd`, and the positive/negative
`fchownat` flag regression; the automatic boot smoke exits cleanly. The
metadata is held beside the public `DrmCardEntry` table, preserving that
struct's existing public construction interface. `cargo check` passes for
`narf-drivers-gpu --all-features` and `narf-userspace --tests --features
linux-compat`; formatting, shell-syntax, and diff checks are clean.

The Fedora disk was regenerated successfully. Image inspection confirms both
`video:x:39:narf` and `render:x:105:narf`, while the installed Plasma unit has
`User=narf`, `Group=video`, and `KWIN_DRM_DEVICES=/dev/dri/card0`. This
establishes the static image/code path but not the live result: only an 8-GiB
boot followed by `PLASMA-READY` can close the boot gate.

The first 8-GiB/SMP2 acceptance attempt with this image is captured in
`/tmp/narf-fedora-drm-access-fix-8g-20260802.log`. It reaches
`basic.target`, starts the normal Plasma service, and launches
`startplasma-wayland` at probe 32. It does **not** reach the DRM open: through
probe 180 the start executable remains alive (`state=R`, CPU ticks increasing
slowly from 666 to 727), while `plasma_session`, KWin, kcminit, kded, ksmserver,
and plasmashell all remain absent. The probe then emits `PLASMA-BLOCKED`. This
run therefore neither validates nor refutes the udev/card-open fix; it exposes
the already-seen intermittent earlier pre-session boundary instead.

A 10-second host profile at that boundary is stored in
`/tmp/narf-fedora-pre-session-20260802.perf.data`: 2,484 samples, zero loss,
with both TCG vCPU threads busy. As in the earlier host profile, symbols are
mostly generated/stripped QEMU code plus host fd/futex bookkeeping, so it
cannot recover the guest call chain. The live probe and continued timer/getty
activity rule out an all-CPU kernel freeze, but an exact startplasma syscall or
narrow system-bus D-Bus trace was still needed to distinguish a missing reply
from slow filesystem work.

The corrected prefix-filtered syscall replay is
`/tmp/narf-fedora-startplasma-prefix-syscall-8g-20260802.trace`. (The preceding
`trace_comm=startplasma-wayland$` attempt matched nothing because NARF's comm
name is truncated; `trace_comm=startplasma` is the valid selector.) It rules
out page-cache slowness at this occurrence. Task 100 completes the locale and
configuration reads, installs signal handlers, maps an 8-MiB thread stack,
and successfully executes `clone3`. The child task then reaches:

```text
task 121: set_robust_list                         = 0
task 121: sigprocmask(SIG_SETMASK, ...)           = 0
task 121: futex(Qt thread-start handshake)        = 0
task 100: futex(child-ready word, FUTEX_WAIT, 0)   [blocks]
task 121: prctl(PR_SET_NAME, ...)                  [no SYSR]
```

At first glance, the unmatched `prctl` appeared to be a kernel-side spin. Code
inspection disproves that inference: the return-side syscall filter calls
`syscall_trace_target_task()` again. `PR_SET_NAME` successfully changes this
thread's comm from the inherited `startplasma-wayland` name to
`QDBusConnection`, so the `startplasma` selector suppresses the `SYSR` and all
subsequent worker syscalls. The creator's futex wait is normal Qt thread-start
synchronization. This trace therefore identifies the worker creation point but
does not move the known blocker below `prctl`; the next replay must select both
`startplasma` and `QDBusConnection`.

The requested max-reasoning review independently confirmed that Plasma 6.7.3
performs a blocking `org.freedesktop.locale1` Properties.GetAll call before
`runEnvironmentScripts`, `setupPlasmaEnvironment`, and
`startPlasmaSession`. Earlier traces had shown the QDBus worker authenticate,
send that 180-byte request, and wait without a reply. The new trace is
consistent with that source boundary but loses visibility exactly when the
worker renames itself, before it can show the socket exchange. Removing the
locale1 service activator would make a missing locale service fail quickly in
the image and is a possible verification-image workaround, but the dual-comm
trace should first distinguish delayed activation/reply from a lower
system-bus wake defect. The review also recommends masking the
crash/restart-looping console gettys in the acceptance image to remove
unrelated PID1/timer churn.

The dual selector replay
`/tmp/narf-fedora-startplasma-qdbus-syscall-8g-20260802.trace` confirms the
filter explanation. The worker's `prctl(PR_SET_NAME)` returns zero, both
glibc arena `munmap` trims and the following `mprotect` return zero, and the
worker opens fd 5 and connects successfully to `/run/dbus/system_bus_socket`.
The repeated `poll(fd5, ..., -1)` entry/`0 InvalidOp` trace pairs during D-Bus
authentication are internal park/backstop cycles, not zero returns observed by
Qt: `poll_common` rewinds RIP over the syscall before `own_stack_block`, then
the return logger sees the placeholder result when that parked kernel frame is
resumed. Userspace immediately re-executes the same syscall. This is bounded
re-polling, but the per-cycle serial trace makes the guest much slower, so the
run was stopped after it supplied these discriminators rather than waiting for
the already-captured 180-byte locale request again.

The max-reasoning review's accepted image workaround is narrower than masking
`systemd-localed.service`: remove only
`/usr/share/dbus-1/system-services/org.freedesktop.locale1.service`, causing
dbus-broker to return `ServiceUnknown` without the broker-to-PID1 activation
chain. Plasma 6.7.3 logs the non-reply and unconditionally continues into its
environment scripts and session launch; locale1 only supplies
`XKB_DEFAULT_*`, so the service explicitly sets model `pc105` and layout `us`.
The regenerated image was inspected with debugfs and contains those settings
and no locale1 activator. This is deliberately labelled an acceptance-image
workaround, not a kernel wake fix. A separate >64-waiter SMP finite-`ppoll`
regression remains appropriate because the earlier synchronous call also
failed to deliver its expected finite timeout.

The resulting uninstrumented 8-GiB/SMP2 run is
`/tmp/narf-fedora-locale-bypass-8g-20260802.log`. It exposes two distinct
latencies rather than a single freeze. systemd marks the Plasma unit started,
but its executor takes until probe 52 to reach `dbus-run-session`; a 10-second
host profile at that pre-exec boundary contains 5,720 samples with zero loss
and both TCG vCPU threads near 100%, but generated/stripped QEMU code again
cannot recover the guest callchain. After startplasma appears, the initial
system-bus/locale phase still consumes roughly probes 54 through 79 before CPU
activity resumes. Removing the locale1 descriptor therefore prevents the
localed activation chain but does not remove the lower D-Bus authentication or
reply/timeout latency.

Crucially, this run then crosses both prior gates. `plasma_session` appears at
probe 86. All wrapper environment calls receive replies, KWinWrapper is owned
at guest time 439.742 s, and probe 88 observes `kwin_wayland` PID 226 plus
`kcminit_startup` PID 228. KWin remains live beyond the exact point where the
old image returned `EPERM` from `/dev/dri/card0` and exited, providing live
evidence that persistent udev metadata plus `Group=video` fixed the primary
DRM access blocker. By probes 89--93 both forked kcminit processes are live;
`kded6`, ksmserver, and plasmashell are not yet present. The independent FUSE
mount still fails with `Bad address`. This is the farthest clean acceptance
run so far, but it is not `PLASMA-READY` yet.

The same run continues through probe 111 with KWin and both kcminit processes
alive. It logs repeated `Couldn't change directory to
"/usr/share/X11/xkb"`, `Keyboard initialization failed`, and virtual-core-
keyboard activation failures while the session is still before kded. This
initially looked like a missing `xkeyboard-config` package, but post-run
debugfs inspection disproves that: `/usr/share/X11/xkb/rules` is a real 0755
directory and contains the expected `base`, `evdev`, and XML/LST rule files.
The recipe now asserts the package explicitly for future clean/incremental
trees, but the observed error is a path/chdir compatibility failure rather
than absent disk content. The next exact syscall target, if it repeats, is
Xwayland's `chdir`/path resolution.

Static image inspection now identifies the exact mismatch. Despite `test -d`
following it successfully in the recipe, debugfs reports
`/usr/share/X11/xkb` itself as a symlink with target
`../xkeyboard-config-2`; the target is a populated 0755 directory. Semcode
traces `sys_chdir` through `resolve_cwd_path` to `resolve_dir_absolute`.
That final helper walks only directory entries and intentionally does not
follow symlinks, so Linux-compatible `chdir(2)` incorrectly rejects this
valid link-to-directory. `sys_chdir` now expands the complete path through the
existing mount-aware `resolve_vfs_symlink_path(..., true)` before its directory
validation, with a syscall-ABI regression that creates a directory symlink
and requires `chdir` to accept it. `cargo check -p narf-userspace --tests
--features linux-compat` and formatting pass. The two-vCPU x86_64
`syscall_abi` QEMU group then passes 997 tests with zero failures and one
topology-dependent skip, followed by a clean boot smoke. This verified subset
is commit `65990088` (`userspace: follow directory symlinks in chdir`); the
notes were excluded from that commit as required.

The rebuilt live run confirms the narrow `chdir` correction: the previous
`Couldn't change directory to "/usr/share/X11/xkb"` diagnostic is absent.
It reaches `plasma_session` at probe 49, KWin plus one kcminit process at
probe 52, and both kcminit parent/child processes at probe 53. KWin remains
alive through at least probe 102 and the active kcminit CPU counter rises
steadily, establishing a new stable high-water mark rather than an epoll
sleep. However, Xwayland still cannot initialize its keyboard. Its later
diagnostics are now more specific: `XKB: Failed to compile keymap`, followed
by repeated `syntax error: line 1 of stdin` / `Errors encountered in stdin;
not compiled.` from the compiler subprocess. Thus the filesystem `chdir`
defect is fixed, but an Xwayland-to-xkbcomp stdin/pipe/exec data-path issue
remains. The capture window ends at probe 136 with KWin and both kcminit
processes still alive; the selected kcminit CPU counter has climbed from 9 to
1,612, but kded6, ksmserver, and plasmashell never appear. No
`PLASMA-READY` is emitted. This is the strongest session-stability result so
far, while also proving that the environment is not fully booted yet.

The first exact `Xwayland,xkbcomp` syscall-trace attempt
(`/tmp/narf-fedora-xkbcomp-syscall-8g-20260802.log`) did not reach either
selected process, so its lack of syscall records is not evidence about the
stdin stream. In that perturbed run KWin appears at probe 59, accumulates CPU
through probe 63, then advances only from 1,146 to 1,152 ticks through probe
83 and disappears at probe 84 before `kcminit_startup` or Xwayland launch.
The run was stopped after the target became unreachable. This is another
sample of the earlier KWin/session variability, not a reproduction of the
later XKB compiler failure. A clean retry must actually show `SYSC`/`SYSR`
records for Xwayland or xkbcomp before it can support a pipe/dup/exec fix.

The clean retry
(`/tmp/narf-fedora-xkbcomp-syscall-retry-8g-20260802.log`) also fails before
the selected processes exist. It advances faster to `plasma_session` at probe
44 and KWin at probe 47, but KWin's CPU counter stops making material progress
after probe 50. `org.kde.KWinWrapper` loses its owner at guest time 290.020 s;
one kcminit process is visible for a single probe, then startplasma shuts the
session down at probe 58. This second target-less trace was stopped. Together
the two retries prove that tracing only Xwayland/xkbcomp is non-perturbing in
syscall volume yet still does not guarantee the boot reaches Xwayland; neither
retry answers the parent-write versus child-read question.

An uninstrumented 8-GiB/four-vCPU run
(`/tmp/narf-fedora-plasma-smp4-8g-20260802.log`) shows that extra vCPUs reduce
the cold sysinit wall time: it crosses the apparent remount quiet point in
under a minute, reaches `basic.target`, launches `plasma_session`, and keeps
KWin plus both kcminit processes alive through probe 117. Their CPU counters
continue to advance slowly, but kded6, ksmserver, and plasmashell remain
absent. The run was stopped so the shared QEMU disks could validate the newly
identified cgroup-read recursion fix. It is another stable high-water sample,
not `PLASMA-READY`, and it used the pre-`5435f629` kernel.

The rebuilt post-`5435f629` acceptance run is
`/tmp/narf-fedora-cgroup-read-fix-smp4-8g-20260802.log`. With 8 GiB and four
vCPUs it crosses sysinit/basic without an all-CPU quiet interval, reaches
`plasma_session` at probe 37, and has KWin plus both kcminit processes live by
probe 40. The selected kcminit CPU counter advances from 454 to 796 through
probe 59, so this phase is active work rather than a lost wake. This single
crossing is live supporting evidence for the cgroup-read recursion fix; the
forced 46-test result is its deterministic regression proof.

The run establishes a new session high-water mark but still does not boot the
shell. `org.kde.KWinWrapper` loses owner `:1.3` at guest time 376.641956 s.
Immediately afterward kcminit child task 161/pid 158 takes a userspace #GP at
RIP `0x4090015d7735` inside an executable mapping. The kcminit parent then
completes, and `kded6` appears at probes 60--61 (CPU 264 -> 1,096) before it
also exits by probe 62. ksmserver and plasmashell never appear; the independent
Documents FUSE mount still fails with `Bad address`. The run was stopped once
the session could not recover.

#### Max-review result: the #GP is glibc abort fallback, not corruption

The max-reasoning review symbolized the exact Fedora mappings and followed the
NARF signal call chain with semcode. Both faults are deterministic glibc
`abort+0x8b`, the deliberate `hlt` at libc offset `0x1735`: kcminit at
`0x4090015d7735` and portal-kde at `0x4090037d3735`. Saved returns map to Qt's
`qAbort` (`libQt6Core+0x1b0b4`) and fatal logging
(`QMessageLogger::fatal+0xea`). Thus neither fault is a random RIP, signal
frame, or context-switch corruption. Qt called fatal, glibc tried to raise
`SIGABRT`, and only reached `hlt` because the abort signal did not terminate
the task.

The fatal register frame proves glibc's final operation was a successful
`rt_sigprocmask(SIG_UNBLOCK, {SIGABRT}, NULL, 8)`: `rdi=1`, the pointed mask is
`0x20`, `rdx=0`, `r10=8`, `rax=0`, and `rcx` is the following `hlt`. Glibc's
preceding sequence is self-`tgkill`, reset `SIGABRT` to `SIG_DFL`, a second
self-`tgkill`, then unblock and fall back. The missing pending signal is
explained by `signal_tid_from_user`: it previously treated a numeric raw
TaskId as authoritative before translating a leader's Linux-visible gettid.
Independent PID and TaskId allocators can collide, especially after KDE's
thread churn. If a leader PID equals an unrelated group's nonleader TaskId,
`tkill` is misrouted and `tgkill(getpid(), gettid(), SIGABRT)` fails its tgid
consistency check with `ESRCH`. The divergent live identities (task 161/pid
158 and task 202/pid 181) fit this collision.

Commit `948aa535` resolves the caller's exact Linux-visible gettid value to the
caller before considering other raw task IDs and shares that computation with
`gettid`. The regression constructs exactly the previously missing case: the
current leader PID numerically equals an unrelated group's nonleader TaskId,
then both `tkill(gettid(), SIGUSR1)` and
`tgkill(getpid(), gettid(), SIGUSR1)` must queue only on the caller. The exact
three-file staged snapshot passes `cargo check -p narf-userspace --tests
--features linux-compat`, the complete `syscall_abi` QEMU run, and clean boot
smoke. The `hlt` must not be special-cased: synchronous #GP-to-SIGSEGV behavior
is correct if user code actually executes it. A future live fork/abort test
should additionally require `WIFSIGNALED(SIGABRT)`, and a longer-term external
PID/TID design should use a collision-free namespace or explicit map.

This fix explains why the fatal abort itself became a misleading SIGSEGV, but
not why Qt called fatal. The current fatal-only stack dump stops just before
the QtGui caller that owns the dynamic message; extending that dump from 96 to
128 words would capture it without hot-path perturbation. The decisive next
step is first the rebuilt 8-GiB Plasma replay: if kcminit/portal now terminate
as SIGABRT, capture their original fatal text/caller; if they no longer abort,
continue to the ksmserver/plasmashell gate.

The requested max-reasoning semcode review closes an important ambiguity in
that error. It followed NARF's pipe creation, fork/clone fd-table copy,
`dup2`, close-on-exec cleanup, exec, scalar/vector read, and scalar/vector
write paths, and also checked Xwayland 24.1.13's `RunXkbComp` call chain.
Xwayland creates a pipe, forks, dup2s the read end onto child stdin, execs a
shell command containing xkbcomp, and writes the generated keymap through an
`fdopen` stream in the parent. The exact Fedora image contains xkbcomp 1.5.0,
xkeyboard-config 2.46, and the required component files; running that same
xkbcomp against a valid `pc105`/`us` textual keymap in the chroot succeeds.
Host tracing confirms xkbcomp consumes fd 0 with ordinary 4-KiB `read` calls.

Empty input reproduces the observed line-1 syntax error, but it does not yet
prove kernel pipe data loss. Upstream `XkbWriteXKBKeymapForNames` can return
false before emitting the initial `xkb_keymap` text when its component names
or masks are incomplete, and Xwayland ignores that Boolean result. Static
review found that NARF preserves the shared pipe object across the expected
fork/dup2/exec chain and re-executes a blocking read while a writer remains;
it found no definite byte-corruption point. The decisive live evidence is
therefore the parent write count/result versus xkbcomp's fd-0 read count: no
write followed by EOF implicates incomplete XKB component state, while a
successful nonzero write followed by EOF or a different count implicates the
kernel fd/pipe path. A proper regression should fork, delay the parent so the
child blocks, dup2/exec the Fedora xkbcomp, write a known keymap, close, wait,
and assert successful output; it should then cover more than 64 KiB, writev,
and closed-reader variants.

The review did find adjacent definite NARF ABI defects, none proven causal
here. The smallest one is now fixed separately: closed-reader
`PipeWrite::write` returns `BrokenPipe`, making the existing syscall-layer
`SIGPIPE` plus `EPIPE` arm reachable. Its syscall regression closes the read
fd, writes one byte, and requires `-EPIPE`; the two-vCPU `syscall_abi` group
passes 998 tests with zero failures and one topology-dependent skip, followed
by a clean boot smoke. The implementation, test constant, regression, and
userspace §3 contract are commit `db8a6069`; this note is excluded.

Three reviewed defects remain uncommitted and separately scoped:
`sys_writev` lacks the scalar write path's blocking/full-pipe and broken-pipe
handling; `readv` treats an empty but still-open pipe as EOF; and dup2/dup3
copy offset/status values instead of sharing their open-file description.
They require their own regressions rather than a speculative bundle labelled
as the Plasma fix.

This run also confirms the review's getty finding: `console-getty` and
`getty@tty1` repeatedly crash/restart and flood PID1 with unrelated service,
SIGCHLD, and timer work. Both units are now masked in the acceptance image;
debugfs verifies the `/dev/null` unit links. The probe-111 run was stopped and
a clean 8-GiB replay started with that reduced churn. In
`/tmp/narf-fedora-getty-masked-8g-20260802.log`, the masks are effective and
the system reaches `basic.target`; `plasma_session` appears at probe 62 and
KWin at probe 65. KWin remains live through probe 78, then drops its
`org.kde.KWinWrapper` owner at guest time 381.642 s. One kcminit process is
briefly visible at probe 79 before startplasma shuts down the whole session by
probe 80. There is no `PLASMA-READY`; the run was stopped after the session
could no longer recover. Getty masking removes noise but does not by itself
fix the later KWin/session failure.

That KWin-targeted replay instead reproduced the separate intermittent early
freeze before KWin could exist. Serial stopped after PID 1 launched the first
sysinit fan-out, with the last line `Starting systemd-remount-fs.service`.
There was no log growth for more than four minutes while QEMU consumed about
218% host CPU with two vCPUs. A 15-second host `perf` capture
(`/tmp/narf-early-freeze-qemu-20260802.perf.data`) collected 3,247 samples with
zero loss; it confirms both TCG execution threads remain busy (with the normal
multi-thread TCG futex hand-off overhead), but stripped/generated host code
cannot identify the guest callchain. This is not a sleeping epoll wait and not
page-cache eviction pressure. The actionable replay target is exact PID 1
(`trace_comm=systemd$`), whose final `SYSC` without `SYSR` will identify the
in-kernel operation if the freeze repeats.

The exact-systemd replay
(`/tmp/narf-fedora-pid1-earlyfreeze-syscall-8g-20260802.trace`) crossed that
frontier instead of freezing. It produced paired `SYSC`/`SYSR` records for
PID 1's epoll waits (`epoll_pwait2 = 1`) and the surrounding cgroup filesystem
reads, and `systemd-remount-fs.service` completed. The run was then stopped
because tracing PID 1 logs its entire unit-catalog scan (including repeated
`TCGETS2 -> ENOTTY` probes on ordinary files) and materially slows boot. This
run supplies direct evidence that epoll delivery works at the formerly quiet
line, but the intermittent early all-CPU freeze still needs a reproducing PID
1 trace before its final unmatched syscall can be named.

The later post-DRM KWin-targeted replay
(`/tmp/narf-fedora-kwin-post-drm-retry-8g-20260802.log`) again reproduces the
same early quiet point before KWin exists: the last serial line is the start of
`systemd-remount-fs.service`, while two TCG vCPU threads consume about 219%
host CPU and the log does not grow. It was stopped after two minutes because
its selector could never match at this frontier. A fresh exact-PID1 retry
(`/tmp/narf-fedora-systemd-early-freeze-8g-20260802.log`) did not reproduce
the silence; it emitted roughly 60,000 syscall trace lines while PID 1 actively
read and parsed unit files, including the known repeated `TCGETS2 -> ENOTTY`
probes. It was stopped before the trace volume could dominate another full
boot. Like the earlier exact-systemd crossing run, this shows that per-syscall
serial tracing materially perturbs the timing and cannot by itself close the
intermittent all-CPU case. A new max-reasoning review is selecting a rarer,
low-perturbation transition or fatal-only dump instead of adding another hot
path trace.

An intermediate recorded run at
`/tmp/narf-fedora-post-wrapper-gates-8g-20260802.log` remained before
`plasma_session`: only `startplasma-wayland` was live and the session monitor
saw no calls through probe 78. KDE first performs a synchronous system-bus
`org.freedesktop.locale1.GetAll` in this phase; activation delays there are a
separate cold-start cost and are why the definitive replay keeps the
900-second window rather than shortening it around the later gate.

### Max-reasoning review results (semcode across NARF + systemd)

A dedicated read-only review covered every modified/untracked entry and used
semcode against both `/data/narf` and `/data/systemd`. Its findings, ordered by
severity, are:

1. **High: epoll has a scan-to-waiter-registration lost-wake window.**
   `epoll_wait_common` snapshots the global readiness generation before
   `collect_ready`, but `refresh_io_wait_generation_after_registration`
   previously overwrote that snapshot after installing the waiter without
   comparing it or rechecking this epoll instance. If child exit publishes
   blocked `SIGCHLD` before either signal/I/O waiter exists, both targeted
   wakes miss; the post-registration deliverable-signal check intentionally
   excludes blocked `SIGCHLD`. The level-ready signalfd is then discovered
   only by the timer fallback. This directly explains an occasionally missed
   wake, though an indefinite hang additionally requires the fallback to
   fail. This is now fixed with a passive final rescan of the specific epoll
   instance after waiter registration, avoiding both this window and false
   retries from unrelated global I/O.
2. **High: deferred timer overflow can permanently lose that fallback.**
   `drain_due_to_deferred` removes a due wheel slot before pushing its waker to
   the 64-entry deferred queue. If the queue is full and another registration
   fills the vacated wheel slot before reinsertion, a completely full wheel
   leaves nowhere to restore the waker. The current last arm drops it in IRQ
   context, both losing the wake and potentially dropping the last allocator-
   backed waker reference where freeing is forbidden. This is now fixed by
   holding the wheel lock through the bounded queue insertion; on `Full`, the
   exact slot and generation are restored before releasing the lock and later
   due entries remain untouched for the next drain.
3. **High: ext2 cached inode snapshots can overwrite newer state.**
   `Ext2Node::from_inode` caches the entire inode and `load_inode` never
   refreshes it. Independent handles can therefore write stale uid/gid/mode,
   size, or block-pointer fields over a newer inode. Existing persistence
   coverage drops and re-resolves the first handle, so it misses concurrent
   stale handles. Mutation needs a shared per-inode cache/lock or a fresh
   serialized on-disk read.
4. **High for Fedora startup: metadata persistence errors are reported as
   success.** `sys_fchmodat` ignores pending/timeout and filesystem errors;
   `mkdir_path` ignores owner/mode update failures. systemd can consequently
   believe a `RuntimeDirectory=` is user-owned mode 0700 while it remains
   root-owned or 0755, after which D-Bus may reject it. Errors must propagate,
   and `IN_ATTRIB` must be emitted only after persistence succeeds.
5. **Medium: overlay metadata mutation lacks lower-directory copy-up.**
   `OverlayDir::{set_dir_mode_async,set_dir_owners_async}` call only
   `upper_dir()`, returning `ReadOnly` for a lower-only directory even on a
   writable overlay. They should ensure/copy up the upper directory first.
6. **Medium: chmod drops setuid/setgid/sticky bits.** Regular-file fchmod,
   fchmodat, and ext2 `set_perms` mask with `0o777` rather than `0o7777`; the
   ABI tests assert return values but not resulting special bits.
7. **Medium: `*at` semantics remain incomplete.** fchmodat ignores dirfd and
   flags; the combined fchmodat/fchownat path accepts an empty path without
   requiring `AT_EMPTY_PATH`, ignores invalid flags and
   `AT_SYMLINK_NOFOLLOW`, and treats arbitrary negative dirfds like
   `AT_FDCWD`.
8. **Medium: adjacent signal defects remain.** Child exit directly ORs
   `SIGCHLD` without advancing `SIGNAL_READABLE_GEN`, so an EPOLLET signalfd
   can lose a hidden drain/refill edge. Stop/continue publication performs no
   signalfd/readiness wake. The compatibility registration also maps
   `EpollPwait` to `sys_epoll_wait`, ignoring its temporary mask; systemd's
   current null-mask `epoll_pwait2` is unaffected by that last defect.
9. **Medium: timer-cache concurrency coverage is insufficient.** The separate
   deadline/valid atomics can transiently expose an older later deadline
   during insertion, making the comment's strict “never later” claim too
   strong. The arm callback should recover, but tests must cover concurrent
   register/refresh/cancel/drain, cache-versus-slot invariants, and more than
   64 simultaneous expiries.

The reviewer also confirmed the precise systemd PID 1 chain:

```text
manager_loop
  -> sd_event_run
  -> sd_event_wait
  -> process_epoll
  -> process_io
  -> sd_event_dispatch / source_dispatch
  -> manager_dispatch_signal_fd
  -> enable sigchld defer source
  -> manager_dispatch_sigchld
  -> waitid
  -> manager_invoke_sigchld_event
  -> service_sigchld_event
```

PID 1's signalfd is a normal level-triggered `SOURCE_IO`; it does not traverse
generic `sd-event.c::process_signal`, and its registration has `EPOLLIN`
without `EPOLLET` or `EPOLLONESHOT`. Relevant systemd definitions are
`src/core/manager.c:521-600`, `:3142-3220`, `:3264-3303`, and
`src/libsystemd/sd-event/sd-event.c:4626-4832`.

### Wake fixes implemented after the review

`userspace/src/epoll.rs` now publishes the currently-waited epoll fd in the
task context just before parking. Both the own-stack park path and the legacy
future path install their normal I/O waiter and then call the passive
`epoll_fd_has_ready` probe. If the watched epoll instance became level-ready
in the original scan-to-registration window, the task removes the waiter and
immediately re-executes the rewound syscall. The probe uses
`EpollInstance::poll_readiness`; it neither acknowledges edge tokens nor
disarms `EPOLLONESHOT`. The new epoll regression verifies repeated probes do
not consume an `EPOLLET|EPOLLONESHOT` event and that the real `epoll_wait`
still delivers it.

`time/src/timer_wheel.rs::drain_due_to_deferred` no longer has a take/unlock/
enqueue/relock window. Its lock order is wheel then deferred queue; the only
deferred consumer releases the queue before invoking a waker, so there is no
reverse ordering. A 65-expiry regression fills the 64-entry deferred queue,
asserts that the overflow timer remains in the wheel, drains the queue, and
then verifies the retained timer wakes on the retry. This removes the known
path in which both epoll's primary wake and its timer backstop could be lost.

Validation so far: `cargo check -p narf-userspace -p narf-time`,
`cargo check -p narf-filesystem --features cgroup-memory`,
`cargo fmt --all -- --check`, and `git diff --check` pass. The cgroup-focused
two-vCPU run passes 44/44 tests and its post-test boot smoke exits cleanly. The
Fedora image was regenerated successfully after installing the probe; it must
be regenerated once more for the cgroup fixes and console-logging unit change.
The zombie-safe sustained KWin/Plasma oracle remains the next gate; until that
emits `PLASMA-READY`, the environment is not yet declared fully booted.

Changed-file accounting covered the three ext2 files, the filesystem trait,
specification and overlay files, timer wheel, ABI path tests, all seven changed
syscall/compat handler files, Fedora regeneration script, Plasma probe, and
this note. The inode UID/GID encoding, VFS async delegation, specification
update, and zombie-safe probe direction are sound; the defects above remain
review blockers. In particular, neither reaching `graphical.target` nor the
`Type=simple` service status proves Plasma: no run has yet produced the new
zombie-safe `PLASMA-READY` gate.

### Observed boot frontier: graphical target reached; Plasma processes not yet proved

The older captures do not prove a complete Plasma session. The closest old
run (`/tmp/narf-fedora-plasma.trace`, July 30) reaches `multi-user.target` and
eventually executes `/usr/bin/startplasma-wayland`, but it does not show a
successful `narf-plasma.service`, `graphical.target`, `kwin_wayland`, or
`plasmashell`. Another focused capture reports `narf-plasma.service` failed.

An August 2 boot of the current worktree and regenerated Fedora disk changes
that frontier. The uninstrumented command was:

```text
NARF_VBLK_IMG=/data/narf/target/narf-fedora-vblk.img \
NARF_QEMU_MEM_MB=2048 NARF_QEMU_SMP=2 \
XTASK_SYSTEMD_PID1_TIMEOUT_SECS=900 \
cargo xtask systemd-pid1 --arch=x86_64 --display none
```

The capture is
`/tmp/narf-fedora-current-plasma-long-20260802.trace`. It queued
`graphical.target`, started `dbus-broker.service`, reached `basic.target`,
reported `Started narf-plasma.service`, and finally reached both
`multi-user.target` and `graphical.target`. This also shows that the apparent
pause after the Fedora welcome banner was slow unit discovery, not a permanent
PID 1 epoll hang: an exact-PID syscall capture
(`/tmp/narf-fedora-current-pid1-syscall-20260802.trace`) continued walking and
loading unit files throughout that interval.

This is still not proof of a usable Plasma session. `narf-plasma.service` is
now `Type=simple`, so systemd marks it started after fork rather than after the
`dbus-run-session`/`startplasma-wayland` exec handshake. The capture contains
no direct observation of `kwin_wayland` or `plasmashell`. A follow-up boot must
trace those process names (or run an in-guest process probe) and show that they
remain alive. Two `avahi-daemon` tasks also faulted writing the user-stack
guard address `0x7ffffffe0000`; the service failed but systemd continued to
the graphical target. Accounts Service failed as well. These failures are not
the original PID 1 wake, but remain compatibility defects to triage.

The process-scoped follow-up capture is
`/tmp/narf-fedora-plasma-process-trace-20260802.trace`, built with
`--features syscall-trace` and
`trace_comm=startplasma,kwin_wayland$,plasmashell$,dbus-run-sess`. It proves
that `dbus-run-session` starts, forks a `dbus-daemon`, completes the daemon's
exec-status pipe handshake, and executes `/usr/bin/startplasma-wayland`.
During the handshake its blocking pipe read is represented by repeated
rewound syscalls with NARF status `InvalidOp`; after the daemon finishes exec,
the read returns 69 bytes followed by EOF and startup advances. Do not mistake
that trace-only retry stream for a returned zero-length Linux read.

`startplasma-wayland` then advances well into KDE/Qt initialization, including
locale/plugin discovery and creation of a Qt thread. Semcode/symbol-backed
inspection resolves that thread's `PR_SET_NAME` pointer to
libQt6DBus.so.6 rodata string `QDBusConnectionManager`; NARF truncates the comm
to `QDBusConnectionM`. That rename makes the thread stop matching the original
comm-scoped trace selector, so the absent matching `SYSR` is not by itself
proof that `prctl` hung. The main startplasma thread is waiting on a futex at
the capture frontier. A future scoped trace should include
`QDBusConnection`, but no `kwin_wayland` or `plasmashell` exec has yet been
observed.

To make the success condition explicit, the Fedora image recipe now installs
`narf-plasma-probe.service`. It prints two-second `PLASMA-PROBE` process-state
heartbeats and emits `PLASMA-READY` only after the same non-zombie
`kwin_wayland` and `plasmashell` PIDs survive a second check 10 seconds later.
Rejecting `Z`/`X` states is load-bearing here: the SIGCHLD bug under
investigation could otherwise leave a zombie that `pgrep` still counts.
`graphical.target` remains pending while the oneshot probe runs, so a reached
graphical target plus `PLASMA-READY` is the new boot gate.

After rebuilding the image with that probe, the first uninstrumented boot
(`/tmp/narf-fedora-plasma-probe-20260802.trace`) reproduced the intermittent
early stall. It queued `graphical.target` and began the initial sysinit service
fan-out, but stopped producing serial output immediately after
`modprobe@drm.service` completed. There was no progress for more than three
minutes, while the QEMU process continued consuming about 220% host CPU with
two vCPUs. This differs from the immediately preceding uninstrumented run,
which crossed the same frontier and reached `graphical.target`; the rebuilt
image therefore does not yet pass the new Plasma gate, and the intermittent
boot problem remains real. The run was stopped manually so its next replay can
trace PID 1 at that exact service-exit frontier.

The subsequent validation boots use 8 GiB (`NARF_QEMU_MEM_MB=8192`) as the
baseline, per the requested VM sizing. The guest reports `usable RAM: 8191
MiB`, with about 8120 MiB initially free, so these runs remove memory pressure
as an explanation for the quiet intervals:

* `/tmp/narf-fedora-plasma-wakefix-8g-20260802.trace` (2 vCPUs) reached
  `basic.target`, started both `narf-plasma.service` and
  `narf-plasma-probe.service`, but the probe emitted no heartbeat. This did not
  prove the guest itself was stuck: the original probe invoked external
  `pgrep` before its first output, so the oracle could block in process startup.
* The probe was therefore rewritten so its first-stage process scan and
  `/proc/<pid>/{comm,stat}` reads use Bash builtins only. A second audit caught
  that the first rewrite still used `$(...)`: Bash implements command
  substitution with a child shell and a SIGCHLD wait, so that was still
  capable of hanging before output on the very path under test. The current
  version returns values with `printf -v` and performs no command substitution
  before its first heartbeat. The image regenerated successfully with this
  genuinely fork-free version. The same live PID must still survive ten
  seconds before `PLASMA-READY` is accepted.
* `/tmp/narf-fedora-plasma-probe-builtin-8g-20260802.trace` (2 vCPUs) then
  stalled earlier, after `modprobe@drm.service`, before the probe was started.
* `/tmp/narf-fedora-plasma-smp1-8g-20260802.trace` repeated an even earlier
  quiet interval immediately after systemd's Fedora banner with one vCPU. It
  remained there for over four minutes before being stopped. Consequently the
  remaining problem is neither an out-of-memory artifact nor exclusively an
  SMP race.

An 8-GiB, one-vCPU, `trace_comm=systemd` replay
(`/tmp/narf-fedora-systemd-trace-smp1-8g-20260802.trace`) showed that the quiet
post-banner interval was active unit discovery. It then crossed the initial
service frontier and repeatedly showed PID 1's `epoll_pwait2` returning events,
128-byte signalfd reads, and `waitid` dispatches. That capture was stopped once
the suspected early SIGCHLD edge had demonstrably succeeded so the disk could
be regenerated with the fork-free probe. The final uninstrumented 8-GiB boot is
`/tmp/narf-fedora-plasma-final-8g-20260802.trace`. Until that probe prints
`PLASMA-READY`, the honest answer remains that the image can reach the Plasma
launcher but is not yet proven to boot a stable Plasma session.

### August 2 live GDB localization: epoll fixed, later cgroup lock recursion

The next regenerated probe initially failed with `pid: unbound variable`.
This was Bash dynamic scoping: `live_pid` declared a local named `pid` and
then attempted to return through an out-variable with the same name. The
probe now uses Bash namerefs for its output values and groups racing `/proc`
reads so an exited process cannot leak a redirection error. `bash -n` passes,
and a host-side run prints a heartbeat without forking or command
substitution. The image was regenerated after this correction.

The decisive 8-GiB, two-vCPU run is captured in
`/tmp/narf-fedora-plasma-probe-final-8g-20260802.trace`; QEMU also exposed a
read-only GDB stub on TCP port 1234. It reached `basic.target`, started the
Plasma service and probe, and continued through `multi-user.target`. The probe
first observed `startplasma-wayland` as PID 106, then—after roughly six minutes
under QEMU TCG—observed live `kwin_wayland` PID 204. This is direct proof that
the compositor exec path works. `plasmashell` had not yet appeared, so the run
still did not satisfy `PLASMA-READY`.

Two GDB snapshots separate two phases of that run:

* `/tmp/narf-fedora-plasma-gdb-snapshot-20260802.txt` found CPU 0 in
  `narf_scheduler::idle_wait` and CPU 1 in userspace while the probe continued
  to tick. That rules out the earlier suspected virtio-block IRQ-off wedge at
  that point; the long startplasma delay was live userspace progress.
* After KWin started, serial/probe timers stopped. The zero-perturbation
  snapshot `/tmp/narf-fedora-plasma-gdb-snapshot2-20260802.txt` found both
  CPUs spinning with IRQs disabled on the same `TASK_CGROUP` lock. CPU 0 held
  the lock in the following recursive chain:

```text
do_clone3
  -> cgroupfs::fork_inherit
  -> place_forced
  -> TASK_CGROUP.lock().insert
  -> BTreeMap node/slab allocation
  -> frame allocation
  -> cgroup_charge::try_charge
  -> cgroupfs::memory::charge_hook
  -> with_chain_states
  -> cgroup_of
  -> TASK_CGROUP.lock()       # recursive acquire; never returns
```

CPU 1 was simultaneously blocked in
`exit_group -> notify_task_exited -> cgroupfs::task_exited ->
TASK_CGROUP.lock()`. Because `IrqSafeSpinLock::lock` disables local IRQs before
spinning, the two CPUs also stopped the timer tick and the probe. This is a
distinct, later permanent-wedge cause; it does not invalidate the demonstrated
epoll scan/register lost wake or timer-overflow fixes.

The filesystem-only fix centralizes `TASK_CGROUP` mutations in a
helper that, after acquiring the IRQ-safe lock, suppresses allocator charging
only for the BTreeMap's cgroup bookkeeping allocations. The allocator charge
hook then returns before attempting membership lookup, so insert/remove cannot
reacquire their own lock. Its existing recursion flag is also being made
per-CPU: the old global `AtomicBool` incorrectly treated a legitimate charge
on another CPU as recursive and silently skipped its accounting. A
deterministic cgroup-memory regression invokes the charge hook through the
same locked mutation helper; without the bypass that exact test self-deadlocks.

The max-reasoning follow-up also caught a second lifetime-sensitive form of
the same cycle: the original one-line `cgroup_of` expression could keep its
temporary `TASK_CGROUP` guard alive while `unwrap_or_else(root)` reconciled
controller state for an absent pid. Because `root()` may allocate, that
fallback could re-enter the charge hook and membership lookup. `cgroup_of` now
copies the optional placement in an explicit inner scope and calls `root()`
only after the guard has dropped.

The first max-reasoning review identified the same recursion class in
controller-state maps: root/child state construction, enumeration, and
attach/detach callbacks could allocate or invoke controller code while
`ctrl_state` remained locked. Map mutations gained the narrow metadata-charge
bypass, construction moved outside the map lock, and attach/detach paths began
using snapshotted `Arc`s. The original follow-up test covered mutation
re-entry, but its 44-test result did **not** cover attribute rendering.

The later early-freeze review found that missing read-side cycle. PID 1 reads
`memory.min`, `memory.low`, `memory.high`, `memory.max`, and related files for
each service cgroup during the sysinit fan-out. `CgroupAttrFile::content` still
held `ctrl_state` while calling `ControllerState::read`; every memory read
formats a fresh `String`. A slab refill could therefore recurse as:

```text
sys_read -> CgroupAttrFile::content [ctrl_state held, IRQs off]
 -> MemoryState::read -> format!/alloc -> frame charge
 -> memory::charge_hook -> with_chain_states -> ctrl_state.lock
```

`memory.high` and `memory.max` had a second inner form: their field guard
survived through `max_line` formatting, while charging re-enters the same
`high` lock from `commit_charge` or `max` lock from `can_charge`. Commit
`5435f629` now clones a single controller `Arc` (or snapshots the controller
set) before every read/writable/write/files callback, copies every locked
memory scalar/limit into a local before formatting, and keeps the existing
metadata bypass only around map mutation/snapshot allocation. Forced tests
invoke the real charge hook from an outer read callback and between each
`memory.high`/`memory.max` snapshot and its formatting. The final two-vCPU
`filesystem/cgroupfs` run passes 46/46, including all four allocator-re-entry
classes, and its post-test boot smoke exits cleanly. A rebuilt 8-GiB Plasma
boot is still required for live liveness proof.

Earlier generator/performance captures provide supporting but non-decisive
context. `/tmp/narf-fedora-generators-trace-8g-20260802.trace` showed PID 1
waiting for its generator runner while the runner still had live generator
children, so it did not prove a missed SIGCHLD. In
`/tmp/narf-fedora-generator-perfdump-8g-20260802.trace`, periodic performance
dumps themselves stopped; sampled PCs just before that included ext2 inode
writes and task-identity locking. A max-reasoning semcode review initially
identified the virtio block controller's IRQ-off unbounded polling as a strong
generic wedge risk, but the live GDB snapshot above supplies the exact lock
cycle for this Plasma occurrence. The virtio risk should remain a separate
follow-up rather than being presented as the proven cause of this run.

#### Live startup profile: synchronous ext2/virtio reads dominate

The post-membership-fix acceptance boot is
`/tmp/narf-fedora-plasma-cgroupfix-8g-20260802.trace` (8 GiB, two vCPUs, QEMU
TCG). It crossed sysinit, D-Bus, and `basic.target`, launched the Plasma probe,
and observed `startplasma-wayland` PID 106. Because reaching KWin still took
minutes, three live GDB profiles were collected without adding kernel hot-path
instrumentation:

* `/tmp/narf-fedora-plasma-profile-sample1-20260802.txt`: one CPU was in
  `sys_mmap -> AddressSpace::materialize -> map_4kb`; the other was processing
  `close(2)` fd-table work.
* `/tmp/narf-fedora-plasma-profile-sample2-20260802.txt`: CPU 0 was in
  `sys_mmap -> ext2::read -> SyncBlock -> VirtioBlkPci::read_sectors`; CPU 1
  was tearing down an mmap and uncharging its frames through the cgroup-memory
  hook.
* `/tmp/narf-fedora-plasma-profile-sample3-20260802.txt`: CPU 0 was again in
  the same ext2 read chain, specifically polling
  `VirtioBlkPci::read_sectors` in `responsive_spin_until`; CPU 1 was servicing
  another task's `epoll_wait` ready-list allocation.
* `/tmp/narf-fedora-plasma-full-cgroupfix-gdb1-20260802.txt`, taken after the
  fully reviewed cgroup fix, is stronger: CPU 0 was in
  `sys_mmap -> ext2::read_inode_at -> read_block/read_byte_range ->
  SyncBlock::submit -> VirtioBlkPci::read_sectors` submitting/polling an
  eight-sector read, while CPU 1 was another `sys_mmap` blocked in
  `narf_lib::Mutex::poll` on the same ext2 volume I/O serialization. This
  confirms that the long pre-KWin interval is active serialized filesystem
  work even after the deadlock class is removed.

This explains the extreme but non-wedged pre-KWin latency: KDE/Qt cold-start
dynamic loading faults/mmap-materializes many file ranges through synchronous
ext2 block reads. The sync block adapter serializes these through the global
virtio controller and the driver busy-polls used-ring completion, consuming a
vCPU under TCG. More guest RAM does not remove cold filesystem reads. A
performance follow-up should measure and address read batching/page-cache use
and the synchronous block bridge; this observation is a profile, not a
protocol-compliant performance number.

The max-reasoning review's broader allocator-recursion warning is now addressed
by the controller-state snapshot/mutation changes and its deterministic test.
The boot acceptance run remains necessary because it exercises concurrent
fork/exit and controller churn at a scale the focused tests do not reproduce.

The same acceptance run later reached live KWin PID 179, but did not reach
plasmashell. KWin stopped accumulating CPU and then disappeared when
`ksplashqml` (task 186, pid 182) faulted:

```text
fatal-fault: task=186 pid=182 comm=ksplashqml sig=11 #GP vec=13
faultva=4090024a2735 rip=4090024a2735 user-rsp=7ffffffdead0
```

The faulting RIP is inside the reported executable VMA
`0x4090024a1000-0x409002610000`, so this is not the earlier all-CPU cgroup
spin and not proof of an unmapped instruction fetch. The full register, VMA,
and 96-word user-stack dump is in
`/tmp/narf-fedora-plasma-cgroupfix-8g-20260802.trace`. After the fault the
probe continued ticking, `startplasma-wayland` remained present, KWin was
gone, and no plasmashell appeared. This boot therefore fails the sustained
Plasma gate. The next image should mirror the Plasma unit's stdout/stderr to
the serial console and a focused trace should include `ksplashqml`, KWin,
startplasma, and the QDBus worker so the userspace instruction/library and
last syscall can be correlated with this zero-error-code #GP.

The regenerated full-cgroup-fix image also exposes a separate journald
compatibility failure during early userspace:

```text
/run/log/journal/<machine-id>/system.journal: Journal file uses a different
sequence number ID, rotating.
Failed to create new runtime journal: No such file or directory
```

The sequence-ID rotation is a normal recovery action, but failing to create
its replacement is not. Boot continues, so this is not the current PID 1 or
Plasma liveness blocker, and `journal+console` still preserves session output.
It nevertheless needs follow-up in `/run/log/journal` directory creation,
rename/unlink behavior, and the still-uncommitted metadata persistence/error
propagation path; otherwise failures may disappear from the journal.

The full-cgroup-fix acceptance run is captured in
`/tmp/narf-fedora-plasma-full-cgroupfix-8g-20260802.trace`. It crossed
`basic.target` and `multi-user.target`, kept the same live KWin PID 165, and
activated the private session D-Bus. It still did not launch plasmashell.
Console mirroring exposed the environment mismatch:

```text
Failed to activate service 'org.kde.KSplash': timed out
    (service_start_timeout=120000ms)
```

Fedora's global `/etc/xdg/startkderc` still set `systemdBoot=true`; the
per-user override previously installed by the recipe was not selected during
this bootstrap path. The NARF image starts Plasma in `dbus-run-session`
without a per-user systemd manager. The `org.kde.KSplash` D-Bus file runs
`plasma_waitforname`, expecting that absent manager to start
`plasma-ksplash.service`, so a cosmetic component consumed a full two-minute
activation timeout and left classic startup incomplete. The image recipe now
forces global `systemdBoot=false` and sets `ksplashrc` to
`Engine=none, Theme=None`. This removes the environment-only dependency from
the acceptance path; the prior ksplashqml #GP remains tracked as a separate
NARF compatibility bug rather than being declared fixed by disabling splash.

A second boot (`/tmp/narf-fedora-plasma-classic-nosplash-8g-20260802.trace`)
showed that Plasma still probes the `org.kde.KSplash` well-known name even in
classic mode with the global `Theme=None`. Because the Fedora D-Bus service
file remained installed, that probe still launched `plasma_waitforname` and
reintroduced the guaranteed 120-second timeout before KWin. The recipe now
also writes the narf user's `~/.config/ksplashrc` and removes
`org.kde.KSplash.service`, making the optional name fail immediately. This is
the same image-policy treatment already applied to the unusable
`org.freedesktop.systemd1` activator; it does not remove KWin or plasmashell.

That third run reached KWin PID 193 and completed portal activation, but never
execed plasmashell. KDE's upstream classic-start source identifies the exact
gate: `plasma_session` synchronously starts `kwin_wayland_wrapper --xwayland`
and waits for D-Bus name `org.kde.KWinWrapper` before starting kded, ksmserver,
or any phased autostart applications. NARF showed a live `kwin_wayland`
process, but the wrapper name never registered, so the startup sequence could
not reach plasmashell. A post-portal GDB snapshot
(`/tmp/narf-fedora-plasma-no-ksplash-gdb-20260802.txt`) found ordinary procfs
and epoll work, not a kernel lock or block-I/O wedge.

At the seven-minute probe timeout, startplasma and KWin shut down normally and
`graphical.target` subsequently reported success without `PLASMA-READY`. That
exposed two oracle-wiring defects: the probe's `Requires=` relationship could
couple its stop to the Plasma service, and a target Wants= symlink does not
make a failed oneshot a hard target failure. The recipe now gives the probe a
15-minute ceiling, uses `Wants=narf-plasma.service` to avoid teardown
propagation, and installs a `graphical.target` drop-in with an ordered
`Requires=narf-plasma-probe.service`. The next scoped trace must cover
`plasma_session`, `kwin_wayland_wrapper`, and `kwin_wayland` to find why the
wrapper name never appears.

The scoped 8-GiB/SMP2 trace is
`/tmp/narf-fedora-kwin-wrapper-syscall-trace-8g-20260802.trace`. It reached
`plasma_session` task 181, wrapper task 194, and live KWin PID 199. KWin's CPU
counter rose while it loaded libraries, scanned configuration/icons, brought
up Mesa/portals, then plateaued at 4748 while remaining live. `plasma_session`
and the wrapper remained in their expected rewound `ppoll` waits and no
`plasmashell` appeared. Two GDB samples independently showed (1) cold eager
`mmap` reads flowing through ext2 to 8-sector virtio submissions with the
other CPU waiting on the miss lock, and (2) after initialization, ordinary
scheduler/timer/console activity rather than an all-CPU kernel wedge.

The rootfs audit rules out a missing Plasma dependency: 643 Qt/QML/Mesa plugin
ELFs and the core executables have zero missing `DT_NEEDED` libraries; all 51
remaining D-Bus activation `Exec=` paths resolve; KDE themes, imports, fonts,
autostarts, portal helpers, machine-id, loader cache, and the runtime-directory
configuration are present. The packed clean ext2 image has about 2.5 GiB free.
`cpp` was the one real packaging gap caused by disabling weak dependencies;
it is now installed alongside `xrdb` in both clean and incremental recipes.

The exact remaining D-Bus chain is now source-confirmed. `plasma_session`
registers `org.kde.Startup`, launches the wrapper, then waits synchronously for
`org.kde.KWinWrapper`. The wrapper registers that name only after
`KUpdateLaunchEnvironmentJob` sees callbacks for every
`org.kde.Startup.updateLaunchEnv`,
`org.freedesktop.DBus.UpdateActivationEnvironment`, and
`org.freedesktop.systemd1.SetEnvironment` call. The job counts error replies as
completion. Image-local tests return the intentionally absent systemd1
`ServiceUnknown` and the D-Bus activation-environment success in about 8 ms,
so absence of systemd1 cannot inherently wedge this job. With KWin and the
wrapper live, the leading defect is an undelivered
`org.kde.Startup.updateLaunchEnv` reply/watcher callback while
`plasma_session` is inside nested `KJob::exec`, or a missed Qt D-Bus worker
wake. The next run should trace only `QDBusConnection` (and/or attach a
same-session `dbus-monitor`) to observe the method call, reply, and final
`RequestName` without the high-volume cold-loader trace.

### Timer-wheel cache: directly relevant to the epoll backstop

`time/src/timer_wheel.rs` changes the global wheel from scanning for the
minimum deadline to trusting the `NEXT_DEADLINE`/`NEXT_DEADLINE_VALID` cache in
`fire_due`, the IRQ rearm path, and the executor idle path. This is directly in
the epoll liveness chain because an I/O park registers its lost-wake retry for
about 10 ms in that wheel.

The current own-stack park handles a full 1024-slot wheel correctly: if
registration fails it clears the park state and returns without blocking, so
PID 1 busy-retries rather than losing its only backstop. The legacy poller also
self-wakes on registration failure. Wheel saturation by the desktop workload
is therefore a performance problem, not by itself a permanent-wedge
explanation in the current tree.

The cache's locked mutation cases preserve the intended minimum after each
operation: insert takes `min(old, new)`, removing or moving the cached minimum
recomputes under `WHEEL`, and every drain recomputes after its single pass.
Nevertheless, the fast paths now make cache correctness load-bearing. The
valid bit and deadline are separate atomics, and a reader can acquire an older
`valid=true` publication and then observe the older, later deadline while
another CPU inserts an earlier slot. That violates the required invariant
"stale may be earlier, never later" and lets `fire_due` or
`drain_due_to_deferred` return past an actually-due timer. Another tick or arm
normally bounds the delay, so it is not the best fit for the current locale
request, but it is still a wake regression. The max review therefore rejects
this pair for commit until it uses one atomic with a `u64::MAX` sentinel (or a
versioned/seqlock publication) and passes an SMP insert-earlier-vs-fire test.
The hang capture must also compare the cache with a locked scan of the actual
slots; testing only `occupied() > 0` is not enough. The nearby
`deferred_wake::MAX_PENDING` comment is stale as well: the pending depth is 64,
not the wheel's 1024 slots.

This change can also alter whether the heisenbug reproduces: removing a
1024-slot scan and its global-lock traffic changes SMP scheduling substantially.
Success after the cache patch is not proof that signalfd publication is fixed;
failure with `pending=1` and no epoll re-scan makes the wheel cache/rearm path a
first-class suspect.

### Ownership/metadata changes: indirect load and boot-progress effects

The ext2, VFS, overlayfs, and chmod/chown handler changes do not write signal,
epoll, task-waker, or process-exit state. They persist uid/gid/mode changes and
let systemd create service runtime directories with the correct ownership.
Their main relevance is that Fedora now advances farther and launches more
services, increasing concurrent tasks, epoll waiters, block I/O, and timer
slots. The synchronous syscall bridge (`poll_blocking` around async metadata
writes) can delay PID 1 while ext2 I/O completes, but it is bounded and is not
a missing `SIGCHLD` publication. Distinguish such a delay by checking whether
PID 1 is inside an fchmod/fchown/mkdir syscall rather than parked in epoll.

The associated ext2/VFS/ABI test changes and filesystem specification update
have no runtime effect beyond validating/documenting that metadata path.

### Fedora image service change: narrows the observed handshake

`verification/data/musl-demo/REGEN_fedora_kde_rootfs.sh` changes the Plasma
session unit from `Type=exec` to `Type=simple` and removes its 180-second start
timeout. This deliberately stops Plasma startup from depending on systemd's
exec-notification handshake. It can bypass a child/exec notification stall for
that unit, but it does not change PID 1's signalfd registration or general
`SIGCHLD` handling. If the boot advances only because of this change, localize
the failure to the exec handshake and its child lifecycle; if PID 1 still
hangs in epoll before or after that service, retain the general publication,
identity, and re-scan analysis below.

`on_child_exit` publishes the pending bit before both wake mechanisms. If the
I/O waiter is already registered, `readiness::notify(0)` removes and wakes it.
If notify races before waiter registration, the own-stack I/O park has a
roughly 10 ms timer-wheel backstop, and `own_stack_park` re-executes the
rewound epoll syscall after any I/O-wait wake. Thus the scan-to-registration
race can add a bounded delay but should not produce a permanent hang unless
the timer-wheel cache/rearm or executor re-poll also fails.

## What the signal-return hypothesis does and does not explain

`default_signal_delivery_restricted` selects
`pending & !signal_mask & restrict & !sigwait_reserved`. Consequently a
correctly blocked `SIGCHLD` remains pending for signalfd and cannot be consumed
by an ordinary or trace-generated return to userspace. systemd passes a null
temporary mask to `epoll_pwait2`, so NARF's epoll path does not replace the
manager's installed mask either.

The return-to-user path becomes causal only if the task identity or signal
mask is wrong. In that case the default action for unblocked `SIGCHLD` is
Ignore, so the syscall-return hook clears the pending bit. A previously
collected epoll event may then be followed by an empty signalfd read. NARF
currently returns `0` for an empty nonblocking signalfd rather than `EAGAIN`;
systemd logs this as `Truncated read from signal fd (0 bytes), ignoring!`.
That log distinguishes "epoll returned an event, then the signal disappeared"
from "epoll never returned the event".

Therefore trace-induced success or failure is not evidence by itself that a
return-to-user consumed `SIGCHLD`. It is evidence to compare the task IDs and
mask at publication, epoll readiness, delivery, and signalfd read.

## Leading permanent-hang candidates

### 1. Publisher/signalfd task mismatch

`PARENT_OF` stores the spawning task's `TaskId`, and `on_child_exit` publishes
`SIGCHLD` under that value. `SignalFdFile`, however, permanently records the
`TaskId` that created the signalfd. Those IDs agree for a single-threaded
parent such as the normal PID 1 setup, but they can differ when a non-leader
thread spawns a child while another thread owns/waits on the signalfd. Linux
models `SIGCHLD` as a process-directed signal; NARF's current tables are
per-task. In the mismatch case, epoll correctly polls the signalfd owner's
empty bitmap forever while the signal is pending on a sibling task.

This is the first invariant to check even for PID 1: record
`parent == signalfd.owner_task == epoll_wait task`. If all three agree, this
candidate is ruled out for that occurrence.

### 2. Exit publication never occurred

The epoll wake path cannot help if `on_child_exit` is not reached. It is a
process-exit observer and runs only on the thread group's `group_dead`
transition. A leaked live-thread count, a missing observer call, or an orphaned
`PARENT_OF` row produces neither the wait entry nor `SIGCHLD`. Correlate the
child's exit with `on_child_exit(child_pid, child_tid)` before changing epoll.

### 3. Wake occurred but no readiness re-scan ran

If publication and owner identity are correct, level-triggered
`SignalFdFile::poll_readiness` must return `EPOLLIN` on every scan until the
signal is drained. A permanent miss then means the parent was not re-executed
after `wake_signal`/`readiness::notify`, or both the targeted wake and 10 ms
backstop failed. The decisive state is whether the parent was present in
`SIGNAL_WAKERS` or `IO_WAKERS`, whether its outer wake flag became set, and
whether `epoll_wait_common` re-entered and called `collect_ready` afterward.
For this Fedora KDE branch, also capture wheel occupancy, cached next deadline,
the locked actual minimum deadline, arm-callback state, and last programmed
clockevent deadline. A due slot with a later/invalid cache directly explains a
missing 10 ms recovery scan.

## Confirmed defects adjacent to, but not sufficient for, PID 1's watch

### Child exit bypasses the signalfd edge-generation invariant

`raise_signal_pending` increments `SIGNAL_READABLE_GEN[task]` on an empty to
nonempty pending transition. `SignalFdFile::poll_edge_token` exposes that
generation so `EPOLLET` can preserve a drain/refill transition that happens
between epoll scans. `on_child_exit` directly ORs `SIGCHLD` into
`SIGNAL_PENDING` and never advances the generation. The existing
`smoke_userspace_signalfd_epoll_wakes_on_signal` test uses
`raise_signal_pending`, so it does not exercise the child-exit publisher and
cannot catch this omission.

This is a real lost edge for an `EPOLLET` signalfd after a hidden drain/refill,
but it is not the direct explanation for systemd's manager signalfd because
that source is level-triggered. The current per-task generation also advances
only when the entire pending bitmap was empty, not when a particular
signalfd's masked view changes from empty to nonempty; multiple masks or an
unrelated pending signal can therefore still lose or manufacture edges.

### Stop/continue SIGCHLD publication has no signalfd wake

`push_stopcont_report` also directly sets the parent's `SIGCHLD` bit, but it
only wakes `wait4`; it does not call `wake_signal`, advance the signalfd
generation, or notify I/O readiness. That can strand a signalfd epoll waiter
until its backstop. systemd installs `SA_NOCLDSTOP`, so a conforming
implementation should not generate these stop notifications for its manager;
this is another semantic gap rather than the ordinary child-exit explanation.

## Minimal non-perturbing trace to resolve the occurrence

Use a small lock-free flight record and dump it only after the hang is
detected. Avoid serial output, locks, or branch-heavy validation on every
epoll/syscall return; the observed behavior is timing-sensitive.

Record these rare transitions:

1. `sys_sigprocmask`: task, requested mask, installed mask; verify the
   `SIGCHLD` bit remains set.
2. `sys_signalfd`: creating task/owner, watched mask, returned fd.
3. `on_child_exit`: child pid/tid, resolved parent, pending before/after,
   parent mask, signal-readable generation, global readiness generation.
4. `wake_signal` and `wake_all_io_waiters`: target task and whether each table
   contained a waker.
5. `epoll_wait_common`: waiting task and, only when inspecting the watched
   signalfd, owner/mask/pending/readiness immediately before park and return.
6. Every mutation that clears `SIGCHLD`: clearing task, pending/mask before,
   and whether the caller is signal delivery or signalfd read.
7. At hang-dump time, not on every timer tick: wheel occupancy, cached
   valid/deadline, locked slot minimum, arm callback installed, last armed
   deadline, and current cycles.

The expected successful sequence is:

```text
parent == signalfd owner == epoll task
SIGCHLD pending = 1, SIGCHLD blocked = 1
publish -> wake (or <=10 ms backstop) -> epoll rescan -> EPOLLIN
syscall-return delivery sees deliverable SIGCHLD = 0
signalfd read returns 128 and then clears SIGCHLD
```

Interpret the first divergence:

- no `on_child_exit`: debug process-exit/group-dead accounting;
- different parent/owner/epoll task: fix process-directed signal ownership;
- pending cleared before signalfd read: debug mask/identity and return-to-user
  delivery (and look for systemd's truncated-read log);
- pending remains set but no second `collect_ready`: debug wake/backstop and
  executor re-poll; if an actual wheel slot is due but the cache is absent or
  later, debug the branch's timer cache first;
- `collect_ready` sees the owner's pending bit and mask but returns no event:
  the defect is inside epoll/signalfd readiness evaluation.

## Regression coverage needed before a fix is considered closed

- A real child-exit publisher test, not `raise_signal_pending`, with a blocked
  `SIGCHLD`, level-triggered signalfd, and exit injected in the
  scan-to-waiter-registration window. Assert epoll returns one event and the
  subsequent read returns 128 bytes.
- The same child-exit path under `EPOLLET`, including a drain/refill hidden
  between scans; this should expose the missing generation update today.
- A return-to-user test proving blocked `SIGCHLD` remains pending between the
  successful epoll return and signalfd read.
- A multithreaded-parent test where a non-leader thread creates the child and
  the leader-owned signalfd waits for process-directed `SIGCHLD`.
- A stop/continue test covering `SA_NOCLDSTOP` and signalfd wake semantics.
- An SMP timer-cache invariant test that interleaves register, refresh,
  cancel, `fire_due`, and deferred drain, asserting that after every completed
  mutation the cache is `None` iff the wheel is empty and otherwise is never
  later than the locked slot minimum. Include an epoll-style 10 ms backstop
  while other Fedora-scale sleepers churn the wheel.

The safest implementation direction is to funnel every pending-signal
publisher through one helper that atomically establishes the pending state and
its readiness transition, then performs signal and I/O wakes after the bit is
visible. Process-directed signals additionally need a thread-group-owned
pending/readiness identity rather than whichever `TaskId` happened to create
the signalfd or child.

## 2026-08-02 timer-wheel cache repair and Fedora replay

The first 8-GiB / four-vCPU replay after `948aa535` deliberately excluded the
unreviewed timer cache. It crossed the earlier remount/journald/tmpfiles freeze,
so it did not reproduce the all-CPU epoll/signalfd wedge, but
`systemd-udevd.service` repeatedly missed its startup notification timeout.
Host-side thread sampling showed all four QEMU vCPU threads near 93% CPU. The
guest remained active and continued retrying the service; this was a hot-path
performance collapse, not an idle epoll sleep. The capture is
`/tmp/narf-fedora-signal-tid-fix-smp4-8g-20260802.log`.

Without a cached minimum, every CPU's executor calls `fire_due` and scans all
1024 timer slots even when the next timer is in the future. On an SMP desktop
boot that also pounds the single global wheel lock. The original dirty cache
avoided the scan, but its independent `AtomicBool valid` and `AtomicU64
deadline` stores could be observed as a mixed snapshot and could therefore
publish a deadline later than an actually-due timer. That version was rejected
instead of being committed.

Commit `6e8c726d` (`time: cache wheel deadline coherently`) replaces that pair's
publication protocol with an even/odd sequence counter. A writer marks the
snapshot unstable before making an earlier deadline visible in the wheel,
publishes `(valid, deadline)`, then releases an even sequence value. Readers
retry across odd or changed sequence values. Removals may temporarily retain
an earlier conservative value, but no completed or concurrently observed
snapshot can be later than a newly-visible minimum. The fast paths in
`fire_due`, `drain_due_to_deferred`, and the IRQ rearm query can therefore stay
lock-free without skipping a due wake.

Validation for the isolated timer commit:

- `cargo fmt --all -- --check`: pass.
- `cargo check -p narf-time --tests`: pass.
- `cargo xtask test --arch=x86_64 --subsystem time/wheel`: 17 pass, 0 fail,
  0 skip, including a new register/refresh/cancel/expiry cache-minimum test and
  the committed 65-expiry deferred-overflow regression.
- The automatic x86_64 boot smoke following that suite exited cleanly with no
  panic markers.

Only `time/src/timer_wheel.rs` and `time/src/tests.rs` were included in
`6e8c726d`. These notes were excluded as required. The branch now has twelve
focused commits above its starting point. A new full Fedora replay, with all
remaining dirty boot-enabling changes plus the exact timer commit, is running
with 8192 MiB, four vCPUs, snapshot mode, and TCG multi-threading. Its capture
is `/tmp/narf-fedora-timer-cache-smp4-8g-20260802.log`. Do not call the boot
successful until the probe emits literal `PLASMA-READY` and the required
processes remain non-zombie for the configured stability window.

The replay reached `basic.target` and started `systemd-udevd.service` on its
first attempt, confirming that the cache removed the earlier udev startup
collapse. It then started `narf-plasma.service`. The session wrapper did not
appear until approximately probe 22, after which `startplasma-wayland` was PID
119. From probe 24 through probe 69 its `/proc` CPU count advanced only from
855 to 874 while `plasma_session`, `kwin_wayland`, `kcminit_startup`, `kded6`,
`ksmserver`, and `plasmashell` all remained absent. The process was therefore
parked rather than compute-bound. The run was stopped intentionally after more
than two minutes of no child-session progress; it did not emit
`PLASMA-READY`.

Two `avahi-daemon` tasks also faulted identically while writing the lower stack
guard address `0x7ffffffe0000` at RIP `0x409000360889`. That is a separate
reproducible ABI/stack-frontier clue and may explain other failed background
services, but Avahi is not a prerequisite of the explicitly independent Plasma
service. The immediate next run enables the `syscall-trace` feature with the
exact comm selector `trace_comm=startplasma-way$`; the last unmatched `SYS`
entry will identify the parked syscall without tracing unrelated boot tasks.

### Correction from scoped syscall trace and semcode callchain review

The scoped trace reached farther than the replay above: the same
`startplasma-wayland` leader eventually resumed and launched both
`plasma_session` and `kwin_wayland`. The earlier flat CPU counter therefore did
not establish a permanent process-wide hang. The probe has two observability
defects: `/proc` reports every non-zombie task as `R`, and its CPU counter covers
only the process leader, not the thread group. The leader had cloned a hidden
thread, parked in a private futex wait, and that worker renamed itself
`QDBusConnectionManager`; the comm-scoped trace stopped following it at the
rename. In the newer trace the futex later returns zero and startup advances.

The repeated trace pairs

```text
SYSC ... ppoll ... timeout=NULL
SYSR ... ppoll = 0 ... st=InvalidOp
```

are likewise not zero-length poll results returned to Plasma. Semcode and
source callchain analysis resolves the path as

```text
syscall dispatch
  -> sys_ppoll
  -> poll_common
  -> poll_scan
  -> own_stack_block
  -> own_stack_park
  -> park_should_block
  -> timer_wheel register/refresh + yield_current_stackful
```

On the no-readiness path, `poll_common` intentionally leaves the return status
at `InvalidOp`, rewinds RIP over the syscall instruction, registers the I/O
waker, and parks. A wake (or the bounded 10 ms lost-wake backstop) resumes the
kernel stack and re-executes the syscall for a fresh readiness scan. Thus the
trace prints an internal park/resume boundary; userspace does not observe the
shown zero. The `ppoll` callchain is not evidence of an immediate-return spin.

### Confirmed SysV startup-stack layout defect

The two identical Avahi faults are fully explained and are unrelated to a
lower stack guard. `0x7ffffffe0000` is the exclusive upper stack boundary.
Symbolization maps the fault to glibc `__memset_avx2_unaligned_erms`, called by
Avahi while clearing the old argv/environment area for its process title.
NARF's `init_sysv_stack` wrote argv strings top-down and then environment
strings top-down, placing `argv[0]` above the final environment string. Avahi's
Linux-valid calculation `last_env_end - argv[0]` consequently underflowed and
the first wide store crossed the upper boundary.

The userspace fix now lays strings in increasing logical order—argv entries,
then environment entries—inside one contiguous area. The existing stack-layout
test was extended with two argv and two environment entries, monotonic and
contiguous pointer assertions, and an Avahi-shaped positive bounded span.
Validation completed on 2026-08-02:

- `cargo fmt --all -- --check`: pass.
- `cargo check -p narf-userspace --tests`: pass.
- `cargo xtask test --arch=x86_64 --subsystem userspace`: 363 pass, 0 fail,
  0 skip; the automatic boot smoke also exited cleanly without panic markers.

This removes the deterministic Avahi crash and one source of desktop-service
instability, but the Fedora boot is still not accepted until the probe emits
literal `PLASMA-READY` and the required Plasma processes survive the stability
window.

The isolated fix is commit `c8231aa4` (`userspace: order initial stack strings
compatibly`). Only `userspace/src/process.rs` and
`userspace/src/tests/elf_loader.rs` were committed; this notes file and all
other branch changes were excluded.

### 8-GiB KVM acceptance replay after the stack fix

The full dirty boot candidate plus `c8231aa4` was replayed with 8192 MiB, four
vCPUs, KVM acceleration, and snapshot disks. The capture is
`/tmp/narf-fedora-kvm-smp4-8g-sysvfix-20260802.log`.

The run brought all four CPUs online, reported 8191 MiB usable, completed udev
on its first attempt, reached `basic.target`, and launched the independent
Plasma session. The former Avahi out-of-bounds `memset` page fault did not
recur, corroborating the isolated stack-layout regression. Avahi still failed
its service start for an as-yet-unresolved reason, so that service should not
be called fixed as a whole.

The startplasma leader's apparently flat interval again proved to be slow but
completing: at guest time about 300 seconds its Qt DBus handshake resumed,
`plasma_session` started, KWin claimed `org.kde.KWinWrapper`, and two
`kcminit_startup` processes appeared. KWin remained non-zombie through the end
of the 180-sample probe. This is additional direct evidence against a permanent
epoll/futex missed wake at that frontier.

The acceptance gate nevertheless failed correctly. `plasmashell`, `kded6`, and
`ksmserver` never appeared, so the run emitted `PLASMA-BLOCKED` and
`graphical.target` failed. The decisive later log is environmental/ABI-shaped:
Xwayland repeatedly reports `XKB: Failed to compile keymap`, while `xkbcomp`
reports `syntax error: line 1 of stdin` and `Errors encountered in stdin; not
compiled.` The image contains the XKB data and an earlier isolated check proved
that `xkbcomp` succeeds with a valid keymap on stdin. The current frontier is
therefore the Xwayland keymap producer / pipe / fork-dup2-exec path, followed by
portal and notification activation timeouts; it is not the corrected SysV
stack layout and is not evidence that `ppoll` returns spuriously.

No `PLASMA-READY` marker has been observed yet. The next diagnostic should
trace Xwayland's keymap-pipe write result and the child xkbcomp stdin read in
one run, while improving the probe to expose thread count and real park reason.

### Final syscall/epoll callchain audit and `epoll_pwait` wiring repair

The max-reasoning review initially appeared to find a `poll(2)` path that
parks with an internal zero return but without an I/O waiter, readiness
generation, or RIP rewind. That diagnosis selected the stale
`handlers/sys_poll.rs` implementation. `install_core_syscalls` installs
`Syscall::Poll` twice, and `SyscallTable::install` explicitly replaces an
existing slot; the later and therefore live registration is
`crate::poll::sys_poll`. Its actual blocking chain is:

```text
Syscall::Poll
  -> poll::sys_poll
  -> poll_common
  -> poll_scan / FileOps::poll_readiness_at
  -> net_io_wait + readiness-generation snapshot + persistent deadline
  -> RIP rewind
  -> own_stack_block / own_stack_park
  -> readiness::notify
  -> wake_io_waiters
  -> task Waker
  -> re-executed poll scan
```

The live `epoll_wait_common` path has the same required re-execution contract,
plus `epoll_wait_fd` and a passive post-registration readiness probe that
closes the level-triggered scan-to-register race without consuming an
`EPOLLET|EPOLLONESHOT` token. Therefore scoped trace records such as
`poll = 0 st=InvalidOp` and `ppoll = 0 st=InvalidOp` are internal park
sentinels, not successful zero returns observed by Qt or Plasma.

The audit did find one real syscall-table defect: `Syscall::EpollPwait` was
wired to `crate::epoll::sys_epoll_wait`, so the caller's temporary signal mask
was ignored. The working tree now routes it to
`crate::epoll::sys_epoll_pwait`. A new ABI regression supplies a bad non-null
signal-mask pointer; this distinguishes the correct pwait-aware wrapper, which
must inspect and reject it, from plain `epoll_wait`, which would ignore arg4
and arg5 and return zero on the empty instance.

Validation of the isolated wiring change on 2026-08-02:

- `cargo fmt --all -- --check`: pass.
- `cargo check -p narf-userspace --tests`: pass.
- `cargo clippy -p narf-userspace --tests -- -D warnings`: pass.
- `cargo xtask test --arch=x86_64 --subsystem syscall_abi/async`: 50 pass,
  0 fail, 0 skip, including
  `smoke_abi_async_epoll_pwait_validates_sigmask`; the automatic boot smoke
  exited cleanly without panic markers.

The isolated two-file repair is commit `d060a888` (`userspace: route
epoll_pwait through signal-mask handler`). These notes and every unrelated
dirty branch change were excluded from the commit as required.

### Max-review conclusion: current Plasma gate is the kcminit ready pipe

The initial Qt D-Bus wait eventually completed in both materially different
environments: 115.137 seconds under KVM with the PCID fallback and 107.326
seconds under TCG with PKS. The similar completion time and the live poll
callchain above rule out a permanent epoll/poll wake loss and argue strongly
against PKS/PCID state handling at that frontier. The missing `prctl` return in
one scoped trace was also a comm-filter artifact: `PR_SET_NAME` changes the
worker's name between independently filtered syscall entry and return records.

The synchronous gate now visible in the successful KVM replay is:

```text
plasma_session
  -> StartProcessJob("kcminit_startup")
  -> kcminit parent: read(ready[0], 1)
  -> kcminit child: QGuiApplication + runModules(phase 0)
  -> expected write(ready[1], 1)
  -> parent exit
  -> kded6 -> ksmserver -> Phase0 / plasmashell
```

Both kcminit tasks remain live from probe 88 through probe 180; the child's
one-byte phase-0 ready write never arrives. Xwayland's later XKB failure is
real but is downstream or parallel, not the direct synchronous gate. The next
low-perturbation diagnostic is to enable only
`QT_LOGGING_RULES=org.kde.kcminit.debug=true`: kcminit logs each module
immediately before calling its `kcminit()` entry, so the last module line
should identify the exact phase-0 plugin holding the ready pipe.

### kcminit ready-pipe callchain review

A max-reasoning semcode review and direct source audit followed the exact
kcminit parent/child handoff rather than treating every pipe user as one
generic path. The NARF side is:

```text
kcminit pipe()
  -> Syscall::Pipe
  -> handlers::sys_pipe
  -> pipe::pipe_pair (shared Arc<PipeShared>)
  -> fork
  -> fd::fork (independent tables, cloned Arc<FileOps> endpoints)

parent read(ready[0], 1)
  -> handlers::sys_read
  -> PipeRead::read
  -> empty + writer alive => read_should_block
  -> net_io_wait + readiness generation + finite backstop + RIP rewind
  -> own_stack_block / own_stack_park
  -> register_io_waiter

child write(ready[1], 1)
  -> handlers::sys_write
  -> PipeWrite::write
  -> enqueue one byte (64-KiB pipe cannot be full here)
  -> readiness::notify(0)
  -> wake_io_waiters / parent Waker
  -> re-executed parent read drains the byte
```

The endpoint lifetime is also coherent. Fork clones the endpoint `Arc`s;
closing the parent's writer and child's reader cannot mark either peer closed
while the child writer and parent reader still exist. If the child exits
without writing, dropping its last writer marks `writer_closed`, notifies, and
the parent returns EOF. A missed external notification is bounded by the raw
read's timer-wheel backstop. Consequently, both kcminit processes remaining
alive for many minutes is strong evidence that the child never reaches its
one-byte `sendReady()` write, not that NARF loses a completed write/wake.

The KDE-side synchronous chain runs phase-0 modules before `sendReady()`.
Those paths invoke `xrdb`/X11 work synchronously, which makes the X11/XKB
environment the leading current suspect and connects naturally to the later
Xwayland/xkbcomp failure. A pipe-kernel defect should only be asserted if a
scoped trace proves `write(ready[1], ..., 1) = 1` while the parent never
completes `read(ready[0], ..., 1)`.

The audit found two adjacent but non-causal pipe gaps: `pipe`/`pipe2` leave
their newly installed descriptors behind if copying the fd pair to userspace
fails, and `pipe2` neither rejects unsupported flags nor applies requested
`O_NONBLOCK`. Neither can explain kcminit's successful plain `pipe()` setup
and one-byte ready handoff.

The missing deterministic regression is the exact end-to-end scheduling case:
parent blocks first on a pipe read, forked child later writes one byte and
closes, parent wakes and returns that byte; a second variant has the child
close without writing and requires prompt EOF. Existing tests cover pipe
round-trips, forked fd-table cloning, dup/exec wiring, readiness, and EPIPE,
but not that full own-stack fork/park/wake sequence.

The Fedora acceptance image now includes only
`QT_LOGGING_RULES=org.kde.kcminit.debug=true` as a low-perturbation diagnostic
in `narf-plasma.service`; the image was rebuilt successfully. The first 8-GiB,
four-vCPU KVM replay of that image never reached Plasma: `systemd-udevd`
timed out repeatedly while QEMU consumed about 225% host CPU. The run was
stopped intentionally rather than misclassifying that active early-boot
regression as kcminit evidence. Its capture is
`/tmp/narf-fedora-kcminit-debug-kvm-8g-20260802.log`.

### Refined kcminit/X11 timeline and XKB corpus check

Re-reading the highest-water KVM capture corrects one overly broad inference.
The line `/usr/sbin/xrdb: Can't open display ''` occurs at guest time
301 seconds during the early `startplasma-wayland` environment setup, before
`plasma_session`, KWin, or kcminit exists. KWin subsequently publishes
`DISPLAY=:0`, `WAYLAND_DISPLAY=wayland-0`, and the generated `XAUTHORITY` path
at guest time 306 seconds; only after that does `kcminit_startup` appear.
Therefore the empty-DISPLAY xrdb invocation is a real acceptance-image setup
defect and explains avoidable early noise, but it is not by itself proof that
the later kcminit child is the process invoking xrdb with an empty display.

The image also does contain a complete XKB corpus. `/usr/share/X11/xkb` is a
valid symlink to the populated `/usr/share/xkeyboard-config-2` tree (about
3.9 MiB when dereferenced), and the prior `chdir` symlink fix lets the guest
enter it. More decisively, an offline chroot check piped a normal
`pc105`/`us` `xkb_keymap` through the image's own `/usr/bin/xkbcomp`; it
compiled successfully. The warnings were ordinary unsupported-high-keycode
and geometry warnings, not a parse failure. This rules out missing or
intrinsically corrupt XKB files as the cause of the live
`syntax error: line 1 of stdin` result.

The strongest remaining environment/data-path lead is now the live generated
keymap stream. Both kcminit processes are already present when KWin lazily
starts Xwayland; Xwayland then fails virtual-core-keyboard activation and the
compiler reports malformed stdin twice. A scoped trace must distinguish:

```text
kcminit phase-0 module blocks on X11 connection/request
  -> KWin lazily launches Xwayland
  -> keymap producer writes generated text through pipe/dup2/exec
  -> xkbcomp reads stdin
  -> parser rejects byte 0 / line 1
```

The next acceptance replay therefore uses 8192 MiB, four vCPUs, the
`syscall-trace` feature, and comm selectors for exact `kcminit_startup`,
`Xwayland`, and `xkbcomp`. The decisive evidence is the last unmatched kcminit
syscall plus the write/read byte counts around the keymap handoff. A pipe fix
is not justified unless the producer's successful write and the consumer's
read disagree; if they agree, the malformed bytes originate in KDE/XKB
generation or another Linux-ABI incompatibility above the pipe queue.

### Scoped kcminit trace: parent wake is not the reproduced failure

The 8-GiB/four-vCPU KVM trace is
`/tmp/narf-fedora-kcminit-xkb-syscall-kvm-8g-20260802.log`. It crossed the
intermittent udev frontier, reached `basic.target`, launched
`plasma_session`, registered `org.kde.KWinWrapper`, and created both kcminit
processes. The syscall filter matched exact `kcminit_startup` tasks 212 and
216. Serial tracing every dynamic-linker and Qt syscall was highly
perturbative, so the run is diagnostic evidence rather than an acceptance
performance sample.

The trace directly resolves the ready-pipe question in this reproduction:

```text
kcminit parent task 212:
  read(fd 7, one-byte buffer, 1)
  -> repeated internal value=0/status=InvalidOp park/retry boundaries

kcminit child task 216:
  continues dynamic linking, Qt plugin discovery, mmap/open/read activity
  -> ppoll(one fd, timeout=NULL)
  -> one iteration returns one ready fd
  -> recvmsg(fd 7, ...) returns 0 when KWin's Wayland connection closes
  -> never calls write(..., 1) for sendReady()
```

At guest time 341.584763, `org.kde.KWinWrapper` loses owner `:1.3`. The child
receives EOF on its connection, continues scanning Qt Wayland shell-integration
plugins briefly, and then both kcminit tasks receive SIGTERM 15 as
`startplasma-wayland` tears the failed compositor session down. There is no
successful child ready-byte write followed by a missed parent wake. The
parent's `read` is doing exactly what the KDE protocol requires while the
child remains pre-`sendReady()`.

This sample also shows a successful `ppoll` wake and subsequent `recvmsg`, so
it is affirmative live evidence that the relevant Qt event wait can receive a
readiness notification. The zero-byte `recvmsg` is real EOF caused by the
KWin/Wayland peer disappearing, not a spurious poll result. No Xwayland or
xkbcomp process was reached before compositor shutdown, so this run does not
capture the malformed keymap stream seen in the less-perturbed high-water
boot.

The low-perturbation next diagnostic is therefore an acceptance-image
`xkbcomp` wrapper that first saves stdin to a regular file and reports its
byte count, then invokes the real compiler with that exact saved input. Empty
input identifies the Xwayland producer/close path; nonempty malformed input
identifies generation/ABI behavior above the generic pipe queue; a valid saved
keymap that only failed on the original streaming path would finally justify
a pipe/stdio transport regression. The next replay should omit syscall tracing
so it can reach the later Xwayland frontier without serializing tens of
thousands of kcminit syscalls.

### KWin trace: the apparent Wayland wait ends in DRM-node permission failure

The low-perturbation xkbcomp-capture replay is
`/tmp/narf-fedora-xkbcomp-capture-kvm-8g-20260802.log`. With 8192 MiB and four
KVM vCPUs it reached KWin and both kcminit processes, but it never launched
kded, ksmserver, plasmashell, Xwayland, or xkbcomp before the 7m53s probe
deadline. KWin's leader CPU counter was essentially flat while kcminit made
slow progress. Consequently this sample produced no `XKBCOMP-CAPTURE` line;
the failure is earlier than the high-water Xwayland/XKB sample.

The prior kcminit syscall trace nevertheless identifies a precise Wayland
handshake boundary. Child task 216 loads `libwayland-client`, creates and
connects AF_UNIX fd 7 to `wayland-0`, and then:

```text
sendmsg(fd 7, 24 bytes, MSG_NOSIGNAL|MSG_DONTWAIT) = 24
ppoll(one fd, timeout = NULL)
  -> internal 0/InvalidOp park-retry boundaries
  -> no ordinary readable response
  -> eventually POLLIN/HUP and recvmsg(fd 7) = 0 after KWin exits
```

Thus kcminit is not waiting to send its request and its parent is not missing
a pipe-ready byte. It is waiting for KWin to answer a successfully queued
24-byte Wayland request. The NARF call chain is
`sys_socket_sendmsg -> SocketFile::dispatch_op -> dispatch_unix_stream ->
do_send -> RingBuf::write -> readiness::notify(0)`; the peer-close transition
does wake the same `ppoll`, proving the wait can receive a real readiness edge.

A KWin-only syscall-trace replay is
`/tmp/narf-fedora-kwin-wayland-syscall-kvm-8g-20260802.log`. It resolves why
the compositor never answers in this reproduction. KWin task 206 fails both
device opens with the bare `-1` compatibility sentinel:

```text
openat(AT_FDCWD, "/dev/dri/renderD128", O_RDWR|O_CLOEXEC) = -1
...
openat(AT_FDCWD, "/dev/dri/card0", O_RDWR|O_CLOEXEC) = -1
exit_group(1)
```

The nodes and their sysfs descriptions exist, and the DRM devfs/sysfs initcalls
completed. The current devfs metadata work intentionally starts both nodes at
the conservative devtmpfs policy `0600 root:root`, expecting udev to apply the
distribution policy. This acceptance image does not yet perform that DRM
uevent/udev permission handoff. KWin runs as uid 1000/group `video`, so DAC
rejects both opens before any compositor event loop can service kcminit's
request. The observed kcminit EOF is downstream of KWin's exit, not an epoll,
poll, pipe, or AF_UNIX missed wake.

The image recipe now applies Fedora-compatible policy before starting Plasma:
`root:video 0660` for `card0` and `0666` for `renderD128`. This intentionally
uses the current persistent devfs `set_owners`/`set_perms` implementation and
the corrected `fchownat`/`fchmodat2(AT_EMPTY_PATH)` syscall paths. The next
8-GiB replay must first prove both opens succeed; only then is a remaining
kcminit wait evidence about the Wayland response path.

### Max-review finding: `maxevents` consumed events that were never returned

The max-reasoning review independently confirmed the KWin/DRM diagnosis and
found a real epoll batching defect that can strand large event loops such as
systemd-udevd. `EpollInstance::collect_ready` scanned every ready interest,
acknowledged every provider, advanced every edge mask/token, claimed every
exclusive event, and disarmed every ready `EPOLLONESHOT` item. Only afterward
did `epoll_wait_common` truncate the vector to `maxevents`. With two ready
entries and `maxevents=1`, the second event was consumed in kernel state but
never copied to userspace.

The behavior was checked against the local Linux source at
`/usr/src/linux/fs/eventpoll.c::ep_send_events`. Linux breaks out before
touching the next ready-list item when `res >= maxevents`; it disables
`EPOLLONESHOT` only after successfully copying that event; and it moves a
delivered level-triggered item to the tail of `rdllist`. The NARF fix therefore
passes `maxevents` into `collect_ready`, stops before polling or mutating an
undeliverable entry, and records a scan cursor so continuously ready
level-triggered entries round-robin across successive short waits.

The public userspace spec now states that only returned entries may advance
edge tokens, acknowledge provider-local readiness, take an exclusive claim,
or disarm one-shot state, and that level-triggered overflow batches are
round-robin. Focused tests use two simultaneously readable eventfds with
`maxevents=1` to cover level-trigger fairness, undisclosed `EPOLLET` edge
preservation, and undisclosed `EPOLLONESHOT` preservation. A synthetic
readiness provider whose acknowledgement clears readiness separately proves
that the second provider is not acknowledged outside the first result batch.

Verification passed:

```text
cargo check -p narf-userspace --features linux-compat
cargo fmt --all -- --check
git diff --check
NARF_QEMU_MEM_MB=2048 cargo xtask test --arch=x86_64 --subsystem userspace
  -> 365 pass, 0 fail, 0 skip
  -> follow-on x86_64 boot-smoke clean exit, no panic markers
```

The first DRM-policy image replay before this fix never reached Plasma because
systemd-udevd repeatedly timed out and restarted. That run did not validate or
invalidate the DRM node policy. The lost-overflow-event bug is a credible
explanation for that intermittent early frontier, so the next 8192-MiB/four-
vCPU KVM acceptance replay must use the fixed epoll batching path and then
verify both DRM opens before interpreting the kcminit/Wayland state.

The epoll implementation, spec clarification, and regressions were committed
as `0b0f9dc5` (`userspace: preserve epoll overflow batches`). This commit does
not include this notes file or any of the still-independent DRM, syscall,
filesystem, ext2, or acceptance-image changes.

### Live DRM policy result and persistent-node coverage

The first post-epoll-fix KVM replay reached `systemd-udevd`,
`basic.target`, and the Plasma units without the earlier udev-trigger restart
loop. A privileged `ExecStartPre=+...` on the `User=narf` Plasma unit did not
execute reliably through the current systemd compatibility path, so the image
now applies device policy with a separately ordered root oneshot service.

The 8192-MiB/four-vCPU KVM run
`/tmp/narf-fedora-drm-root-service-kvm-8g-20260802.log` proves the policy and
metadata syscalls on the real Fedora image. The helper observed both nodes as
`0600 root:root`, then successfully changed `card0` to `0660 root:video`
(numeric gid 39) and `renderD128` to `0666`. Fresh later lookups retained the
changed metadata rather than recreating default-mode file objects.

The GPU regression coverage performs the same persistence check without the
image: for both `card0` and `renderD128`, it verifies the conservative initial
metadata, calls `set_owners` and `set_perms`, performs a fresh `DriDir` lookup,
and verifies the new owner/group/mode. The focused GPU e2e suite passes 37/37
with a clean follow-on boot smoke. The implementation, interface-spec update,
and tests are committed as `6d3daf6f` (`gpu: persist DRM devfs metadata`). The
commit excludes this notes file and the Fedora image policy helper.

This clears the earlier environmental reason for KWin's `openat` failures,
but it is not yet `PLASMA-READY`: the same live run reached
`startplasma-wayland` but did not reach `plasma_session`, KWin, or plasmashell
before it was stopped for a narrower trace.

### Current startplasma trace: leader waits after its worker renames

The scoped current-branch run is
`/tmp/narf-fedora-startplasma-stall-syscall-kvm-8g-20260802.log`. It uses 8192
MiB, four KVM vCPUs, the epoll batching fix, and the live-proven DRM policy.
Cold startup remains much too slow: the Plasma unit was marked started well
before its command reached userspace, and `startplasma-wayland` appeared only
around probe 98. Once present, however, it made sustained forward progress
through dynamic loading, locale/config discovery, and Qt initialization.

The last visible sequence is deterministic:

```text
leader: clone3(CLONE_THREAD-style Qt worker) = 252
worker: set_robust_list(...) = 0
worker: sigprocmask(...) = 0
leader: futex(child-ready word, FUTEX_WAIT, 0) [parks]
worker: prctl(PR_SET_NAME, "QDBusConnection...")
```

There is no return-side `prctl` line because the return logger reapplies the
comm filter after the successful rename. The worker therefore renames out of
the `startplasma-way` selector at exactly this point, while the leader remains
in normal Qt thread-start synchronization. The flat leader CPU counter is not
process-wide evidence of a kernel spin or lost epoll wake; NARF's `/proc`
reporting also labels all live non-zombie tasks `R` and does not expose the
hidden worker in the current probe. This run was stopped after probe 126
because the selected comm could no longer observe the only thread able to make
progress. The next diagnostic boundary must include both the leader and the
renamed `QDBusConnection` worker.

The existing call-chain review further shows that kcminit's later ready pipe
is not the present boundary. Its child runs synchronous phase-0 modules before
`sendReady()`; if it writes, `PipeWrite::write -> notify -> wake_io_waiters`
wakes the blocked parent, and if it exits first, dropping the final writer
returns EOF. Existing direct readiness tests do not cover that whole forked
park/wake lifecycle, so dedicated parent-blocks-first/child-writes and
child-exits/parent-EOF regression cases are being added before the pipe path is
declared fully covered.

Those pipe regressions are now implemented in the existing
`fork_pipe_smoke_x86_64` guest binary. The first case closes the parent's write
end, delays the child so the parent reaches an empty/open blocking `read(2)`,
then verifies that a one-byte child write and close wake the parent. The second
again parks the parent first, then lets the child exit without explicitly
closing or writing; exit-time fd teardown must wake the parent and return the
Linux EOF result (`read == 0`). An SMP2 snapshot guest printed `fork-ok`; the
transcript is `/tmp/narf-fork-pipe-regression-qemu-20260802.log`. The test-only
change is committed as `14fded01` (`verification: cover forked pipe wake
paths`).

The review also exposed a genuine but independent AF_UNIX EPOLLET gap. A
listener could accept its final queued endpoint and receive a new connection
before the next epoll scan. Both sampled masks are then `POLLIN`, so NARF's
mask-only edge memory suppressed the new connection even though Linux's socket
wake callback makes it a fresh edge. AF_UNIX listeners now advance a readable
generation on every accept-queue enqueue, and an end-to-end regression covers
`connect -> epoll_wait -> accept -> connect -> epoll_wait` without an
intervening empty scan. The userspace suite passes 366/366 and the follow-on
boot smoke exits cleanly. The implementation, spec update, and regression are
committed as `b0ea5d6b` (`userspace: preserve Unix listener epoll edges`).

This listener fix is deliberately not claimed as the current D-Bus AUTH root
cause. The max-reasoning `/data/systemd` review found that dbus-broker caches
the listener's EPOLLIN and accepts once per dispatch round until `accept4`
returns EAGAIN; it performs a zero-timeout epoll scan before the next accept.
A refill hidden between those scans remains covered by broker's cached event.
The current trace's stronger boundary is the accepted/connected system-bus
peer: the Qt worker connects successfully, sends the leading NUL and 24-byte
AUTH request, then waits for fd 5 to become readable. The ongoing review is
following that accepted peer through broker authentication and reply enqueue.

The max review's final source result narrows the next trace rather than
inventing a fix. In upstream dbus-broker, a successful listener accept
immediately constructs and dispatches the peer; the connection starts with
cached `EPOLLIN|EPOLLOUT`, so the broker should attempt to read the already
queued 25 authentication bytes without needing a fresh child-socket epoll
edge. Absence of the client reply therefore leaves four distinguishable
boundaries: the broker never reaches `accept4`, accepted-peer setup stops in a
credential `getsockopt`, `recvmsg` consumes AUTH but SASL/output never sends,
or `sendmsg` succeeds and the client's poll/readiness wake is lost.

The next replay must trace both exact comm names,
`dbus-broker$` and `QDBusConnection$`. The decisive syscall sequence is:

```text
no broker accept4 after client connect    -> listener/epoll wake path
accept4 followed only by getsockopt       -> peer credential setup
recvmsg = 25 with no sendmsg              -> broker SASL/output path
sendmsg > 0 with no client recvmsg        -> connected-ring poll/wake path
```

Relevant NARF boundaries are `socket.rs`'s AF_UNIX dispatch/accept/enqueue and
`poll_edge_token`, `compat.inc.rs::accept_common`, the socket recvmsg/sendmsg
handlers, and `epoll.rs::collect_ready`. The already-captured client-only trace
cannot choose among these server-side alternatives because the worker renames
out of the original filter and dbus-broker was not selected.

### Dual D-Bus trace: socket-activation listener lost `O_NONBLOCK`

The 8192-MiB/four-vCPU KVM dual-comm trace is
`/tmp/narf-fedora-dbus-auth-dual-kvm-8g-20260803.log`. It chooses the broker
side of the earlier decision tree conclusively. dbus-broker receives its
system-bus listener as fd 5 over its controller AF_UNIX channel via
`SCM_RIGHTS`, registers it with epoll, and successfully accepts clients. It
creates accepted fds 6 and 7, performs the peer-credential `getsockopt` calls,
registers the peers, consumes an initial 48-byte message, and sends output.
The listener and accepted-peer/AF_UNIX paths therefore work through the first
dispatch round.

The stall starts when broker drains the cached listener event. After the last
queued peer, it calls `accept4(5, ..., SOCK_NONBLOCK|SOCK_CLOEXEC)` again. The
flags passed to `accept4` apply to the newly accepted fd; Linux decides whether
the empty-listener call blocks from fd 5's existing open-file status. NARF
instead entered the blocking retry path forever:

```text
SYSC t=88 accept4 a0=0x5 a1=0x0 a2=0x0 a3=0x80800
SYSR t=88 accept4 = 0 st=InvalidOp
(repeated internally; no EAGAIN returned to dbus-broker)
```

This prevents `listener_dispatch()` from returning, so the broker never gets
back to its accepted peers to finish the Qt worker's AUTH exchange. It is not
an epoll delivery failure at this boundary: epoll delivered the listener event
and the broker accepted connections. `/data/systemd/src/core/socket.c` also
confirms that systemd creates activation sockets with
`SOCK_CLOEXEC|SOCK_NONBLOCK` before passing them to services.

The NARF cause was the ancillary representation. `parse_scm_rights_fds`
reduced every sender descriptor to only `Arc<dyn FileOps>`, and
`install_recv_ancillary` installed the receiver entry with
`status_flags: 0`. The same path correctly kept fd-slot `FD_CLOEXEC` separate
and applied it only for `MSG_CMSG_CLOEXEC`, but it discarded open-file status
such as `O_NONBLOCK`. `sys_socket` also populated only the fd-table copy and
did not initialize the socket object's shared nonblocking view.

Commit `c7fc0c22` (`userspace: preserve SCM_RIGHTS status flags`) carries the
file object plus current status flags through stream, seqpacket, and datagram
AF_UNIX ancillary queues, restores those flags in the receiver, and initializes
the shared socket nonblocking state at `socket(SOCK_NONBLOCK)` creation. The
public userspace spec now states the Linux-visible split: file status flags
survive `SCM_RIGHTS`; sender descriptor flags do not; receiver `FD_CLOEXEC`
comes from `MSG_CMSG_CLOEXEC`.

The regression changes the existing end-to-end SCM_RIGHTS ABI smoke to pass a
`socket(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK)` descriptor. It verifies both the
installed receiver `FdEntry.status_flags` and `fcntl(F_GETFL)`. Before the fix,
the focused suite was 94 pass / 1 fail with only
`smoke_abi_socket_scm_rights_fd_passing` reporting the lost flag. After the
fix, the focused socket ABI suite is 95/95, its follow-on boot smoke exits
cleanly, `cargo check -p narf-userspace --features linux-compat` passes,
`cargo fmt --all -- --check` passes, and `git diff --check` passes. The commit
contains only the implementation, public-interface text, and regression; this
notes file remains uncommitted.

This fixes the demonstrated Fedora D-Bus blocker, but a new uninstrumented
8-GiB acceptance replay is still required before claiming `PLASMA-READY`.
Generic shared-offset/open-file-description state remains broader pre-existing
fd-table work; this commit makes the socket-activation status semantics needed
by the observed path correct without claiming that unrelated gap is closed.

### Post-SCM_RIGHTS replay: KWin starts, Plasma shell still gated by kcminit

The uninstrumented 8192-MiB/four-vCPU KVM replay is
`/tmp/narf-fedora-scm-rights-fix-kvm-8g-20260803.log`. It confirms that the
socket-activation fix clears the earlier system-bus authentication boundary:
the machine reaches `multi-user.target` in roughly 40 seconds, the session bus
starts, `plasma_session` and `kwin_wayland` appear, KWin acquires its KDE D-Bus
names, and the KDE portal backend activates. That is materially farther than
the pre-fix run, but it is not a successful desktop boot. Two
`kcminit_startup` processes remain, while `kded6`, `ksmserver`, and
`plasmashell` never appear; no literal `PLASMA-READY` is printed.

The same run also exposes acceptance-image defects that are independent of
the demonstrated kernel wake fix. Xwayland cannot compile its generated XKB
keymap, the capture wrapper receives a zero-byte stdin stream, a Plasma
keyboard helper faults after an `mprotect` rejection, and the core
`xdg-desktop-portal` process later aborts after a double-free diagnostic. KWin
survives those failures. These are real remaining boot blockers or symptoms,
but none by itself proves that epoll failed to deliver an event.

The VM does have the requested memory and page-cache scale. NARF reports 8191
MiB usable RAM. Although `filesystem/src/page_cache.rs` has a conservative
128-MiB constructor default, boot immediately replaces it with a RAM-relative
capacity in `frame/src/bare_main.rs`: half of usable frames for the cache and
one thirty-second for the low watermark. On this run that is approximately a
4-GiB page-cache capacity and a 256-MiB low watermark, not a 128-MiB ceiling.
This is configuration arithmetic, not a measured cache-performance claim.

### kcminit/session-bus dual trace: AUTH and wake succeed

The targeted 8192-MiB/four-vCPU trace is
`/tmp/narf-fedora-kcminit-dbus-dual-kvm-8g-20260803.log`, with exact comm
filters for `kcminit_startup` and the session `dbus-daemon`. It disproves the
next generic epoll hypothesis. The daemon accepts kcminit's AF_UNIX peer,
receives the authentication bytes, sends the authentication response, and
answers `Hello`; the bus monitor records the reply and assigns `:1.5` to the
kcminit child. The child then discovers and loads the four installed plugin
DSOs:

```text
kcm_fonts_init.so
kcm_mouse_init.so
kcm_style_init.so
kcm_touchpad_init.so
```

Discovery is not proof that all four initialization entry points returned,
and `kcm_touchpad_init` is phase 1 rather than phase 0. The three phase-zero
modules are fonts, mouse, and style. Fonts/style can launch `xrdb`
synchronously and wait for it before kcminit calls `sendReady()`.

Thus the current boundary is not the system bus, session-bus AUTH, generic
AF_UNIX accept, or the already-covered parent-blocks-first pipe wake. The
session daemon then activates `org.freedesktop.portal.Desktop` on kcminit's
behalf. Portal startup spends successive long intervals probing unavailable
document/FUSE, GTK settings, PipeWire, and KWallet services; it eventually
reports successful activation, but kcminit still does not finish before the
240-second capture ends.

At the end of the capture the kcminit parent (internal task 154) repeatedly
re-enters `read(fd=7, len=1)` on its child-ready pipe and the child (internal
task 158) repeatedly re-enters `ppoll(nfds=4, timeout=NULL)`. The trace's
`value=0, st=InvalidOp` lines are not zero-byte Linux returns: both handlers
park with the syscall RIP rewound and intentionally leave the return slot
untouched; the trace logger prints that sentinel only after the own-stack
park resumes, immediately before the syscall instruction is re-executed.

The unexpectedly high re-entry rate is still important. `poll_common` parks
these waits on the global net-readiness generation, and any readiness notify
can wake unrelated waiters. During a busy Plasma/portal startup that produces
a thundering-herd-style sequence of harmless scans. It explains the noisy
trace and rising scheduling/CPU counters, but it does not yet explain why the
specific four-fd poll set never becomes ready. The next decisive capture must
decode those four pollfds and correlate the final requested D-Bus method with
the daemon's reply, without tracing every daemon epoll scan. No poll/pipe code
change is justified by this trace alone.

The max-reasoning callchain review identifies a stronger immediate lead in the
same log. After plugin discovery, task 158 locates `/usr/sbin/xrdb`, forks task
239, and that task execs `/usr/sbin/xrdb`; soon afterward task 158 settles into
the four-fd `ppoll`. There is no child `write(fd=8, len=1)` or close of that
ready-pipe writer anywhere in the capture. The parent therefore has not lost a
successfully queued ready byte: kcminit has not reached `sendReady()`. Combined
with Xwayland's XKB compile failure and the capture wrapper's zero-byte stdin,
the leading inference is that kcminit is synchronously waiting for xrdb while
xrdb waits on an Xwayland that failed before emitting a keymap. The next
lowest-perturbation replay should wrap/log xrdb start and exit, decode task
158's pollfds once, and mark the ready-pipe write/close once.

The review also confirms a broader Linux-semantics gap in NARF's wait design.
Linux poll registers on each source's own wait queue and the source wakes only
its subscribers. NARF currently puts ordinary poll, pipe, eventfd, and AF_UNIX
waiters in a global readiness registry; `notify(0)` wakes all of them, and
infinite waits retain a 10-ms backstop while blocking pipe reads also use a
1-ms deadline. This creates the observed thundering herd and can make a traced
desktop boot pathologically slow. Removing the timers alone would introduce a
scan-to-register lost-wake window. A correct follow-up needs source-specific
subscriptions, register-then-rescan validation, targeted write/close wakeups,
and isolation/race regressions. This work is real, but the current trace does
not show it losing kcminit's ready byte.

Current acceptance status: the kernel reaches Fedora PID 1, D-Bus,
`plasma_session`, and a live KWin compositor with 8 GiB, but it still does not
reach `plasmashell` or print `PLASMA-READY`.

### Max metadata review: ext2 and chmod/chown fixes validated

The max-reasoning metadata review found that the Fedora image's ownership and
mode setup was not yet trustworthy even though the first focused tests passed.
The material findings were: ext2 lookups held independent whole-inode caches
that could overwrite a prior handle's metadata; fresh ext2 mount-root handles
reported a synthetic `0555,0:0` sentinel; chmod truncated Linux's `07777` mode
surface to `0777`; chown retained setuid/setgid; lower-only overlay directories
did not copy up for metadata changes; legacy `fchmodat` read a nonexistent
flags argument; relative `*at` paths and final-symlink behavior differed from
Linux; and several persistence failures were returned as success.

The reviewed working change now:

- serializes ext2 whole-inode read/modify/write sequences across independent
  handles with an async-safe per-volume mutex and always starts mutations from
  the current disk inode;
- loads inode 2 during mount and refreshes its cached metadata after writes, so
  a fresh root handle observes persisted owner/mode changes;
- round-trips 32-bit ext2 UID/GID fields, all `07777` chmod bits, and clears
  file setuid/setgid on chown;
- copies lower-only overlay directories into the writable upper before an
  async mode/owner update;
- separates three-argument `fchmodat` from `fchmodat2`, validates flags,
  resolves relative paths through a directory fd, distinguishes `EBADF` from
  `ENOTDIR`, follows final symlinks by default, and implements the explicit
  no-follow and empty-path cases;
- propagates metadata errors and emits notifications only after successful
  persistence; mkdir performs best-effort namespace rollback if its post-create
  metadata initialization fails.

The regression coverage includes independent stale ext2 handles followed by
chmod and data writes, 32-bit owner encode/relookup, fresh inode-2 handles,
privilege-bit clearing, writable-overlay copy-up, real-dirfd `fchmodat`,
`fchmodat2`, and `fchownat`, invalid flags/dirfds, unused legacy-register
isolation, `uid_t(-1)` preservation, symlink follow versus no-follow, and
special mode bits. Validation after the review fixes:

```text
cargo fmt --all -- --check                                      PASS
cargo check (ext2 + filesystem + userspace/linux-compat)        PASS
cargo clippy (same packages/all targets, -D warnings)           PASS
x86_64 ext2+filesystem+syscall_abi                              1481 pass, 0 fail, 0 skip
x86_64 follow-on boot-smoke                                     clean exit
aarch64 ext2+filesystem+syscall_abi                             1465 pass, 0 fail, 4 skip
aarch64 follow-on boot-smoke                                    clean exit
```

This is filesystem/image-setup correctness, not evidence of a new epoll fix.
Credential-based chmod/chown authorization remains an explicitly documented
compatibility limitation; NARF's capability authority is still the security
boundary. The unrelated aligned ext2 full-block read optimization is being
kept out of the metadata commit. This notes file also remains uncommitted.

The validated metadata/interface/test set was committed as `18a7514c`
(`filesystem: persist Linux ownership and modes`).
The separately reviewed aligned-read hunk was committed as `2839456d`
(`ext2: read aligned blocks directly`); it was present in both successful
cross-architecture suites and boot smokes above.

### 2026-08-03 Wayland-only kcminit replay: kded starts, ksmserver does not

The next uninstrumented acceptance replay used the already-regenerated image
with the bounded `xrdb` wrapper, the `kcminit_startup` wrapper that clears
`DISPLAY` only for kcminit, and the expanded cold-path process probe:

```text
NARF_VBLK_IMG=/data/narf/target/narf-fedora-vblk.img \
NARF_QEMU_MEM_MB=8192 NARF_QEMU_SMP=4 \
XTASK_QEMU_ACCEL=kvm XTASK_QEMU_SNAPSHOT=1 \
XTASK_SYSTEMD_PID1_TIMEOUT_SECS=1200 \
cargo xtask systemd-pid1 --arch=x86_64 --display none
```

The capture is
`/tmp/narf-fedora-kcminit-wayland-guard-kvm-8g-20260803.log`. The run was
stopped deliberately after 3m34s once the new state had remained unchanged
for more than two minutes; it did not emit `PLASMA-READY`.

This replay crosses the prior kcminit phase-zero gate. The early startplasma
`xrdb` invocation exits with status 1 instead of waiting. Later the image logs
`KCMINIT-WAYLAND-GUARD clearing DISPLAY=:0`; the kcminit module `xrdb` also
exits with status 1. The initial two `kcminit_startup` processes then collapse
to one, the session bus publishes `org.kde.kcminit`, and `kded6` starts and
acquires `org.kde.kded6` at guest time 69.967 s. KWin remains present through
the end of the run. This is direct evidence that optional X11 initialization
was holding the earlier phase-zero ready handoff; neither the parent pipe wake
nor session-bus AUTH/Hello is the reproduced blocker.

The desktop is still incomplete. One `kcminit_startup` process remains alive
with four threads, `plasma_session` remains alive, and neither `ksmserver` nor
`plasmashell` ever appears. The delayed probe snapshot at sample 40 is not
sufficient to name that process's actual wait: NARF's `/proc/<pid>/syscall`
reports `running`, `/proc/<pid>/wchan` reports `0`, every fd symlink is exposed
only as the generic `anon_inode:[FileOps]`, and the process-level stat counter
does not identify which of its four threads is parked. Treating those fields
as a resolved syscall or source fd would be speculation.

Two independent failures remain visible but are not yet proved to gate the
classic session sequence. Xwayland again invokes xkbcomp twice with a captured
zero-byte stdin stream and fails virtual-core-keyboard activation. The core
portal reaches activation after its known FUSE `Bad address` failure and a
120-second KWallet timeout. A `plasma-keyboard` helper also faults after
`ExecutableAllocator::makeWritable` reports `EINVAL`. None of those events
causes KWin to exit in this sample.

Semcode confirms the relevant NARF wait chain as
`sys_ppoll -> poll_common -> poll_scan -> FileOps::poll_readiness_at`, followed
by `own_stack_block` when no requested fd is ready. The live implementation
registers one task in the global readiness registry and relies on a generation
check plus a bounded timer backstop. The local Linux reference
`/usr/src/linux/fs/select.c` instead runs `do_pollfd -> vfs_poll` with a
`poll_table`; each provider registers the task on its own wait queue before
`poll_schedule_timeout` sleeps, and the second scan disables further waiter
registration. This explains NARF's unrelated-wakeup/thundering-herd cost but
does not explain a lost completed ready-pipe byte in this run, because kcminit
has already crossed that handoff and kded is registered.

The next test-first boundary is the classic-session transition after
`org.kde.kded6`: identify whether `plasma_session` is waiting for a process
exit, a D-Bus name, or another child handshake. Coverage must exercise the
corresponding parent/child and wait primitive before any kernel change. The
current untested observability area is per-thread `/proc` state and stable fd
type/identity reporting; another process-level syscall trace would only repeat
the ambiguity above.

### 2026-08-03 Plasma-session debug replay: kded broadcast is on the wire

The follow-up replay regenerated the Fedora image with
`org.kde.plasma.session.debug=true` in the Plasma service's
`QT_LOGGING_RULES`, then ran:

```text
NARF_VBLK_IMG=/data/narf/target/narf-fedora-vblk.img \
NARF_QEMU_MEM_MB=8192 NARF_QEMU_SMP=4 \
XTASK_QEMU_ACCEL=kvm XTASK_QEMU_SNAPSHOT=1 \
XTASK_SYSTEMD_PID1_TIMEOUT_SECS=600 \
cargo xtask systemd-pid1 --arch=x86_64 --display none
```

The capture is
`/tmp/narf-fedora-plasma-session-debug-kvm-8g-20260803.log`. It was stopped
deliberately at a stable 2m11s plateau. At the final probe,
`plasma_session`, KWin, the phase-one kcminit endpoint, and kded6 were all
still alive; ksmserver and plasmashell had never appeared, and the run did not
emit `PLASMA-READY`.

This run narrows the transition beyond process-name sampling. The session bus
monitor records both of the relevant ownership broadcasts:

```text
65.396696 NameOwnerChanged("org.kde.kcminit", "", ":1.4")
72.572247 NameOwnerChanged("org.kde.kded6", "", ":1.5")
```

The first broadcast coincides with the initial two kcminit processes
collapsing to the intended phase-one endpoint. The second proves that kded6's
well-known name was published on the same bus that `plasma_session` uses. No
ksmserver process follows during the remaining capture. Exact Plasma 6.7.3
source sequences `kcminit_startup`, a `StartServiceJob` for kded6, and then a
`StartServiceJob` for ksmserver; the service job uses a
`QDBusServiceWatcher` to finish when the requested well-known name is
registered. Thus the old kcminit ready pipe is no longer the boundary, and a
failure to publish the kded name is ruled out.

The requested Plasma session debug category emitted no recognizable
application messages—not even the expected `Starting` records—although the
environment value is present in the captured activation traffic. That makes
this debug-category path an untested/ineffective observability surface, not
evidence that a particular callback did or did not run. The run also did not
isolate the exact `plasma_session` thread or fd because NARF's current
process-level `/proc` fields cannot do so.

Semcode's exact NARF readiness chain is
`sys_epoll_wait -> epoll_wait_common -> EpollInstance::collect_ready ->
poll_item_readiness -> FileOps::poll_readiness_at`; when no entry is ready the
handler publishes the park state and reaches `own_stack_block`. Linux's
reference path keeps level-triggered items on the ready list in
`/usr/src/linux/fs/eventpoll.c::ep_send_events`, while provider callbacks are
registered on the source wait queue by `ep_ptable_queue_proc`.

Two focused regressions now cover the D-Bus-shaped byte-stream cases:

- two separate AF_UNIX writes queue a method reply and broadcast, userspace
  consumes exactly the reply, and a second zero-timeout level-triggered
  `epoll_wait` must return the still-readable fd;
- one coalesced write is only partially consumed, and repeated epoll delivery
  continues until all unread bytes are drained.

Both new tests pass in the complete x86_64 `syscall_abi/socket` run:

```text
97 pass, 0 fail, 0 skip
follow-on x86_64 boot-smoke: clean exit
```

This rules out the simplest unread-data redelivery failure without changing
the implementation. The remaining untested kernel case is an event arriving
between the initial readiness scan and waiter registration in a real parked
task. NARF has an explicit post-registration `epoll_fd_has_ready` rescan, but
the syscall-level harness has no live task context and therefore cannot cover
that branch. A deterministic own-stack concurrency test is required before
attributing the Plasma boundary to it. In parallel, exact Plasma/Qt source
must establish whether `StartServiceJob` can remain pending even after its
monitoring connection observes the well-known name.

Exact Qt 6.10.3 source (the image contains `libQt6Core.so.6.10.3`) adds the
next part of the call chain. `QDBusConnectionPrivate::socketRead` dispatches
the bus message, `handleSignal` selects the service watch,
`activateSignal` posts a `QDBusCallDeliveryEvent` to the watcher object's
thread, and `QCoreApplication::postEvent` invokes that thread's event
dispatcher wakeup. For the GLib dispatcher used here,
`QEventDispatcherGlib::wakeUp` calls `g_main_context_wakeup`, whose Linux
wakeup source is an eventfd. This means a successful D-Bus socket wake alone
does not prove the `StartServiceJob::emitResult` callback reached
`plasma_session`'s main thread.

That cross-thread bridge was previously under-covered: the existing eventfd
smoke only wrote and read the counter in one thread. It now retains that basic
check and adds 64 SMP rounds in which the main pthread is pinned to CPU 0, a
worker pthread is pinned to CPU 1, and the worker writes a shared eventfd while
the main thread blocks indefinitely. Even rounds use `epoll_wait(-1)` and odd
rounds use `ppoll(..., timeout=NULL)`, covering both the Qt socket-notifier and
GLib main-loop wait shapes plus the own-stack scan/register race. The focused
live result is:

```text
NARF_QEMU_SMP=2 XTASK_QEMU_NO_BALLOON=1 \
cargo xtask run-interactive --arch=x86_64 \
  --cmd /bin/eventfd_smoke --expect eventfd-ok
PASS: 64 cross-CPU pthread wake rounds, eventfd-ok
```

Thus queued AF_UNIX bytes, a later AF_UNIX readiness transition, and the
cross-thread eventfd wake bridge all have deterministic passing coverage. The
remaining distinction is inside the real Qt connection: whether the kded
`NameOwnerChanged` matches the watcher and is posted at all. The captured
`plasma_session` connection (`:1.2`) also receives
`org.freedesktop.DBus.Error.MatchRuleNotFound` for request serial 9 after the
temporary KWin watcher finishes. Exact Qt shows this can be a watcher
`RemoveMatch`; it is a lead, not yet proof that the persistent kded match was
absent. A plasma_session-only `QDBUS_DEBUG=1` replay can expose add/remove
rules and signal dispatch without returning to broad syscall tracing.

### 2026-08-03 QDBUS_DEBUG replay: no usable Qt records and an earlier plateau

The next Fedora image wrapped only `/usr/bin/plasma_session`, exported
`QDBUS_DEBUG=1`, and then executed the original binary under the temporary
name `/usr/bin/plasma_session.narf-real`. It used the same 8-GiB/KVM command
as the preceding replay. The capture is
`/tmp/narf-fedora-plasma-qdbus-debug-kvm-8g-20260803.log`; it was stopped
deliberately after 2m50s, once the state had remained unchanged for more than
two minutes. It did not emit `PLASMA-READY`.

The wrapper itself is confirmed by the early record
`PLASMA-SESSION-QDBUS-DEBUG starting pid=123`, but no Qt qdbus diagnostic
record follows. In particular, the log contains no match-rule installation,
removal, signal dispatch, or internal QDBus message even while the external
session-bus monitor is active. Fedora's Qt build therefore does not expose
this proposed diagnostic surface in the current environment. Absence of that
output cannot be used to infer that a watcher match or callback was absent.

This run is also more perturbing than the two normal-image replays. KWin stays
alive, but both initial `kcminit_startup` processes remain through the final
probe, `org.kde.kded6` is never acquired, and neither ksmserver nor
plasmashell appears. Repeated portal activation calls eventually time out.
The probe's `session=[none]` field is an observer artifact: its exact-comm
lookup no longer matches the renamed `plasma_session.narf-real`; the active
wrapper/real process still owns the session connection visible as `:1.2`.
The earlier kcminit plateau is real, but this one replay cannot distinguish a
timing perturbation from an effect of the wrapper or debug environment.

Consequently, `QDBUS_DEBUG` is rejected as an effective test here and the
temporary wrapper should be removed before the next image. The untested area
remains delivery above the already-covered AF_UNIX and eventfd primitives:
does an independent GLib D-Bus name waiter observe `org.kde.kded6` when the
normal session reaches that name? A bounded `gdbus wait --session
org.kde.kded6` check exercises that boundary without adding syscall tracing
or modifying Plasma's process identity.

### 2026-08-03 independent GLib name-wait test: kded delivery succeeds

After removing the QDBUS_DEBUG wrapper and restoring the package
`plasma_session` binary, the next image started an independent
`gdbus wait --session org.kde.kded6` before `startplasma-wayland`. The capture
is `/tmp/narf-fedora-plasma-gdbus-wait-kvm-8g-20260803.log`; it used the same
8-GiB/SMP4/KVM command as the preceding replays and was stopped deliberately
at a stable 2m25s plateau. It did not emit `PLASMA-READY`.

This is a focused integration test rather than a syscall trace. The waiter
first connects as `:1.1`, confirms that `org.kde.kded6` has no owner, installs
its GLib D-Bus watch, and parks before Plasma begins. The normal startup then
crosses kcminit phase zero. The external monitor records:

```text
79.411385 NameOwnerChanged("org.kde.kded6", "", ":1.13")
PLASMA-GDBUS-WAIT kded observed
```

The success marker immediately follows the ownership broadcast. Thus an
independent GLib main context can consume the exact well-known-name transition
that Plasma's `QDBusServiceWatcher` needs. Together with the passing AF_UNIX
level-redelivery and cross-CPU eventfd/epoll/ppoll regressions, this covers the
kernel socket-readiness, park/wake, Qt/GLib-style cross-thread wake, and GLib
D-Bus match/delivery layers. The earlier `MatchRuleNotFound` lead is not a
generic lost bus signal.

The state remains unchanged from probes 20 through 43: `plasma_session`, KWin,
the phase-one kcminit endpoint, and kded6 are alive; neither ksmserver nor
plasmashell appears. The independently observed name does not make Plasma's
`StartServiceJob` complete. A `plasma-keyboard` helper still hits its separate
`mprotect`/userspace fault and portal/KWallet activation still times out, but
neither event stops KWin or removes the kded owner in this sample.

The remaining untested area is now above GLib and specific to the in-process
Qt/Plasma state machine: whether the `QDBusServiceWatcher` retains the kded
match, whether `activateSignal` posts its delivery event to the intended
thread, whether that queued event is dispatched, and whether the receiving
`StartServiceJob` is still alive and connected. Exact-source tests or an
acceptance-image workaround at that boundary are preferable to more kernel
tracing, because every lower wait primitive in the observed call chain now
has direct passing coverage.

### 2026-08-03 QDBus match-lifecycle replay: persistent kded rule is installed

The follow-up image expanded the existing session-bus monitor to include
`AddMatch` and `RemoveMatch` calls, preserving the independent GLib waiter.
The capture is `/tmp/narf-fedora-plasma-dbus-match-kvm-8g-20260803.log`; the
same 8-GiB/SMP4/KVM run was stopped at a stable 2m9s plateau and did not emit
`PLASMA-READY`.

Exact Plasma 6.7.3 constructs its kded and ksmserver `StartServiceJob` objects
after the synchronous KWin-wrapper job completes. Exact Qt 6.10.3 implements
each `QDBusServiceWatcher` through `watchService -> connectSignal`, which sends
a `NameOwnerChanged` match restricted to the service and an empty old owner.
The live protocol records match that source path on Plasma's connection
`:1.3`:

```text
42.541850 AddMatch ... arg0='org.kde.kded6',arg1=''
43.053070 AddMatch ... arg0='org.kde.ksmserver',arg1=''
89.527952 NameOwnerChanged("org.kde.kded6", "", ":1.14")
PLASMA-GDBUS-WAIT kded observed
```

There is no `RemoveMatch` for either Plasma rule before the broadcast or
through the final probe. The previously suspicious
`org.freedesktop.DBus.Error.MatchRuleNotFound` at reply serial 9 is now fully
identified: connection `:1.3` had just removed the completed KWin-wrapper
rule, then attempted to remove Qt's internal rule for
`arg0='org.freedesktop.DBus'`. It is unrelated to the still-live kded watcher.

The process state stays at Plasma session, KWin, phase-one kcminit, and kded6
through probe 41; ksmserver and plasmashell remain absent. This rules out the
two leading match-lifecycle hypotheses: the kded rule was neither omitted nor
removed with the temporary KWin watcher. The remaining untested Qt boundary
is narrower: the matching bus message must traverse
`QDBusConnectionPrivate::handleSignal -> activateSignal`, post its
`QDBusCallDeliveryEvent`, and have Plasma's main thread dispatch that event to
`StartServiceJob::emitResult`. A focused Qt watcher executable already shipped
in the image is preferable for the next test if available; otherwise the
acceptance image can bypass only this proven Qt callback gate using the
independent GLib name waiter.

### 2026-08-03 isolated Qt watcher test: QDBusServiceWatcher succeeds

The next image added Fedora's shipped `plasma_waitforname` beside the GLib
waiter. This executable is built from the same Plasma 6.7.3 tree and uses the
same Qt 6.10.3 `QDBusServiceWatcher`: it installs a registration watch, enters
a minimal `QCoreApplication` event loop, and exits from its `serviceRegistered`
slot. The capture is
`/tmp/narf-fedora-plasma-qt-wait-kvm-8g-20260803.log`; the usual
8-GiB/SMP4/KVM run was stopped at a stable 2m3s plateau and did not emit
`PLASMA-READY`.

Both independent implementations complete on the one kded transition:

```text
81.132243 NameOwnerChanged("org.kde.kded6", "", owner)
PLASMA-GDBUS-WAIT kded observed
PLASMA-QT-WAIT kded observed
```

The Qt waiter's connection then issues the expected kded `RemoveMatch` while
exiting. Plasma session, KWin, phase-one kcminit, and kded6 remain stable
through probe 34; the original `StartServiceJob` still does not start
ksmserver, and plasmashell remains absent.

This passing focused test clears the untested generic Qt steps named by the
previous replay: Qt receives a matched `NameOwnerChanged`, posts/delivers the
watcher's notification, runs a Qt main event loop, invokes a connected slot,
and exits normally on NARF. The live distinction is now the receiving object
and continuation in `plasma_session`: `QDBusServiceWatcher::serviceRegistered`
is connected directly to inherited `StartServiceJob::emitResult`, whose
`KJob::finished` connection must start the already-constructed ksmserver job.

Without a locally rebuildable Fedora Plasma/Frameworks development stack, the
next test-first step is a narrowly scoped acceptance supervisor: wait for kded
through the proven Qt helper, launch `ksmserver`, wait for its well-known name,
then launch `plasmashell`. Marker lines around each action will distinguish
process-start failure from the next service-registration gate. This bypasses
only the proven broken classic-session continuation and leaves the lower
kernel/Qt paths unchanged.

### 2026-08-03 classic-session supervisor replay: ksmserver exits early

The first acceptance image with the scoped supervisor used the usual
8-GiB/SMP4/KVM command. Its capture is
`/tmp/narf-fedora-plasma-classic-supervisor-kvm-8g-20260803.log`; it was
stopped at a stable 1m59s plateau and did not emit `PLASMA-READY`.

The supervisor successfully resumes execution exactly where Plasma's original
job remains pending:

```text
86.757353 NameOwnerChanged("org.kde.kded6", "", ":1.15")
PLASMA-GDBUS-WAIT kded observed
PLASMA-CLASSIC-SUPERVISOR kded observed; launching ksmserver
PLASMA-CLASSIC-SUPERVISOR ksmserver pid=117
```

Probe 23 sees that same ksmserver PID alive, proving that the executable was
found and started with the live Plasma session environment. Probe 24 and every
later sample show `ksm=[none]`. No `org.kde.ksmserver` ownership broadcast is
emitted, so the supervisor correctly remains at its bounded name waiter and
does not launch plasmashell. KWin, kded6, phase-one kcminit, and plasma_session
remain alive throughout.

This advances the boot boundary beyond kded and converts the next failure into
a concrete early-process-exit case. The log contains no ksmserver diagnostic
or fatal-fault record. The current supervisor observes only the D-Bus name, so
the child's exit code/signal is an untested area. The next test must wait for
both the child and the name watcher and report whichever completes first; if
the child wins, record its exact wait status before changing ksmserver's
environment or dependencies.

### 2026-08-03 ksmserver status replay: early exit is SIGABRT

The supervisor now races the ksmserver child against the exact Qt name waiter
using Bash `wait -n -p`. The capture is
`/tmp/narf-fedora-ksm-exit-status-kvm-8g-20260803.log`; the normal
8-GiB/SMP4/KVM replay was stopped at a stable 1m42s plateau and did not emit
`PLASMA-READY`.

The reproduced sequence is:

```text
PLASMA-CLASSIC-SUPERVISOR kded observed; launching ksmserver
PLASMA-CLASSIC-SUPERVISOR ksmserver pid=112
PLASMA-PROBE 23 ... ksm=[pid=112 state=R cpu=109] plasma=[none]
PLASMA-CLASSIC-SUPERVISOR ksmserver exited before name status=134
PLASMA-PROBE 24 ... ksm=[none] plasma=[none]
```

Shell status 134 is 128 plus signal 6 (`SIGABRT`). The child is therefore
successfully executed and then deliberately aborts before registering
`org.kde.ksmserver`; it is not a missing executable, ordinary exit, or missed
name notification. NARF emits no fatal-fault record for this process, and the
application writes no useful diagnostic before termination. The surrounding
KWin, kded6, kcminit, and plasma_session processes remain alive.

The newly uncovered area is ksmserver's early abort path and startup
assumptions. Exact Plasma source should be checked for assertions/fatal exits
before adding any trace. A narrow environment/argument test can then decide
whether the supervisor omitted state normally supplied by `StartServiceJob`,
or whether ksmserver is independently blocked by an incomplete compatibility
surface. Plasmashell remains deliberately untested in this run because the
supervisor does not cross an unacquired ksmserver gate.

Exact Plasma 6.7.3 source makes the prerequisite explicit. In
`ksmserver/main.cpp`, ksmserver unconditionally saves the incoming platform,
sets `QT_QPA_PLATFORM=xcb`, constructs `QGuiApplication`, and calls
`ConnectionNumber` on the native X11 display before constructing
`KSMServer`. Only the later `KSMServer` constructor creates ICE sockets and
the D-Bus object. This image's Xwayland is independently known to fail its
generated-keymap compile and virtual-core-keyboard activation. Ksmserver's
pre-registration abort is therefore consistent with its forced-XCB startup
running against that incomplete Xwayland, not with another missed D-Bus wake.

The next focused acceptance test should keep the ksmserver attempt and exact
status marker, then treat status 134 as an unavailable optional X11 session
manager and launch native-Wayland `plasmashell` directly. The existing probe's
10-second same-PID oracle will determine whether that is sufficient to boot a
stable Plasma desktop. Other ksm failures must remain hard failures so the
workaround cannot hide a new regression.
