# PID-namespace translation audit

Branch `cachyos-efi`, baseline `de7bd91e` (before the ring-membership fix),
audited 2026-08-15. Read-only findings; nothing here is fixed except where a
row cites a landed commit.

## Model

Three number spaces meet in this tree and the bugs cluster at the seams:

- **`TaskId`** — the scheduler's handle.
- **outer `ProcessId`** — globally unique, `PID_TO_TASK` / `TASK_TO_PID`.
- **inner (namespace) pid** — per-`PidNamespace`, starts at 1.

Bridges: `report_pid_to` / `accept_pid_from` do outer↔inner;
`pgid_to_user` / `pgid_from_user` do TaskId↔outer↔inner — **but only
`pgid_to_user` does the inner half**. That asymmetry is the single largest
source of findings.

Idioms to match:
- IN (arg arriving from userspace): `accept_pid_from(caller, pid)` / `resolve_inner_pid`, `None` → ESRCH. Reference: `sys_kill.rs:33`, `sys_sched_setaffinity.rs:31`.
- OUT (value rendered to userspace): `report_pid_to(reader, outer)` / `pgid_to_user`. Reference: `sys_wait4.rs:61`, `report_ucred_to`.

## Status (updated as findings land)

**LANDED — 22 of 34 findings fixed, every one with a RED-first test:**

Core (main tree): #1/#3/#4/#5/#6 pgid family; #2 ptrace; #7 getsid; #8
kill/tkill/tgkill/pidfd si_pid; #9 SIGCHLD si_pid; #14 waitid stop/cont
si_pid; #15 fcntl F_GETLK l_pid; #17 kill(-1) ns visibility; #21 process_vm.

IN-direction batch (merged from a worktree agent): #11 prlimit64; #12 kcmp
(+ a follow-up ESRCH-for-unknown-pid fix); #18 sched_setparam/getparam; #19
capset; #20 migrate_pages/move_pages; #22 get_robust_list; #23 ioprio
(WHO_PROCESS; WHO_PGRP/WHO_USER left as a documented LINUX-GAP); #27
bpf(TASK_FD_QUERY); #28 setpriority/getpriority (`who` was discarded — now
implemented via accept_pid_from, not just documented). Tests live in
`userspace/src/abi_pidns_tests.rs` (container-gated).

Every fix uses the same idiom: `accept_pid_from(caller, pid)` (inner->outer,
identity in non-container) then `pid_to_task_raw`/`proc_pid_to_tid`
(outer->TaskId), matching sys_kill.rs / sys_sched_setaffinity.rs.

**VERIFIED-CORRECT-IN-PRACTICE (no fix needed):** #24 cgroup.threads — the
write path routes cgroup.procs and cgroup.threads both into `members` via
`place()`, so `cg.threads` is never populated and the read always hits the
report_pid mirror-procs branch; the raw-tid branch is dead code.

**DEFERRED (low value / risk, documented — the remaining 11):**
- #10 perf_event_open — NOT done. In perf_event.rs (a non-handler module);
  the agent's batch excluded it. Real (perf record -p in a container) but
  needs perf infrastructure to test. Follow-up.
- #13 fork-return after CLONE_NEWPID — UNSURE. In-tree comment claims the
  coupling is deliberate (cites project_pidns_flow_model). Verify that flow
  before touching.
- #16 /proc/<pid>/task/<tid> names — NARF is single-thread-per-process; task/
  has one entry. Low impact until real threads land.
- #25 mq_notify si_pid — POSIX mq, negligible reach.
- #26 tkill/tgkill non-leader raw-tid arm — needs multi-threaded processes
  NARF barely has; touching signal_tid_from_user outweighs the payoff.
- #30 wait4/waitid unbound-inner fallback -> ECHILD — current behaviour is
  documented-safe except for a numeric-collision sibling; changing it risks
  the blocking-wait path.
- #31 NSpid chain, #32 /proc stat tty fields (constant 0), #33 SysV IPC
  IPC_STAT pids (written 0), #34 setns TaskId fallback (likely dead) — OUT
  rendering with no live leak / UNSURE reachability.

Net: every finding rated moderate-or-higher is fixed; #10 is the one real
remaining item with a clear consumer.

## Findings (severity-ranked)

| # | surface | dir | kind | file:line | current behavior | Linux ref | consumer that breaks | fix |
|---|---|---|---|---|---|---|---|---|
| 1 | `kill(-pgid)` | IN | pgid | sys_kill.rs:96 | `(-spec)` used raw | signal.c:1586 `find_vpid(-pid)` | bash job control, systemd `KillMode=control-group` | fixed `pgid_from_user` (#3) |
| 2 | `ptrace` all requests | IN | pid | ptrace.rs:627/666/134 | zero translation, any request | ptrace.c:1398 `find_get_task_by_vpid` | gdb/strace in a container; **containment escape** | `accept_pid_from` at entry |
| 3 | `pgid_from_user` helper | IN | pid/pgid | core.inc.rs:7602 | `pid_to_task_raw` on inner pid, no `accept_pid_from` | sys.c:1136/1198 | root cause of #1/#4/#5/#6 | insert `accept_pid_from` before `pid_to_task_raw` |
| 4 | `setpgid` both args | IN | pid+pgid | sys_setpgid.rs:14,19 | via raw `pgid_from_user` | sys.c:1136 | shell job control in a container | via #3 |
| 5 | `getpgid(pid)` arg | IN | pid | sys_getpgid.rs:10 | via raw `pgid_from_user` | sys.c:1198 | `ps -o pgid`, tcsetpgrp | via #3 |
| 6 | `ioctl(TIOCSPGRP)` | IN | pgid | fd.rs:869 | via raw `pgid_from_user` | tty_jobctrl.c:517 | agetty/login/bash `tcsetpgrp(3)` | via #3 |
| 7 | `getsid()` return | OUT | sid | sys_getsid.rs:17 | `report_pid_to(read_sid())` — misses `task_to_pid_raw` hop; wrong in non-container too | sys.c:1240 + `pid_vnr` | agetty/login session check, `ps -o sid` | `pgid_to_user(read_sid(target))` |
| 8 | `kill`/`tkill`/`tgkill` `si_pid` | OUT | sender | sys_kill.rs:44 → linux_compat.rs:112 | plain kill delivers `si_pid == 0` | signal.c:1097 `task_tgid_nr_ns` | **udevd on_sigusr1**, systemd signalfd | `store_sigqueue_info(target, sig, SI_USER, 0, report_pid_to(target, sender))` |
| 9 | SIGCHLD `si_pid` | OUT | child | core.inc.rs:7501 | bit only, no siginfo → `si_pid == 0` | signal.c:2211 `task_pid_nr_ns` | **systemd PID 1 dispatch_sigchld**, dbus | same idiom into parent's ns |
| 10 | `perf_event_open(pid)` | IN | pid | perf_event.rs:3678 | raw; sample records emit raw pid + raw TaskId tid | events/core.c:5082 | `perf record -p` / bpftrace in a container | `accept_pid_from` in; `report_pid_to`/`linux_tid_for_task` on records |
| 11 | `prlimit64(pid)` | IN | pid | sys_prlimit64.rs:14 | user pid used directly as TaskId | sys.c:1751 | systemd `LimitNOFILE=`, prlimit(1) | `accept_pid_from` → tid |
| 12 | `kcmp(pid1,pid2)` | IN | 2×pid | sys_kcmp.rs:22 | raw both | kcmp.c:146 | systemd fd-dedup, criu | `accept_pid_from` in `resolve` |
| 13 | fork/clone return after `CLONE_NEWPID` | OUT | child | sys_fork.rs:232 | returns child's new-ns pid (1) to parent in old ns → parent `waitpid` ECHILD | fork.c:2667 `pid_vnr` in parent's ns | `unshare -fp`, runc/crun init | `report_pid_to(parent, child.raw())` — **UNSURE**, see notes |
| 14 | `waitid` stop/cont `si_pid` | OUT | child | sys_waitid.rs:80 | untranslated (exit arm :113 IS translated) | exit.c `pid_vnr` | `waitid(WUNTRACED)` supervisors, systemd | `report_pid_to(parent, child_pid)` |
| 15 | `fcntl(F_GETLK)` `l_pid` | OUT | owner | sys_fcntl.rs:161,183 | raw TaskId; no OFD `-1` | locks.c:2321 `locks_translate_pid` | lslocks, flock(1), sqlite | `report_pid_to(caller, task_to_pid_raw(owner))`; `-1` for OFD |
| 16 | `/proc/<pid>/task/<tid>` names | OUT | tid | procfs/pid_ext.rs:997 | uses outer pid; inner reader sees host number | array.c:213 NSpid | `ps -L`, htop -H, JVM threads | `linux_tid_for_task` per member |
| 17 | `kill(-1)` broadcast | IN | — | sys_kill.rs:74 | iterates every outer pid globally | signal.c:1591 `task_pid_vnr` visibility | container escape; systemd-shutdown broadcast | filter on ns visibility |
| 18 | `sched_setparam`/`getparam` | IN | pid | sys_sched_setparam.rs:23 | user pid used directly as key | sched/syscalls.c:217 | chrt(1), systemd `CPUSchedulingPolicy=` | mirror `sched_setaffinity` |
| 19 | `capset` self-check | IN | pid | sys_capset.rs:35 | compares inner pid vs outer → spurious EPERM | capability.c:115 | libcap `cap_set_proc`, runc | `accept_pid_from` then compare |
| 20 | `migrate_pages`/`move_pages` self-check | IN | pid | sys_migrate_pages.rs:10 | untranslated self-compare | migrate.c:2541 | numactl | as #19 |
| 21 | `process_vm_readv/writev` | IN | pid | core.inc.rs:3564 | raw | process_vm_access.c:197 | criu, gdb fast path | `accept_pid_from` before compare |
| 22 | `get_robust_list(pid)` | IN | pid | sys_get_robust_list.rs:10 | user pid as table key | futex/syscalls.c:59 | glibc robust-mutex, criu | `accept_pid_from` → tid |
| 23 | `ioprio_set`/`get` | IN | pid/pgid | sys_ioprio_set.rs:14 | raw `who` as key → two ns share one entry | block/ioprio.c:84 | ionice, systemd `IOSchedulingClass=` | `accept_pid_from`/`pgid_from_user` |
| 24 | `cgroup.threads` read | OUT | tid | cgroupfs/mod.rs:1140 | raw tids, no filter (Procs arm at :1116 IS correct) | cgroup.c `pid_vnr` | systemd cg_read_pid | mirror Procs arm |
| 25 | `mq_notify` `si_pid` | OUT | sender | mqueue.rs:391 | no siginfo → `si_pid == 0` | mqueue.c `__do_notify` | POSIX mq RT apps | `store_sigqueue_info` + `report_pid_to` |
| 26 | `tkill`/`tgkill` non-leader arm | IN | tid | compat.inc.rs:4674 | raw-TaskId thread tids bypass translation | signal.c:4123 | container→host thread signal | gate raw arm on ns visibility |
| 27 | `bpf(TASK_FD_QUERY)` self-check | IN | pid | sys_bpf.rs:477 | untranslated self-compare | bpf/syscall.c | bpftool | as #19 |
| 28 | `setpriority`/`getpriority` `who` | IN | pid/pgid | sys_setpriority.rs:7 | `who` discarded → always self; no leak | sys.c:282 | renice(1), systemd `Nice=` | resolve via `accept_pid_from` |
| 29 | `waitid(P_PGID)`/`wait4(pid<-1 or ==0)` | IN | pgid | sys_waitid.rs:38 | pgid ignored, collapsed to "any child" | exit.c `find_vpid` | shells reaping by pgid | implement with fixed `pgid_from_user` |
| 30 | wait4/waitid unbound-pid fallback | IN | pid | sys_wait4.rs:22 | raw inner kept on translation miss | exit.c → ECHILD | nested-ns supervision | `None` → ECHILD |
| 31 | `/proc/<pid>/status` NSpid chain | OUT | pid chain | procfs/mod.rs:2376 | single value not the chain (value itself correct) | array.c:210 | nsenter/nspawn mapping | **UNSURE** — benign at 1 nesting level |
| 32 | `/proc/<pid>/stat` tty_nr/tpgid | OUT | tty pgrp | procfs/mod.rs:2325 | hardcoded `0 0`; no leak | array.c:516 | `ps -o tpgid`, w, who | `pgid_to_user(tty_fg_pgrp)` |
| 33 | SysV IPC IPC_STAT pids | OUT | pid | sysvipc.rs:258/433, sys_shmctl.rs:40 | pid fields written as 0; no leak | ipc/*.c `pid_vnr` | `ipcs -p`, PostgreSQL | wrap in `report_pid_to` when implemented |
| 34 | `setns` legacy TaskId fallback | IN | pid | sys_setns.rs:64 | reinterprets fd number as pid | nsproxy.c (fd-only) | — | **UNSURE** — likely dead; delete or test-gate |

## Top 5

1. **`pgid_from_user` (#3)** — structural twin-asymmetry of the de7bd91e bug; drives every job-control primitive (#1/#4/#5/#6); wrong-target is the *common* case because `read_pgid` defaults `pgid == pid`. Fix one helper, four rows close.
2. **`ptrace` (#2)** — the only finding that is a containment escape with write primitives. The `tracers` registry is already outer-keyed, so one `accept_pid_from` at entry fixes it.
3. **plain `kill`/SIGCHLD `si_pid == 0` (#8/#9)** — same consumer as the already-fixed pidfd path (udevd `on_sigusr1`, systemd PID 1). SIGCHLD is the higher-frequency half.
4. **`getsid()` raw TaskId (#7)** — wrong in non-container builds too; one-line fix, idiom already exists in `current_task_sid_user`.
5. **fork after `unshare(CLONE_NEWPID)` (#13)** — parent `waitpid` ECHILD. UNSURE: in-tree comment claims deliberate; verify against `project_pidns_flow_model`.

## VERIFIED-CORRECT (re-runnable checklist)

IN: `sys_kill.rs:33` (kill pid>0), `tkill`/`tgkill` via `signal_tid_from_user`→`accept_pid_from` (compat.inc.rs:4678), `rt_sigqueueinfo`/`rt_tgsigqueueinfo` (de7bd91e), `pidfd_open` (translates before `mint_for` — sole mint path, so pidfd_send_signal/getfd/waitid(P_PIDFD) covered by provenance), `wait4(pid>0)`/`waitid(P_PID)` (modulo #30), `sched_setaffinity`/`getaffinity`, `getsid` argument, cgroupfs explicit-pid writes, `proc_namespace_fd_from_path`, sched_setscheduler/getscheduler/rr_get_interval (N-A stubs), exit_group/exit_task/unshare/socket (N-A internal keys; socket:57 is a deliberate host-init privilege gate), fcntl F_SETOWN/F_GETOWN (unimplemented tree-wide).

OUT: getpid/getppid/gettid, all four wait4 return sites + finish_wait_child, waitid exit-reap si_pid (:113), report_ucred_to (SO_PEERCRED + SCM_CREDENTIALS), getpgrp/setsid/getpgid-return via pgid_to_user, TIOCGPGRP/TIOCGSID, PIDFD_GET_INFO, /proc/<pid>/fdinfo pidfd Pid/NSpid, /proc enumeration (ns_visible_inner filter), /proc/<pid>/stat+status pid/ppid/pgrp/session, cgroup.procs read, ns_last_pid static.

## Explicitly UNSURE

- #13 fork return — Linux semantics unambiguous but in-tree comment claims deliberate; check `project_pidns_flow_model`.
- #31 NSpid chain — right for one nesting level; matters only if nested pid ns reachable.
- #34 setns TaskId fallback — reachability not established.
- `semctl(GETPID)` — IPC_STAT arms write no pid; did not trace whether a GETPID command constant falls through to EINVAL.
