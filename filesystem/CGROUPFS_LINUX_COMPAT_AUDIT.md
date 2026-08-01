# Cgroupfs Linux compatibility audit

Audit scope: NARF's cgroup-v2 unified hierarchy, core control files,
controller registration and delegation, membership hooks, cgroup namespaces,
procfs projections, and the pids, misc, memory, CPU, cpuset, I/O, and PSI
surfaces. Cgroup-v1 is intentionally out of scope.

The implementation was compared against the local Linux tree at
`/usr/src/linux`, commit `9bd577abc6fcf9c07995705220487f743e074de0`
(`sched_ext-for-6.17-rc2-fixes-46192-g9bd577abc6fc-dirty`). The NARF audit
started from `fff02aeeff6511bae44c22e9dd0c11efeb7c4f88`.

## Method

The audit followed both the VFS surface and the task/accounting paths:

1. Linux `kernel/cgroup/cgroup.c` and
   `Documentation/admin-guide/cgroup-v2.rst` supplied the core file set,
   cftype placement, metadata, delegation, threaded-tree, namespace, freezer,
   and kill contracts.
2. Linux `kernel/cgroup/{pids,misc,cpuset}.c`, `kernel/sched/core.c`,
   `mm/memcontrol.c`, and `block/{blk-cgroup,blk-throttle}.c` supplied the
   controller file sets, parsers, accounting, and enforcement semantics.
3. Semcode call-chain analysis at the base commit traced `attach_by_path` into
   `place`, `place` into controller attach/detach hooks, `store_core` into
   subtree/freeze/kill mutations, `fork_inherit` into membership propagation,
   and `register_builtin_controllers` into the controller registry. This
   identified the shared core seams where root state, delegation rules,
   namespace rendering, and file visibility must be fixed rather than patched
   independently in each controller.
4. Host Linux cgroup2 metadata was sampled to confirm that kernfs attributes
   report zero `st_size` and stable inode identities with read/write modes
   determined by the cftype callbacks.

## Implemented compatibility

| Surface | Linux contract | NARF result |
|---|---|---|
| Hierarchy | One cgroup2 tree with stable directory identity | `Cgroup` nodes retain stable inode IDs and shared tree state across lookups. |
| Attribute metadata | Kernfs attributes have stable identities, zero `st_size`, and callback-derived modes | Core, controller, and PSI files use stable non-zero inode IDs, size zero, and 0444/0644/0200 modes. |
| Readdir | Sync and async enumeration expose the same live files | `enumerate_async` returns the same snapshot and visibility filtering as `enumerate`. |
| Core file placement | `cgroup.type`, events, freeze, kill, and local stat are absent on root; limit/stat files follow their cftype flags | Root and non-root core arrays and controller-file filters match these placement rules. |
| Root controller state | Every registered controller has root css state independently of delegation | Root state is reconciled with the registry, allowing hierarchical counters and root statistical files without exposing root limit knobs. |
| Delegation | Top-down availability, no internal processes, atomic writes, and no removal while a child delegates | `cgroup.subtree_control` validates before mutation, uses last-token-wins ordering, checks processes and threads, and returns busy for dependent children. |
| Limits on tree shape | `max` or a non-negative signed-int bound | `cgroup.max.depth` and `.descendants` reject malformed and out-of-range values. |
| Namespaces | Paths are relative to the reader's cgroup namespace root; visible siblings use `..` | `/proc/<pid>/cgroup` projection computes the lowest common ancestor and emits relative components. |
| Membership | Process placement is exclusive and inherited across fork | The reverse PID index moves a task atomically through controller prechecks/hooks; fork and clone hooks inherit membership. |
| Freeze/kill | Non-root control files use Linux value syntax; kill is invalid for a threaded cgroup | Freezer state/events and recursive kill are wired; threaded kill is rejected. |
| Threaded transition | A populated/domain-controller cgroup cannot become threaded | The writable transition validates population and domain-only controllers and promotes the parent to `domain threaded`. |
| Local statistics | Current Linux exposes `cgroup.stat.local` and `cpu.stat.local` | Both files are present at the correct levels; unsupported freezer/throttle duration counters report honest zeroes. |
| PIDs | current, peak, max, hierarchical events, and local events | The complete file set is visible; limits veto placement and counters/peaks update across active ancestors. |
| Misc | current, peak, max, root capacity, events, and local events enumerate registered resources | The complete file set and root placement are present, including zero/max rows for registered resources. |
| CPU parser | Weight/nice, quota/period, burst, and idle values obey Linux ranges | Writes validate complete input atomically; weight and nice reach scheduler priority, while quota remains reporting-only. |
| I/O parser/accounting | Default weight and per-device max records have strict syntax; statistics are hierarchical | Invalid prefixes and empty limit records are rejected; accounted block submits update `io.stat`. |
| Cpuset v2 | Requested/effective CPU and memory masks; no v1 `memory_migrate` file | CPU affinity and future memory placement receive effective masks. The v1-only file was removed. |
| PSI feature selection | Linux exposes cgroup PSI only when PSI is configured and enabled | `cgroup-psi` gates the switch and all three pressure files; the base `cgroup` feature exposes none. `cgroup-all` opts in. |

## Remaining differences

These gaps are explicit; this audit does not claim full Linux cgroup2
conformance.

### High priority

1. **Threaded cgroups.** `cgroup.threads` still uses process-level membership.
   NARF does not model independent thread placement, propagate
   `domain invalid` through a threaded subtree, or enforce the complete set of
   threaded-controller constraints.
2. **CPU bandwidth enforcement.** `cpu.max` and `cpu.max.burst` parse and
   round-trip, but the cooperative scheduler has no CFS-style quota/throttle
   seam. Throttling counters therefore remain zero.
3. **I/O limit enforcement.** `io.max` and `io.latency` retain policy, but the
   block scheduler has no token-bucket or latency-controller path. I/O
   accounting is real; throttling is not.
4. **PSI accounting and triggers.** When `cgroup-psi` is enabled, files render
   the Linux wire shape with zero values. Stall accounting, writable trigger
   registration, poll wakeups, and per-open trigger lifetime are absent.
5. **Cpuset descendant updates.** A local CPU/memory-mask write updates current
   members, but a later parent narrowing does not recompute already-created
   descendant states. Partition-root and isolated-CPU scheduling semantics are
   also incomplete.

### Medium priority

1. **Event hierarchy.** `pids.events.local` and `misc.events.local` exist, but
   local versus descendant aggregation and kernfs poll notifications are not
   fully distinguished. Misc resources also lack a charging provider, so
   usage, peak, and event values remain zero.
2. **Core statistics and lifecycle.** Subsystem/dying-subsystem rows,
   asynchronous dying-cgroup retention, and real frozen-duration accounting
   are absent.
3. **Memory controller breadth.** The existing controller does not implement
   every Linux memory/swap/zswap/NUMA statistic and reclaim policy. Memory
   accounting work is intentionally left to the concurrent memory-accounting
   branch; this audit does not modify `cgroupfs/memory.rs`.
4. **Delegation security.** Linux ownership rules, delegation boundary
   containment, user-namespace permission checks, LSM hooks, release-agent
   legacy behavior, and BPF cgroup program attachment are outside the current
   VFS/controller model.
5. **Mount and namespace breadth.** The unified initial hierarchy works, but
   named/v1 hierarchies, all cgroup2 mount options, namespace-aware mount
   ownership, and complete `/proc/cgroups` bookkeeping are not implemented.

## Regression coverage

Kernel smokes cover core root/non-root placement, stable kernfs metadata,
sync/async readdir agreement, ordered subtree-control writes, child-delegation
dependencies, namespace-relative sibling paths, populated threaded-transition
rejection, threaded kill rejection, PSI feature absence/presence, strict CPU
and I/O parsing, cpuset v2 file shape, registered misc resource rendering, and
root controller-file placement. Existing smokes continue to cover membership,
fork inheritance, limits, freeze/events polling, recursive kill, controller
accounting, and procfs projections.

The complete repository merge gates remain authoritative; a focused cgroupfs
smoke run is not a substitute for both-architecture CI.
