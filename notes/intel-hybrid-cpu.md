# Intel hybrid-CPU topology

Date: 2026-05-25. Post-Renoir bring-up. First Intel-specific work
for Alder Lake / Raptor Lake / Meteor Lake (12th gen+) silicon.

## What landed

Read-only per-CPU `cpu_type` registry, populated from CPUID leaf
`0x1A` EAX[31:24]:

- `narf_lib::percpu::CpuType` — enum `Unknown` (0x00) / `Atom`
  (0x20, E-core) / `Core` (0x40, P-core). Wire encoding pinned to
  Linux's `X86_CPU_TYPE_*` defines so a drift can't silently
  mis-classify.
- `narf_lib::percpu::set_cpu_type(id, ty)` / `cpu_type(id)` /
  `count_cpu_type(ty)` — flat `[AtomicU8; MAX_CPUS]` registry.
- `narf_arch::x86_64::cpuid::read_hybrid_cpu_type()` — per-CPU
  helper. Deliberately not in `Features::probe()`: the probe is a
  BSP-only snapshot, but core type is per-LP and must be read from
  each CPU's bring-up path.
- `Features::hybrid` (leaf 7 sub 0 EDX:15) — capability gate.
- BSP populates slot 0 in `frame::bare_main`; each AP populates
  its own slot in `frame::x86_64::smp::_ap_start_rust`,
  immediately after `set_current_cpu` and before `mark_online`.
- Boot-log line `cpu-topology: BSP=Core, N P-core(s) + M E-core(s)`
  emitted post-SMP-bring-up.

## What stays correct on non-Intel-hybrid silicon

AMD parts (incl. Renoir 4700U + Phoenix HawkPoint1 bring-up
targets), pre-Alder-Lake Intel, and QEMU TCG all leave leaf 0x1A
undefined / zero. That decodes to `CpuType::Unknown`, which is the
right answer for uniform-core silicon. QEMU `-display none` boot
reports `BSP=Unknown, 0 P-core(s) + 0 E-core(s)` — expected.

## What's left

- `narf_scheduler::Affinity` already has a `CpuSet`-shaped
  `allowed` field. To support "P-cores only" placement, the
  ergonomic shape is `Affinity::p_cores_only()` /
  `Affinity::e_cores_only()` constructors that build the mask
  from `count_cpu_type` at task-spawn time. **Not implementing
  in this pass** — scheduler integration (affinity-hinted
  dispatch, biasing latency-sensitive tasks toward P-cores) is
  the follow-up.
- Hot-unplug + cpu_type slot teardown — `mark_offline` clears the
  online bit but leaves the type slot populated. Fine today
  because no caller treats the slot independently of the online
  bitmap; revisit when hot-unplug lands.

## Reference

Linux `arch/x86/kernel/cpu/intel.c::intel_get_cpu_type`,
exposed as `get_this_hybrid_cpu_type()`.
`arch/x86/include/asm/cpu.h::X86_CPU_TYPE_INTEL_{ATOM,CORE}`.
