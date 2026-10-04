# init — Staged Initcall Registry

`narf-init` is the kernel's initialization-ordering mechanism. It
plays the role Linux fills with its `*_initcall` family, but without
the ELF-section machinery that backs that scheme — no per-stage
linker sections, no `__initcall_start_N` boundary symbols, and no
`do_initcalls` walker over them. Instead, subsystems and drivers
register a function pointer tagged with a `Stage`, and the kernel
runs each stage in order, invoking every function registered under it
exactly once.

The staging hierarchy mirrors Linux's ordering intuition. Earlier
stages cover primitives the rest of the kernel assumes are already
live — arch-required setup before the heap exists, then core
services (RCU, scheduler, interrupt dispatch), then post-core
structures, per-CPU bring-up, per-subsystem one-time setup,
filesystem registration, driver probes, and finally late glue such as
splash and boot-summary work. Ordinary drivers default to the device
stage. The staging is policy rather than a hard guarantee: an early
initcall that touches the heap is still a bug. The contract the
registry does uphold is temporal — when a given stage runs, every
initcall in all prior stages has already returned.

Failure handling is deliberately soft. Initcalls report success, a
"not present" result for absent features or devices (a silent skip
that is counted but not treated as a failure), or a non-fatal error
that is logged through an optional hook before the kernel moves on to
the next call. This resilience is the whole point of the registry: it
is meant for subsystems and drivers the kernel must survive losing.
Fatal, must-succeed bring-up — enabling paging, early console
init, bringing the frame allocator online — stays outside the
registry entirely, sequenced by hand in the boot path. The registry
also tracks per-stage statistics and supports an optional wall-time
budget per initcall and a verbose per-call trace, both aids for
diagnosing slow or misbehaving boot steps.

As one of the lowest crates in the stack, `narf-init` is depended on
by nearly every subsystem that needs to schedule setup work, which is
why it carries only a handful of foundational dependencies. It is
`no_std` and arch-neutral.
