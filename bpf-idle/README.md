# bpf-idle — BPF Idle Governor

`narf-bpf-idle` lets a verified BPF program decide how deeply an idle CPU
sleeps. It is the first real consumer of NARF's BPF `struct_ops` mechanism: it
binds a runtime-supplied, verifier-checked BPF program set to `narf-power`'s
pluggable idle-state selector, so the policy that chooses a CPU C-state is no
longer a fixed native implementation but a program that can be loaded, swapped,
and reasoned about at runtime. When the power subsystem needs to pick an idle
state — given a latency budget and a predicted idle duration — it can dispatch
that decision into BPF.

The crate exists as a seam between two subsystems that are built to know
nothing about each other. On one side, `narf-power` defines its own
hand-written idle-governor contract and dispatches through an Arc-backed trait
object, unable to tell a BPF-driven governor from a native one. On the other,
`narf-bpf-structops` supplies the `struct_ops!` machinery that turns a trait
declaration into the full apparatus for loading and running a program set: the
governor trait, a target-specific typed builder, the adapter that executes the
bound program, an owning link, and a descriptor registered into the kernel's
`struct_ops` table. This crate writes the small bridge that maps the generated
adapter onto `power`'s native contract and the committer that moves it into
`power`'s live governor slot. It is the only place the two meet.

The design embodies the capability and verification discipline of NARF's BPF.
Installation is gated by a capability whose kind the `struct_ops` layer proves
before the committer runs, and `power` re-checks the capability when it accepts
the governor. Each program is verified for this method's scalar context, empty
kfunc allowlist, atomic context, and bounded fuel. Dropping the generation-
tagged owning link detaches it and restores the native governor. Nothing is
installed at boot; the force-link anchor only keeps the descriptor and smokes
from being dropped by the linker.

`narf-bpf-idle` is `no_std` and `alloc`-backed, with strict lints. Its
non-test surface depends directly only on `narf-capabilities`,
`narf-bpf-structops`, and `narf-power`; the struct-ops crate owns the dependency
on the BPF runtime and verifier. The ISA assembly helpers and kernel-test
registry are enabled only for smokes that build and execute test programs; that
feature also enables the struct-ops framework crate's tests.
