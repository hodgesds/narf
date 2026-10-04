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
hand-written idle-governor contract and dispatches through a boxed trait
object, unable to tell a BPF-driven governor from a native one. On the other,
`narf-bpf-structops` supplies the `struct_ops!` machinery that turns a trait
declaration into the full apparatus for binding and running a program set:
the governor trait, the adapter that actually executes the bound program, a
capability-gated install entry point, and a descriptor registered into the
kernel's `struct_ops` table. This crate writes the small bridge that maps the
generated adapter onto `power`'s native contract and the committer that, once
the program set is verified, moves the adapter into `power`'s live governor
slot. It is the only place the two meet.

The design embodies the capability and verification discipline of NARF's BPF.
Installation is gated by a capability whose kind the `struct_ops` layer proves
before the committer runs, and `power` re-checks the capability when it accepts
the governor, so a malformed or unauthorized set never reaches the live slot.
Nothing is installed at boot; a governor appears only when a program installs
one at runtime. The crate's force-link anchor exists purely to keep the
`struct_ops` descriptor and the smoke tests from being dropped by the linker.

`narf-bpf-idle` is `no_std` and `alloc`-backed, with strict lints. Its
non-test surface depends only on `narf-capabilities`, `narf-bpf-structops`, and
`narf-power` — deliberately naming only the `struct_ops` program-set type and
the power types. The full BPF runtime (`narf-bpf`, the ISA, and the verifier)
is pulled in only under the `kernel-test` feature, by the smokes that actually
assemble, verify, load, and run a program bound to the governor; that feature
also cascades the `struct_ops` framework crate's own tests.
