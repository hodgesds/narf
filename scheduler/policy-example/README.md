# scheduler/policy-example — Out-of-Tree Scheduler Policy Compile Proof

`narf-scheduler-policy-example` is a standalone crate that proves NARF's
scheduling policy can live outside the scheduler core. The NARF executor
owns task slots, run-queue locks, budget charging, stack and domain
restore, and context switching; scheduling *policy* — which runnable task
to pick next — is replaceable from a separate `no_std` crate through a
read-only interface. This crate exists to keep that interface honest.

## What it demonstrates

It implements an example budget-aware, class-ordered policy that depends
only on `narf-scheduler`'s public API. Crucially, it *cannot* name the
core's private machinery: task slots, run-queue locks, stack/domain switch
state, and the architecture context-switch functions are all out of reach.
A policy sees only what the read-only `RunQueue` / `TaskMeta` snapshot
exposes — scheduling class, work kind, runnable state, affinity, priority,
deadlines, and immutable budget/accounting snapshots — and returns a
chosen task handle. It can keep its own per-CPU state across the queue
events the core reports, but it can never charge a budget, throttle a
task, remove a queue slot, or switch execution context; those stay core
only.

## Why it is in the tree

Because it is a dependency-isolated compile target, it serves as a
continuously-checked boundary test: if a change to `narf-scheduler` leaks
an internal type into the policy surface or breaks the external-crate
contract, this crate stops compiling. It corresponds directly to the
replaceable-policy interface described in the parent `scheduler` crate and
is the reference shape an out-of-tree policy author would copy. It is not
published and gates nothing beyond its own compilation.
