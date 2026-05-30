# event_bus

Planning-only. See `SPEC.md` for the full design.

## TL;DR

A unified SPMC publish/subscribe bus for NARF system services. One
publisher per topic, many cursor-tracked subscribers, slow
subscribers see a `SYN_DROPPED`-style gap signal but never slow the
publisher. Cap-gated end-to-end. Subsumes today's seven scattered
event-fan-out mechanisms (`filesystem/src/uevent.rs`,
`bus/src/acpi_notify.rs`, `aml/src/buttons.rs`, `power/src/thermal.rs`,
plus several smaller subscriber lists).

## Quick layout

- `SPEC.md` — full design specification (~3.5k words). Survey of
  in-tree prior art, comparison to LMAX Disruptor / NATS / Aeron /
  Linux netlink, ring shape + cap model + backpressure design,
  Rust API sketch, five-phase rollout, four open decisions.

## Phasing snapshot

- Phase 1 (~1.8 kLoC, 3 wk): in-kernel SPMC + async API + migrate
  acpi_notify / buttons / thermal.
- Phase 2 (~1.4 kLoC, 2 wk): file-descriptor + epoll surface,
  uevent migration.
- Phase 3 (~1.6 kLoC, 3 wk): wildcards + cross-domain mmapped ring.
- Phase 4 (~700 lines, 1.5 wk): replay / late-join.
- Phase 5 (~800 lines net, 1 wk): migrate remaining consumers.

## Open decisions blocking implementation

See `SPEC.md` §7. Four decisions need user input before Phase 1
starts:

1. Wildcards in Phase 1 vs Phase 3.
2. Engine in kernel TCB vs dedicated driver domain.
3. Variable-size payload strategy (arena handle, fixed cap, or
   uevent-stays-separate).
4. One fd per topic vs one fd many-topics.
