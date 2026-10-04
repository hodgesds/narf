# i3c — MIPI I3C Bus Core

This crate is the protocol core for MIPI I3C (Improved Inter-Integrated
Circuit), the successor bus to I2C defined by the MIPI Alliance in the
I3C Basic specification. It is the hardware-independent half of the I3C
subsystem: it defines the abstract bus interface that controller drivers
implement and client drivers consume, together with the shared data
types and a process-global registry of live buses. The matching
controller hardware lives in `drivers/i3c`; this crate owns no silicon.

I3C keeps the two-wire, multi-drop topology of I2C but adds dynamic
addressing, higher data rates, and in-band signalling. The abstraction
here reflects those additions directly. Targets are brought onto the bus
through Dynamic Address Assignment (DAA): the controller broadcasts the
ENTDAA procedure and each responding device reports its Provisioned ID,
Bus Characteristics Register, and Device Characteristics Register, from
which it is handed a dynamic address. Common Command Codes (CCCs) — the
standardized in-band control messages, both broadcast and directed —
are a first-class concept, as is HDR-DDR, the double-data-rate mode that
clocks data on both edges to roughly double throughput at a given clock.

The defining I3C feature modelled here is the In-Band Interrupt (IBI):
instead of a dedicated interrupt pin, a target raises an interrupt over
the shared bus wires. The core exposes this as an async notification
surface — drivers register wakers or handlers against a target address,
and the controller's drain path wakes the corresponding future when an
IBI arrives. This makes I3C event handling naturally async-first and
removes the per-device IRQ line that I2C sensors otherwise require.

Access to the bus is mediated by the kernel's capability system: an
I3C-specific capability type participates in the global `CapKind` space,
and a rights enum distinguishes per-device read, per-device write,
per-device notify (IBI reception), and full bus administration (DAA and
other management operations). This lets a driver be granted authority
over exactly the target devices it owns rather than the whole bus.

The crate is `no_std` and allocator-backed, async throughout (transfers,
CCCs, DAA, and IBI handler registration are futures), and used on both
x86_64 and aarch64. Controller drivers register their bus
implementations into the registry so client drivers can locate a bus
without threading a handle through every initcall.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Stage: 4 (specification and initial bus trait)
