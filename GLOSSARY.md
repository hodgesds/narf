# NARF Glossary

Project-specific vocabulary used across specs. Everything here is defined
once, so subsystem docs can link rather than redefine.

### Framekernel

NARF's architectural style. A minimalist Rust TCB ("the Frame") runs in
Ring 0 / EL1, but its single kernel address space is partitioned into
hardware-enforced domains by PKS (Intel) or MTE (ARM). Drivers run inside
those domains instead of in separate address spaces — they get the speed of
a monolithic kernel and the containment of a microkernel.

### The Frame

The TCB itself: boot, CPU state management, trap/exception dispatch, domain
configuration, capability table maintenance. Lives in `frame/`.

### Narf-Link

The logical binding between a driver and the PKS/MTE domain it executes in.
A Narf-Link includes the domain id, the driver's capability root, and the
memory regions the driver is permitted to touch.

### Narf-Ring

NARF's zero-copy IPC primitive. A shared-memory ring buffer whose slots
carry ownership-transferred pointers rather than copied bytes. Variants:
SPSC and MPSC. Details in `ipc/specification/spec.md`.

### Domain (PKS / MTE domain)

A hardware-enforced partition of the kernel address space. Up to 16 domains
on x86_64 via PKS (16 keys) / PKU (16 keys for user); aarch64 provides an
analogous partitioning via MTE tags. A domain has an id, a set of rights,
and a set of memory regions tagged to it.

### Cap (Capability)

An unforgeable, typed token granting one specific right over one specific
object. Rust's type system prevents forging, aliasing-without-permission,
and use-after-free. Examples: `Cap<BlockDevice, Write>`, `Cap<NetIface, Recv>`.

### Direct Context Transfer

Scheduling optimisation in which a task invoking another task donates its
remaining time slice to the callee, avoiding a full scheduler round-trip
("double-trip"). Implemented by the executor in `scheduler/`.

### P2PDMA (Peer-to-Peer DMA)

DMA transfer where one PCIe device writes directly into another device's
memory (e.g. NIC → GPU) without bouncing through system RAM or the CPU.
Requires IOMMU configuration; see `io/`.

### UIPI (User Interrupts)

Intel ISA extension that lets hardware deliver an interrupt directly to a
user-mode (or non-TCB) handler, bypassing the kernel trap. NARF uses UIPI
to deliver IRQs straight into the appropriate driver's domain. GICv3 ITS
provides the conceptual equivalent on aarch64.

### Global LTO

Link-Time Optimisation spanning the entire OS binary, so calls across
subsystems can be inlined. NARF treats the kernel as one cargo-workspace
LTO unit; see `build/`.

### Stage (1/2/3/4)

Roadmap stages: Skeleton, Barrier, Flow, Compatibility. Every spec carries
a Stage assignment. See `ROADMAP.md`.

### TCB (Trusted Computing Base)

Code that, if compromised, compromises the whole system. In NARF the TCB is
deliberately small: `frame/` + `memory/` (domain manager) + `capabilities/`
+ the executor core in `scheduler/`. Drivers are *outside* the TCB even
though they share the kernel address space — that's the whole point of the
framekernel approach.
