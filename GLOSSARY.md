# NARF Glossary

Project-specific vocabulary used across specs. Everything here is defined
once, so subsystem docs can link rather than redefine.

### Framekernel

NARF's architectural style. A small trusted core establishes protection
rules for kernel services. PKS or PCID-tagged page tables on x86_64, and
MTE where available on aarch64, can confine resources assigned to domains.
The actual protection depends on the selected backend and mapping policy;
see `docs/DOMAIN_BACKENDS.md`.

### The Frame

The TCB itself: boot, CPU state management, trap/exception dispatch, domain
configuration, capability table maintenance. Lives in `frame/`.

### Narf-Link

The logical binding between a driver and the PKS/MTE domain it executes in.
A Narf-Link includes the domain id, the driver's capability root, and the
memory regions the driver is permitted to touch.

### Narf-Ring

NARF's shared-memory IPC primitive. Ring slots carry handles to buffers;
ownership transfer avoids copying the buffer payload, though handles and
ring metadata are copied. Details in `ipc/specification/spec.md`.

### Domain

A named protection context with an ID, rights, and associated resources.
NARF declares 16 domain IDs. Enforcement uses PKS or PCID on supported
x86_64 systems and MTE on supported aarch64 systems. Without an active
backend, a declared domain is not a hardware isolation boundary.

### Cap (Capability)

An unforgeable, typed token granting a right over an object. Rust types
constrain use at compile time; `Cap::invoke()` checks current validity after
revocation. Examples: `Cap<BlockDevice, Write>`, `Cap<NetIface, Recv>`.

### Direct Context Transfer

Scheduling optimisation in which a task invoking another task donates its
remaining time slice to the callee, avoiding a full scheduler round-trip
("double-trip"). Implemented by the executor in `scheduler/`.

### P2PDMA (Peer-to-Peer DMA)

DMA transfer where one PCIe device writes directly into another device's
memory (e.g. NIC → GPU) without bouncing through system RAM or the CPU.
Requires IOMMU configuration; see `io/`.

### UIPI (User Interrupts)

Intel ISA extension for delivering user interrupts without a conventional
kernel trap. It is an optional hardware path in NARF's design, not the
default IRQ path on every machine. GICv3 ITS handles interrupt translation
on aarch64.

### Global LTO

Link-Time Optimisation spanning the entire OS binary, so calls across
subsystems can be inlined. NARF treats the kernel as one cargo-workspace
LTO unit; see `build/`.

### Stage (1/2/3/4/5)

Development stages: Skeleton, Barrier, Flow, Compatibility, Silicon. Every
subsystem spec carries a Stage assignment. See `STATUS.md` for progress.

### TCB (Trusted Computing Base)

Code that, if compromised, compromises the whole system. In NARF the TCB is
deliberately small: `frame/` + `memory/` (domain manager) + `capabilities/`
+ the executor core in `scheduler/`. Drivers are *outside* the TCB even
though they share the kernel address space — that's the whole point of the
framekernel approach.
