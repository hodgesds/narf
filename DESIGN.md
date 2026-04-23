# NARF: Not Another Rust Frankenkernel

**Project Status:** Design Phase (v1.0)

**Vision:** To provide a "Zero-Overhead" secure operating system by merging
the safety of Rust with the performance of hardware-assisted isolation.

This file is the verbatim v1.0 vision document — the source of truth every
subsystem specification derives from. Changes to the high-level design belong
here; subsystem-level detail belongs in the per-subsystem `specification/spec.md`.

---

## 1. Architectural Blueprint: The Framekernel

NARF rejects the binary choice between "slow microkernel" and "insecure
monolithic." Instead, it uses a **Framekernel** architecture.

- **The TCB (Trusted Computing Base):** A minimalist Rust "Frame" that manages
  CPU state, PKU domains, and Capability tables.
- **Intra-Address Space Isolation:** Unlike Linux, where everything in Ring 0
  shares one big memory space, NARF uses **Intel PKS / ARM Memory Tagging** to
  divide the kernel's address space into 16 hardware-protected domains.
- **The "Narf-Link":** Drivers (Network, GPU, NVMe) run in these domains.
  They share the same virtual memory map for speed but are hardware-blocked
  from touching each other's data.

## 2. The Continuity Scheduler (Async-First)

In NARF, the scheduler is not a separate entity; it is a **Global Async Executor**.

- **Everything is a Future:** Every system call, interrupt, and driver task
  is a stackless Rust `Future`.
- **Zero-Copy IPC (The Narf-Ring):** Communication happens via shared-memory
  ring buffers. When data moves from the NIC to an App, NARF uses Rust's
  Ownership Transfer to "move" the pointer. The bytes never move in physical RAM.
- **Direct Context Transfer:** If an App calls the Filesystem Service, the
  Executor "donates" the App's remaining CPU time-slice directly to the
  Service. This eliminates the "Double Trip" context-switch penalty found in
  older microkernels.

## 3. Security Model: Capability-Based Access

NARF operates on the principle of **Least Privilege**.

- **No Root User:** Permissions are tied to Capabilities (unforgeable tokens).
- **Object-Level Security:** To write to a disk block, a process must possess
  a `BlockCap`. To see a network packet, it needs a `NetCap`.
- **Rust-Enforced:** These capabilities are wrapped in Rust types that cannot
  be forged, leaked, or used after they are destroyed.

## 4. Performance Innovations

To outpace Linux, NARF focuses on **Hardware Bypass**:

| Feature    | Implementation                   | Result |
| ---------- | -------------------------------- | ------ |
| I/O Path   | Peer-to-Peer DMA (P2PDMA)        | Data moves from NIC → GPU without CPU intervention. |
| Interrupts | User-Level Interrupts (UIPI)     | Hardware signals the driver directly, bypassing the Kernel Trap. |
| Compiling  | Global LTO                       | The entire OS is optimized as a single binary unit for maximum inlining. |

## 5. Development Roadmap

- **Stage 1 (The Skeleton):** Bootloader + Basic Async Executor + Serial Console.
- **Stage 2 (The Barrier):** Implementation of PKS/PKU memory domain switching.
- **Stage 3 (The Flow):** First "Narf-Ring" implementation for VirtIO drivers.
- **Stage 4 (The Compatibility):** relibc integration to run standard Rust binaries.

---

**Final Design Quote:**

> "NARF: Because security shouldn't feel like a speed limit."
