# drivers/nvme — Specification

> Status: **Outline v0.1** (Stage 4).

## 1. Purpose & scope

**Owns:** NVMe controller init (admin queue), I/O queue pair
management, submission/completion entry marshalling, command set
support (read, write, flush, TRIM at minimum).

**Does NOT own:** Filesystem (later, out of scope of the kernel tree),
multipath / fabrics (defer).

## 2. Assumptions

- PCIe enumeration has found an NVMe class controller.
- `io/` DMA buffers + IOMMU context available.
- `interrupts/` can wire MSI-X vectors, one per I/O queue.

## 3. Public interface

- Inbound (capability-gated):
  - `Cap<Namespace, Submit>` — submit on a **shared** I/O queue.
    `block/`'s multi-queue dispatcher (Stage 4) chooses the actual
    physical queue per-submission for load-balanced shared use.
  - `Cap<IoQueue, Own>` — exclusive use of one I/O queue pair, with
    sequential completion guarantees. Required for workloads that
    need strict per-submitter ordering (database WAL, journaled FS
    commit). This is how SPDK achieves determinism for storage
    engines.
- Outbound: **per-queue Narf-Ring handles** + a multiplexer ring
  exposed to `block/` for the shared-queue case. The driver owns N
  physical I/O queues and exposes them via N rings; `block/` selects
  per-submission queue affinity.

## 4. Invariants & safety properties

- PRP / SGL lists validated against the DMA buffer's bounds.
- A completion cannot be processed before its submission entry is valid
  (paired ordering).
- The admin queue is never used on the I/O fast path.

## 5. Architecture notes

### x86_64
- MSI-X, `clwb` for PRP list flushes if platform requires it.
### aarch64
- MSI-X via GICv3 ITS; cache maintenance around buffers on non-coherent
  platforms.

## 6. Dependencies

- **Consumes:** `drivers/` (framework), `io/`, `ipc/`, `interrupts/`,
  `capabilities/`, `memory/`.
- **Provides to:** whatever storage stack sits above NARF (outside this
  kernel tree; via the block Narf-Ring).

## 7. Stage assignment

Stage 4.

## 8. Open questions

- Multi-queue policy: one I/O queue per CPU, or per-domain?
- CMB / HMB usage — Stage 4 worth it?
- End-to-end data protection (DIF/DIX) — Stage 4 scope or later?
