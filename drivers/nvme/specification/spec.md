# drivers/nvme — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined the
> queue-pair model + identify flow; v1.0 locks the
> multi-queue policy, the CMB/HMB scope, and the data-protection
> posture.

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

## 7a. Admin command builders (`admin`)

`admin/` is a clean-room module producing 64-byte SQE byte arrays
the driver feeds into the admin Submission Queue. References
(public-only):

- **NVM Express Base Specification, Revision 2.0c** (Oct 2022) —
  NVM Express Inc. Public document. §3.3.3 (SQE layout, 64 bytes;
  CDW0 packs opcode | fuse | psdt | cid). §5 Admin Command Set
  table 27 (opcode list). §5.4 Format NVM (CDW10 carries LBAF in
  bits 3..0 and SES in bits 11..9). §5.21 Sanitize (CDW10 bits 2..0
  = SANACT, bit 3 = AUSE, bits 7..4 = OWPASS, bit 8 = OIPBP; CDW11
  = overwrite pattern). §5.16 Get Log Page (CDW10[7:0]=LID,
  CDW10[31:16]=NUMDL, CDW11[15:0]=NUMDU). §5.31 Set Features (CDW10
  carries the FID; FID 0x07 Number of Queues encodes NSQR/NCQR in
  CDW11; FID 0x1A Boot Partition Write Protection encodes BPID in
  CDW11 bit 31 and BPWPS in CDW11[2:0]).
- **NVM Command Set Specification, Revision 1.0c** — SMART/Health
  log page (LID 0x02) byte layout used by the SmartLog decoder
  (composite temperature in K at offset 1..3, percentage used at
  offset 5, power-on hours at offset 128, unsafe shutdowns at offset
  160, media errors at offset 176).

## 7b. NVMe-MI sub-module

`mi/` is a clean-room NVMe Management Interface codec. References
(public-only):

- **NVM Express Management Interface, Revision 1.2c** (NVM Express
  Inc., 2023). §3 (Message Format), §3.1 (NVMe-MI Message Header /
  NMH), §3.4 (Message Integrity Check / MIC, CRC-32 polynomial
  0xEDB88320 reflected, init/xor 0xFFFFFFFF — same as Ethernet),
  §5.1 Read NVMe-MI Data Structure (DTYPE table 124),
  §5.6 Controller Health Status Poll, §5.8 NVM Subsystem Health
  Status Poll.
- **DMTF DSP0236 v1.3.1** — MCTP base. NVMe-MI travels as MCTP
  message-type 0x04.

The codec is bus-agnostic — the same bytes flow over MCTP-over-SMBus,
MCTP-over-PCIe-VDM, or in-band tunneling via NVMe Admin opcodes. No
GPL Linux source consulted.

## 8. Resolved decisions

### 8.1 Multi-queue policy (resolved)

**Decision:** **one I/O queue per CPU**, capped at the
device's `MaxQueueCount`. The driver creates queues at
bring-up sized to `min(cpu_count, max_q_count_supported)`.
Each queue is bound to a specific CPU's APIC ID for MSI-X
delivery.

Per-domain queues were considered but rejected: domains
multiplex onto CPUs (per `memory/spec` §8.1), so a
per-CPU queue serves all the domains running on that CPU
without per-domain bookkeeping.

I/O submissions choose a queue based on the submitting
task's CPU affinity. Cross-CPU queue submissions are
permitted (with the obvious cache-locality cost).

### 8.2 CMB / HMB (resolved)

**Decision:** **out of scope for v1.0**.

CMB (Controller Memory Buffer): only useful for P2P DMA
between NVMe and other devices (e.g. RDMA NIC writing
directly into NVMe's SQ); requires `Cap<BusDevice, P2pDma>`
+ ACS-clean topology. Defer to Stage 5+ when there's a
concrete consumer.

HMB (Host Memory Buffer): primarily a power-savings
feature for consumer-class NVMe drives. Out of scope until
a workload makes it worth the implementation cost.

The driver advertises support flags for both via its
`IfaceStats`, so a future consumer can detect availability
without the driver code growing.

### 8.3 End-to-end data protection (resolved)

**Decision:** **DIF/DIX integration in Stage 5+**, not v1.0.

v1.0 NVMe driver does not negotiate DIF/DIX. The protection
information feature is unused; metadata fields are zero.

When `block/spec` §8.4's encryption-at-rest layer matures,
DIF/DIX becomes interesting (per-block integrity tags
that the device verifies). At that point the driver gains
a `Cap<NamespaceProtection, _>` cap, enabled per-namespace.

For v1.0, NVMe relies on the device's internal ECC for
end-to-end data integrity; software adds no further
protection.

## 9. ABI versioning

`narf-drivers-nvme` exports its `Controller` type opaquely
through the block-device adapter (`NvmeBlockSync` /
`NvmeBlockAsync`) which implement `BlockDeviceSync` /
`BlockDeviceAsync` from `block/spec` §9. There is no
NVMe-specific public API beyond that.

`NVME_DRIVER_ABI_MAJOR = 1`, `NVME_DRIVER_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
