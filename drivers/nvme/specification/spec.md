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

- Data pointers (`imp::prp`, mirroring Linux `nvme_pci_setup_data_prp`):
  `setup_prps(addr, len, lists, list_dma) -> Result<PrpPair, PrpError>` builds
  PRP1 / PRP2 / a chained PRP list for a physically contiguous buffer at any
  dword-aligned offset; `prp_list_pages_needed`, `max_transfer_bytes(mdts,
  mpsmin)` (MDTS in CAP.MPSMIN units, clamped to `NVME_HOST_MAX_TRANSFER` =
  2 MiB), `host_page_supported(mpsmin)` and `decode_namespace_format(id_ns)`
  (FLBAS index incl. bits 6:5, LBA size 512..=4096, metadata ⇒ unusable).
- `Controller::max_transfer_bytes()`, `Controller::is_dead()`,
  `Controller::nvm_io_at(opcode, lba, n_blocks, buf, offset)`;
  `read_lba` / `write_lba` accept any contiguous buffer up to the max
  transfer. `IdentifyController::mdts`, `NvmeCaps::to` +
  `ready_timeout_ms()` (Linux `(CAP.TO + 1) * 500 ms`, 5 s floor).
- New `NvmeError` variants: `UnsupportedPageSize` (CAP.MPSMIN > 4 KiB, bring-up
  refused as Linux `nvme_enable_ctrl` does), `BadTransfer`,
  `ExceedsMaxTransfer`, `ControllerDead` (an I/O command timed out; later I/O
  refused), `NamespaceUnusable`.
- `NvmeBlockSync` / `NvmeBlockDevice` split a request into commands of at
  most `min(max_transfer, 128 KiB scratch)` / `max_transfer` bytes, in units of
  the namespace's LBA size.

- **Multiple controllers** (Linux `nvme_probe` per PCI function). `probe` runs
  once per NVMe function and installs it as the next instance `nvme<C>` (probe
  order = PCI enumeration order); each instance owns its BAR mapping, admin and
  I/O queues, MSI-X vectors, PRP list and 128 KiB DMA scratch behind its own
  request gate. Re-probing an installed function is a no-op.
  `controller_count()`, `instance_of(PcieAddr)`, `with_controller_at(instance,
  f)`, `admin_passthrough_at(instance, ..)`, `remove_controller(instance, cap)
  -> Option<bool>` (refuse I/O, unregister its block devices and node, then
  `disable_after_failure`: CC.EN=0 confirmed before DMA is freed, leaked
  otherwise; re-probe brings it back under the same instance).
  `with_controller` / `admin_passthrough` / `NvmeBlockSync` /
  `NvmeBlockDevice` address instance 0.
  Controller access preserves the caller's interrupt state. A contended
  process-context caller with IRQs enabled cooperatively yields after a
  short spin, allowing a descheduled holder on the same CPU to release the
  gate. IRQ/masked and non-stackful callers service pending TLB-shootdown
  and membarrier acknowledgements while waiting; they never re-enable IRQs
  or invoke framebuffer/device pumps from the gate wait.
- **Reset / recovery + hot-remove** (Linux `nvme_reset_work` / `remove`).
  `Controller::reset_recover(cap) -> Result<RecoveryReport, NvmeError>`:
  snapshot identity (IDENTIFY + namespace set), `disable_after_failure`,
  full `bring_up`, I/O-queue recreation, then an identity gate —
  serial / model / vendor must match the snapshot (firmware revision is
  not identity); a mismatch stops the foreign device again and returns
  `NvmeError::IdentityChanged`, and a changed namespace set on the same
  controller is reported as `RecoveryReport::namespaces_changed` for
  re-publication. A controller that cannot be shown stopped stays dead
  and I/O keeps failing; the first submit / flush that finds a
  controller dead tries the recovery again before proceeding.
- **Command timeout → reset → replay** (Linux `nvme_timeout`,
  `nvme_reset_work`, `nvme_retry_req`). Every I/O-queue command — Read,
  Write, Flush, Dataset Management, Write Zeroes — has `IO_TIMEOUT_MS` =
  30 s (Linux `nvme_io_timeout`); admin commands keep 5 s and are never
  replayed, so a broken controller still fails its probe in seconds.
  When the budget runs out the CQ is looked at once more before the
  command is declared lost (Linux `nvme_poll_irqdisable`, "timeout,
  completion polled"; counted by `late_completions()`). A lost command
  marks the controller dead, and the sync block entry points
  (`NvmeBlockSync` / `NvmeNamespaceBlock` read / write / write_fua /
  flush / trim, `NvmeBlockDevice` submit / flush / discard) then
  **reset the controller at the timeout site and replay the request**
  (`run_with_replay`), under the request gate held from the first
  attempt through the reset to the last replay, so no other command can
  run in between. The replay budget is `IO_MAX_RETRIES` = 5 (Linux
  `nvme_max_retries`) *consecutive timeouts on the controller* — reset
  by any completed command — so one request is attempted at most six
  times, and a controller that stopped answering altogether costs later
  requests one attempt each. The request fails (`CompletionTimeout` →
  `BlockIoError::DriverError` / `BlockError::IOError`) when the budget
  is spent, the reset fails, the namespace set changed across the reset
  (re-published, not replayed: the request's geometry is stale), or the
  final shutdown has begun (no reset then). Each replay restarts the
  request at its first block and re-stages every chunk from the caller's
  data; all five request kinds are idempotent under repetition with
  nothing in between. Deviation from Linux: no Abort command is sent
  first — the first expiry resets. `io_replays()` counts replays.
  `remove_controller` is also
  the driver's bus remove hook (bus §9.5): a `Detach` event for its
  function withdraws its block devices and node and disables it.
- **Namespace scan** (`imp::ns`, Linux `nvme_scan_work`): Active Namespace List
  (CNS 2) from NVMe 1.1, else `1..=NN`, capped at 1024; Identify Namespace per
  NSID, skipping NCAP=0 (inactive), NSZE=0 and unusable LBA formats; NGUID /
  EUI64 from Identify Namespace, overridden by the Namespace Identification
  Descriptor list (CNS 3, NVMe 1.3+). An error-status completion skips that
  namespace; a timeout aborts bring-up with the page parked for
  `disable_after_failure`. `Controller::namespaces()`,
  `Controller::nvm_io_nsid_at(nsid, ..)`, `IdentifyController::{ver, nn}`.
- **Block names and identity.** Namespace `k` (0-based, ascending NSID) of
  controller `C` registers as `nvme<C>n<k+1>` through
  `narf_block::register_block_device_with_identity` with a
  `narf_block::DiskIdentity` (`transport "nvme"`, controller PCI address,
  model/serial/firmware, vendor id, NSID, EUI64/NGUID/UUID), and is
  partition-scanned (`nvme<C>n<k+1>p<P>`). Every entry is behind the registry's
  `narf.disks` guard. `NvmeNamespaceBlock::new(instance, nsid)` is the
  registry device. **Names are not identity**: they shift when a controller is
  added, removed or fails to probe; consumers identify disks by filesystem
  UUID / PARTUUID or `DiskIdentity`.
- **Flush / FUA / shutdown** (`imp::shutdown`). `IdentifyController::{vwc,
  rtd3e}`; `Controller::has_volatile_write_cache()`, `flush_nsid(nsid)` (I/O
  opcode 0x00 when VWC bit 0 is set, else a no-op success; the 30 s I/O
  budget, a timeout marks the controller dead and the block entry points
  reset + replay), FUA = Write CDW12 bit 30 (native;
  `capabilities().fua = true`), `Controller::shutdown()` (flush every
  namespace, then CC.SHN = normal and wait for CSTS.SHST = complete within
  `clamp(RTD3E, 5 s, 60 s)`, Linux `nvme_disable_ctrl(shutdown)`; I/O refused
  afterwards). `shutdown_all_controllers()` is registered as the
  `narf_power::system` shutdown hook `"nvme"`, run on every reboot /
  power-off after the filesystem sync and the persistent-log flush. It
  refuses new requests, waits up to `SHUTDOWN_DRAIN_TIMEOUT_MS` (30 s, Linux
  `NVME_IO_TIMEOUT`) per controller for the in-flight command to release the
  request gate, then flushes + sends CC.SHN; a controller that never drains
  still gets CC.SHN written straight to the register (`SlotShutdown::Forced`,
  logged as an error). Never waits from interrupt context.
- **Dataset Management / Write Zeroes** (#927). `IdentifyController::oncs`
  (bytes 256..258); `Controller::supports_dataset_mgmt()` (ONCS bit 2),
  `supports_write_zeroes()` (ONCS bit 3), `dataset_mgmt_ns(ns, ranges)`
  (I/O opcode 0x09 with CDW11 AD=1; at most 256 ranges per command; the
  range-definition length is the 1-based block count, NVM Command Set
  §3.2.3 Figures 39–41; the range list is staged in the controller's
  persistent DSM page) and `write_zeroes_ns(ns, lba, n_blocks)` (opcode
  0x08, CDW12 NLB 0-based, at most 65 536 blocks per command, no data
  transfer). Both return `NvmeError::NotImplemented` on a controller
  without the ONCS bit — never a silent success. The block surfaces
  advertise exactly what ONCS supports: `BlockDeviceSync::supports_trim`
  / `trim` on `NvmeBlockSync` / `NvmeNamespaceBlock`, and
  `NvmeBlockDevice::supports(Discard | WriteZeroes)` with
  `BlockOp::Trim` / `BlockOp::WriteZeroes` issuing the real opcodes
  (the request buffer is never written to the device). The advisory
  DMRL / DMRSL / DMSL processing limits are not yet parsed; commands
  stay within the architectural limits above.
- **System suspend / resume** (`DevicePmOps`, #926). `suspend` drains the
  request gate (30 s budget; `DeviceSuspendError::Busy` if it never frees —
  no forced quiesce, unlike final shutdown), then `Controller::suspend_pm`:
  Flush every namespace + CC.SHN (the shutdown path), queue teardown and
  CC.EN clear (Linux `nvme_suspend` = `nvme_dev_disable(shutdown = true)`).
  `resume` (`Controller::resume_pm`) is a full re-init — `bring_up` +
  `create_io_queues_preferred` (Linux `nvme_resume` = controller reset) — followed by
  an identity re-check against the pre-suspend snapshot (Identify
  serial/model/NN + the registered namespace set; the firmware revision is
  not compared). A mismatch leaves the controller torn down and fails the
  resume rather than serving a different disk under the old registrations.
- **Interrupt / multi-queue datapath + AER** (#928). Probe runs
  `Controller::create_io_queues_preferred`: Set Features — Number of
  Queues (FID 0x07, NVMe Base Spec 2.0c §5.27) + per-queue MSI-X pairs
  (`create_io_queues_msix`), falling back to the single polled pair
  (`create_io_queue`) only when MSI-X is unavailable or the negotiation
  is refused before any queue was created (`NvmeError::Msix` is the
  contract for "nothing created yet"; any other error stops the
  controller instead). MSI-X entry 0 stays the admin queue's (Linux
  `nvme_create_cq`: `vector = num_vecs == 1 ? 0 : qid`); I/O queues
  use entries `1..=granted` with `IV = qid`, `IEN = 1`, one IDT
  vector + installed handler each. Production submissions
  (`nvm_io_dma`, `nvm_io_multipage`, hence every block-layer read /
  write) route through `submit_sqe_irq` — IRQ-driven wait on the
  queue's vector `fire_count` with a CQE-phase fallback, 30 s budget
  (`IO_TIMEOUT_MS`), CID-matched drain, one last CQ look at expiry —
  whenever the picked queue has a vector; the polled
  `Queue::submit` stays the fallback for vector-less boots.
  `submit_io_irq_async` is the async form, composed from
  `submit_io_begin` (SQE + doorbell, wait future constructed
  pre-doorbell) + await + `submit_io_finish` (CID-aware CQE drain);
  the split
  lets a caller release the slot gate across the await — no
  `IrqSafeSpinLock` is ever held across a suspension point and no
  `block_on` appears on this path. The composed async form still
  holds the slot gate (an atomic, IRQs live) across the await, so
  one async I/O is in flight per controller; completion matching is
  CID-aware (see §10.1) — true concurrency still needs the
  per-queue CID waiter table + the request-gate → async-Mutex
  migration. Bring-up enables Async Event
  Configuration (SMART/health + namespace-attribute-changed, FID
  0x0B) and posts 3 AERs (§5.2 recommends ≥4; the depth-8 admin
  queue could host 7 — see §8.4 — but QEMU accepts only 3 before
  returning "Cmd Limit Exceeded" on the 4th, so 3 is the posted
  count — see §10). The admin
  submit path is CID-aware: a stray AER completion at the CQ head
  is stashed (`Queue::stray_aer`) for `drain_aer_events`, never
  mistaken for the awaited command's CQE. A Stage::Late supervisor
  task parks on each instance's admin vector (250 ms deadline) and
  drains AERs; a namespace-attribute-changed Notice triggers
  `Controller::rescan_namespaces` + withdraw/re-publish of the
  block devices, the same pair `recover_slot` uses after a reset.
- `/dev/nvme<C>`: one controller node per instance
  (`narf_filesystem::devfs::register_nvme_controller(instance, node,
  namespaces)`); `NVME_IOCTL_IO_CMD` / `NVME_IOCTL_IO64_CMD` are refused
  (EOPNOTSUPP: no I/O-queue passthrough yet); its admin passthrough and `write`
  are allowed only under `narf.disks=all` or when every namespace of that
  controller is the identified boot medium. Device PM registers `nvme<C>`
  per instance (`DevicePmOps`).

## 4. Invariants & safety properties

- The AER supervisor always reaches an await point, including when no NVMe
  controller is installed. An empty controller registry parks for the normal
  supervisor poll interval, permitting peer executor tasks to make progress.

- PRP / SGL lists validated against the DMA buffer's bounds.
- No DMA buffer a command may still reference is freed: I/O uses persistent
  scratch and PRP-list pages, a timed-out I/O marks the controller dead, and a
  timed-out admin passthrough leaks its pages.
- A timed-out request is replayed only after the controller was confirmed
  stopped (CC.EN=0, CSTS.RDY=0) and its queues rebuilt, with the request gate
  held throughout, and only if the namespace set is unchanged. Replays are
  bounded (`IO_MAX_RETRIES` consecutive timeouts per controller); nothing but
  the idempotent block requests (read, write, flush, deallocate, write zeroes)
  is ever replayed — no admin command, no passthrough.
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

### 8.4 Admin queue depth vs AER headroom (resolved, #1618)

**Decision:** **admin queue depth 8** (`ADMIN_Q_DEPTH = 8`).

NVMe Base Spec 2.0c §5.2 recommends hosts keep at least AERL+1 AER
requests outstanding, with a floor of ≥4. The old depth-4 admin queue
capped AER posting at `depth - 1 = 3`, below the floor. At depth 8
the SQ is 8 × 64 = 512 B and the CQ 8 × 16 = 128 B, so each queue
still fits in a single 4 KiB DMA page; the AER cap (`depth - 1` = 7)
covers the ≥4 floor while leaving one SQ slot free for a non-AER
admin command. AQA, the doorbell stride (CAP.DSTRD, depth-independent),
and the depth-1 drain bound all derive from the constant, so no other
arithmetic changes; the AER smoke asserts the queue holds 4 AERs at
once. The I/O queue depth stays 4 — only the admin queue needs the
AER headroom.

## 9. ABI versioning

`narf-drivers-nvme` exports its `Controller` type opaquely
through the block-device adapter (`NvmeBlockSync` /
`NvmeBlockAsync`) which implement `BlockDeviceSync` /
`BlockDeviceAsync` from `block/spec` §9. There is no
NVMe-specific public API beyond that.

`NVME_DRIVER_ABI_MAJOR = 1`, `NVME_DRIVER_ABI_MINOR = 0`.

## 10. Open questions

- **AER posted count vs §5.2 floor (#928 remainder).** Bring-up
  posts 3 AERs (`AER_POST_COUNT`); NVMe Base Spec 2.0c §5.2
  recommends ≥4 outstanding. The admin-depth half is resolved:
  #1618 raised `ADMIN_Q_DEPTH` to 8 (§8.4), so the queue could
  host 7. The count stays 3 because QEMU reports AERL=0 yet
  accepts only 3 and returns "Cmd Limit Exceeded" on the 4th;
  raising the posted count toward `depth - 1` is a follow-up for
  silicon that accepts more.
- **Concurrent async I/O (#928 remainder).** `submit_io_irq_async`
  holds the slot gate across its await (sound — the gate is an
  atomic, IRQs live — but one async I/O in flight per controller).
  Completion matching is CID-aware since #1619 (§10.1); true
  concurrency still needs a per-queue CID waiter table +
  routing `BlockDevice::submit` through `submit_io_irq_async`,
  gated on the `InstalledController` request-gate → async-Mutex
  migration — until then the async block-layer submit stays
  eager-sync through the sync IRQ path.

### 10.1 CID-matched completion tracking (delivered, #1619)

**Delivered:** every completion consumer matches by CID (NVMe
base spec §4.6: the CQE's `cid` echoes the submission's CDW0
bits 16..31), never merely by taking the next entry at the CQ
head:

- `Queue::submit_raw_ms` (polled admin + I/O submit) loops on
  the CQ head until the CQE carrying its own CID arrives, within
  the caller's timeout budget. A stray whose CID is an
  outstanding AER is stashed (`stray_aer`, bounded by
  `ADMIN_Q_DEPTH - 1`) for `drain_aer`; any other stray is
  consumed and dropped.
- `Controller::drain_aer` consumes only CQEs whose CID is an
  outstanding AER (tracked per admin queue in `aer_cids`),
  drains the `stray_aer` stash first, and reposts one AER per
  drained completion. A head entry carrying another CID is a
  normal admin command's completion and is left for its waiter.
- `Controller::submit_io_irq` / `submit_io_irq_async` drain
  through `try_take_io_cqe`: only the CQE carrying the
  submitted CID is accepted; strays are consumed and dropped
  and the wait repeats within the command deadline. The sync
  path loops inside `submit_sqe_irq` (30 s budget, then
  `reap_io_cqe`: one non-blocking drain of up to `depth` head
  entries before the command is declared lost); the async
  form is `submit_io_begin` (which returns the CID) + await +
  `submit_io_finish`, whose CID-aware drain re-checks the head
  after the await — the lost-wakeup window the old single-shot
  form's pre-doorbell construction handled is closed by the
  pre-doorbell future construction plus that re-check.
- Diagnostics: `Controller::aer_outstanding()` (AER CIDs still
  tracked on the admin queue — a completion stashed by
  `submit_raw_ms` untracks its CID, so the count drops until
  `drain_aer` reposts) and `Controller::stray_aer_len()`.
- No stray is dropped silently. Every dropped stray (both
  matchers; a stashed AER completion is not a drop) is counted —
  `stray_cqe_drops()` — and the 1st, 10th, 100th, ... is logged
  with the queue, CQ head index and phase, the expected CID and
  the seen CQE's CID / SQ id / SQ head / status / result (Linux
  `nvme_handle_cqe`: "invalid id %d completed on queue %d").
- Every completion timeout is logged where it is declared and
  counted — `command_timeouts()`: opcode, CID, queue, elapsed
  time, CQ head index + phase and the head CQE (marked FRESH
  when its phase tag says a completion is sitting there
  unconsumed), SQ tail, CSTS, the queue's interrupt vector with
  its `fire_count` and the number of times it fired since the
  command was submitted, and whether this CPU has interrupts
  enabled / is in an interrupt handler (Linux `nvme_timeout`:
  "I/O tag %d (%04x) opcode %#x QID %d timeout"). The async
  finish path reports the same line without the elapsed time.

**Fixture:** `imp/tests_cid.rs` drives the real
`submit_raw_ms` loop against a RAM-backed fake controller
with spec-laid-out pre-posted CQEs (§4.6): a stray AER error
completion at the admin head is skipped (event word stashed,
then drained + reposted) and the submit returns its own CQE;
an I/O-queue stray is dropped, never stashed — and counted
by both matchers (`smoke_nvme_stray_drop_is_counted`); a
command against a silent CQ times out, is counted once and
consumes nothing (`smoke_nvme_timeout_is_counted`). A live AER
event cannot be synthesised on QEMU from the harness (no QMP
hot-attach), so the live event half is silicon-only — the
same carve-out as the AER supervisor.

**Rebase note:** #1617 (IRQ/multi-queue datapath + AER) landed
first, so this PR rebased onto it and dropped the duplicate
admin half #1617 already carried (`submit_raw_ms` CID loop,
`stray_aer`, the AER-supervisor wiring) — keeping the
`aer_cids` tracking, the `try_take_io_cqe` I/O drain, the
`tests_cid.rs` fixture, and the DSM model-controller CID
tagging (which #1617 also carried, so that commit was
skipped as already-applied). The CID-aware drain was wired
into #1617's `submit_io_begin` / `submit_io_finish` split
(`begin` returns the CID, `finish` takes it) and into
`submit_sqe_irq`, instead of the branch's pre-#1617
monolithic async loop.

**Remainders (not this change):**

- True concurrent async I/O still needs a per-queue CID waiter
  table + routing `BlockDevice::submit` through
  `submit_io_irq_async` — all gated on the
  `InstalledController` request-gate → async-Mutex migration,
  since the gate serialises the whole controller today and no
  second submitter can exist to wait.
- A multi-submitter smoke belongs with that migration, not
  here: through the gate it would only prove sequential
  submits, not concurrency.
