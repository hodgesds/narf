# block — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined the
> queue-based block surface; v1.0 locks the page-cache home,
> request-fairness model, barrier semantics, encryption-layer
> placement, hot-remove handling, and ABI versioning.

## 1. Purpose & scope

**Owns:** The generic interface every block device (real or virtual)
implements, the I/O scheduler that orders requests across consumers,
multi-queue dispatch, and operations that aren't just read/write:
discard/TRIM, flush, write-zeroes, zone management (deferred).

**Does NOT own:**

- Concrete block drivers — live in `drivers/{nvme,virtio,…}`.
- Filesystems or file semantics — `filesystem/`.
- DMA buffer mechanics — `io/`.
- Caching decisions (page cache equivalent) — `filesystem/` owns the
  cache; `block/` is a pass-through unless explicitly configured.

## 2. Assumptions

- `drivers/` produce devices that implement the `BlockDevice` trait.
- `io/` supplies `DmaBuffer<T>` for backing I/O.
- `ipc/` Narf-Rings carry requests between `block/` and drivers.
- `capabilities/` gates access: `Cap<BlockDevice, R>` where R ∈ {Read,
  Write, Admin, Discard}.

## 3. Public interface

### 3.1 Device trait

```rust
pub trait BlockDevice: Send + Sync {
    fn logical_block_size(&self) -> u32;          // e.g. 512 or 4096
    fn physical_block_size(&self) -> u32;
    fn capacity_blocks(&self) -> u64;
    fn supports(&self, feat: BlockFeature) -> bool;

    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion>;
    fn flush(&self)                     -> impl Future<Output = ()>;
    fn discard(&self, range: LbaRange)  -> impl Future<Output = ()>;

    /// Cancel an in-flight request by kernel-assigned tag.
    /// Returns `Cancelled` (op was aborted before hardware completed),
    /// `Completed` (op finished naturally; caller should drain the
    /// completion to inspect the result), or `NotFound` (tag refers
    /// to no in-flight op — already completed and drained, or never
    /// submitted). Required by `abi/` §3.1 cancellation protocol.
    fn cancel(&self, tag: u64) -> impl Future<Output = CancelResult>;
}

pub enum CancelResult { Cancelled, Completed, NotFound }
pub enum BlockFeature { Flush, Discard, WriteZeroes, Fua, Zoned, AtomicWrites }
```

### 3.2 Request / completion

```rust
pub struct BlockRequest {
    pub op:       BlockOp,           // Read | Write { fua: bool } | WriteZeroes | Trim
    pub lba:      u64,
    pub blocks:   u32,
    pub buffer:   Cap<DmaBuffer, _>, // cap-gated; payload never copied through block/
    pub qos:      QosHint,           // Latency | Throughput | Background
    pub user_tag: u64,               // opaque to the kernel; echoed in completion
}

pub struct BlockCompletion {
    pub tag:      u64,               // kernel-assigned; primary key for cancel
    pub user_tag: u64,               // echoed from the submission
    pub result:   Result<(), BlockError>,
    pub timing:   Option<IoTiming>,  // opt-in, via tracing/ FnTime equivalent
}
```

**Two tags, not one.** The submission carries a caller-set
`user_tag` (opaque correlation cookie) and receives a
kernel-assigned `tag` in the completion. The kernel's `tag` is
unique across all in-flight requests system-wide and is the
primary key for `cancel`. Without this split, two callers could
collide on the same `tag` and target each other's cancellations.

Zero-copy: `buffer` is a DMA buffer cap owned by the caller; the
driver DMAs directly into/out of it. `block/` is routing + scheduling,
not a copy stage.

### 3.3 I/O scheduler

Baseline algorithm: **deadline + fair-share**.

- Each request carries a `QosHint`. Latency-class requests get a
  short deadline (default 1 ms); throughput-class requests get a
  longer deadline (default 100 ms); background-class requests yield
  to the others.
- **Per-`Cap<BlockDevice>` rate limiting**, not per-task. Each cap
  carries a configurable token bucket (tokens-per-second, default
  unlimited). Revocation of the cap atomically removes its bucket
  from the scheduler's accounting table. Per-cap is correct because
  one task may hold multiple caps with different rates (e.g. a fast
  log device + a throttled scratch device).
- Priority inversion avoided by treating the highest-class pending
  request as the scheduler's head-of-line.

Deliberately simpler than Linux's mq-deadline/BFQ. Replaceable per
device via `BlockSchedulerPolicy` if a specific workload demands it.

### 3.4 Multi-queue dispatch

- A `BlockDevice` may expose N submission queues (typical: one per
  CPU for NVMe).
- `block/` places the scheduler upstream of the driver queues —
  request ordering happens per-device, dispatch happens per-queue.
- Consumers don't see queue multiplicity; they submit against the
  device, `block/` picks the queue (CPU-local preferred).

### 3.5 Registry lookup

```rust
pub fn find_block_device(name: &str) -> Option<Arc<dyn BlockDeviceSync>>;
pub fn find_block_device_indexed(
    name: &str,
) -> Option<(usize, Arc<dyn BlockDeviceSync>)>;
```

Registered GPT partitions carry their GPT type GUID, label, and unique GUID
plus a best-effort filesystem volume UUID parsed from immutable FAT or ext
identification bytes. `PartitionMetadata::is_efi_system_partition()` identifies
an EFI System Partition solely by its UEFI GPT type GUID, never by a volatile
device name, label, or volume UUID.
`DevFs` uses that metadata to expose `/dev/disk/by-{label,partuuid,uuid}`
aliases; discovery never validates or mounts the filesystem.

Targeted lookups clone only the matched device `Arc`; they do not allocate an
owned registry snapshot. The indexed form captures the registration-order index
and device under the same registry lock so `devfs` can derive a coherent Linux
minor number across concurrent hot-unplug.

## 4. Invariants & safety properties

- No byte of I/O data ever lives in `block/` address space; all
  payload movement is DMA between driver and consumer-owned buffer.
- Capability discipline: a consumer with `Cap<BlockDevice, Read>`
  cannot issue `Write` or `Discard` — the trait method is gated at
  the invocation surface.
- **Every `submit` / `flush` / `discard` resolves its
  `Cap<BlockDevice, _>` via `Cap::invoke` at dispatch time.** A
  device detach / hot-remove / admin revoke bumps the device's
  object epoch; outstanding caps return `Err(Revoked)` on their next
  operation. In-flight requests are fenced: the driver drops on-the-
  wire completions for submissions whose cap went stale during the
  trip. See `capabilities/` §3 for epoch mechanics.
- Flush ordering: a submitted flush completes only after every
  previously-submitted write on the same device has completed.
- Discard is advisory (blocks may or may not be zeroed on next read
  unless `WriteZeroes` is used); document this to callers.
- QoS hints are hints. The scheduler never misses a hard deadline
  because of a QoS reordering; it only reorders within the slack.
- **Submission and completion rings inherit `ipc/` §4 in full:**
  explicit release/acquire barrier pair on indices (matters on
  aarch64), cache-line partitioning, 2-bit wrap counter +
  AVAIL/USED flag, no silent completion drops.
- **Submission back-pressure: standard `ipc/` blocking-via-waker.**
  A consumer that submits faster than the device can absorb is
  blocked until queue space frees. Latency-class submissions are
  scheduled ahead of background-class ones within the slack but
  receive no exemption from back-pressure.
- **Cancellation:** dropping the Future returned by `submit` requests
  cancellation, not blind discard. The driver returns a definitive
  `Cancelled` completion; the DMA buffer is reclaimed only after
  that completion arrives. Dropping without waiting for the
  `Cancelled` is a leak (and a debug-build assertion).
  **The `block/` scheduler is responsible for injecting
  `BlockDevice::cancel(tag)` on behalf of a dropped Future** — the
  user side does not need to issue cancel explicitly; the scheduler
  notices the dropped wake-target and propagates. This closes the
  DMA-buffer UAF hazard at the layer where it can be enforced.

## 5. Architecture notes

Largely arch-neutral. Two points of contact:

- **Memory ordering of submission/completion indices** — release on
  submit, acquire on complete; drivers implement per arch.
- **Atomic 64-bit CAS** on request tag allocation — present on both
  primary archs.

## 6. Dependencies

- **Consumes:** `drivers/` (provides devices), `io/` (DMA buffers),
  `ipc/` (request Narf-Ring), `capabilities/`, `time/` (deadlines),
  `tracing/` (per-request timing via USDT), `scheduler/` (dispatch
  worker task), `rcu/` (device registry — many readers across
  filesystem and direct-block tools, rare writers on hot-plug).
- **Provides to:** `filesystem/` (primary consumer), any direct-block
  userspace tooling with an appropriate cap.

## 7. Stage assignment

| Stage | Lands                                                          |
| ----- | -------------------------------------------------------------- |
| 3     | Core `BlockDevice` trait + `cancel`, single-queue deadline scheduler, flush, virtio-blk backing, **composable device stacking via `stack(inner: Cap<BlockDevice, _>, transform: BlockTransform) -> Cap<BlockDevice, _>`** so `crypto/` can register encrypted-at-rest as the first transform without forcing a Stage 4 retrofit of `filesystem/`. |
| 4     | Multi-queue dispatch, discard/TRIM, write-zeroes, per-consumer fair-share, NVMe backing. |
| post-1.0 | Zoned block devices, atomic writes, write hints (stream IDs). |

## 8. Resolved decisions

### 8.1 Page-cache home (resolved)

**Decision:** **page cache lives in `filesystem/`**, not
`block/`. `block/` is a pure pass-through queue layer:
queue, dispatch, complete. Caching policy (read-ahead, dirty
write-back, eviction) is FS-specific and benefits from FS
metadata (which blocks are inodes vs data, which dirs are
hot).

`block/` does NOT cache; every read/write hits the device
unless the FS layer above intercepts. This keeps `block/`
simple and lets per-FS caching strategies coexist.

### 8.2 Request fairness (resolved)

**Decision:** **per-cap-chain fair share** with a fallback
to per-process when the cap chain is unidentifiable. The
queue scheduler tracks a "request origin" cap chain (provided
by the caller's `Cap<BlockDevice, Submit>` badge) and
applies weighted fair queueing across chains.

Default weights:
- Latency-sensitive (badge flag set): 4×.
- Default: 1×.
- Background (badge flag set): 0.25×.

Drivers receive requests in a single FIFO; the fairness is
above the driver. Per-driver fairness (one driver hogs a
device at the expense of another) is a separate concern
handled by `Cap<Quota, Spend>` (drivers spec §17.2).

### 8.3 Barrier semantics (resolved)

**Decision:** **`flush` is sufficient; no explicit barriers**.
Modern devices (NVMe, virtio-blk) provide flush + write-back
caching that satisfies POSIX `fsync` semantics. NARF's block
layer exposes:

```rust
pub enum BlockOp {
    Read   { lba: u64, n: u16, buf: Cap<DmaBuffer, Write> },
    Write  { lba: u64, n: u16, buf: Cap<DmaBuffer, Read> },
    Flush,                            // wait for prior writes durable
    Discard{ lba: u64, n: u32 },     // TRIM/UNMAP
}
```

`Flush` is ordered: it completes after all prior `Write`s on
the same queue have hit durable media. This is the only
ordering guarantee at the block layer; FS layers compose
their own crash-consistency around `Flush`.

### 8.4 Encryption-at-rest placement (resolved)

**Decision:** **between `filesystem/` and `block/`** (per-file
or per-FS encryption), not at the device level.

`crypto/` exposes `Cap<Key<Aes256Gcm>, Use>`; the FS layer
encrypts payloads before submitting to `block/`. Full-device
encryption is a special case where the FS layer treats every
block uniformly, and is configured at mount time.

This placement lets:
- Per-file encryption (different keys per directory tree).
- Cross-device encryption survival (data on one device
  decrypts the same way on another).
- Driver-side simplicity (no crypto in driver code).

The minor cost is the FS pays the encrypt/decrypt overhead;
acceptable for v1.0. AES-NI / Crypto Extensions on modern
silicon makes it cheap.

### 8.5 Hot-remove handling (resolved)

**Decision:** **fail-fast all in-flight I/O on hot-remove**,
no live migration in v1.0.

When `bus/` signals `BusEvent::Removed` for a block device:
1. Driver's `Driver::quiesce()` runs — driver stops issuing
   new ops, waits for hardware to drain or times out.
2. `block/` revokes the device's `Cap<BlockDevice, _>`; all
   in-flight requests complete with `Err(DeviceRemoved)`.
3. FS layer above receives the errors and propagates them
   (typically as `EIO`).

Live migration (transfer in-flight requests to a different
device) is Stage 5+ work — requires multi-device replication
that's an FS concern, not a block-layer one.

## 9. ABI versioning

`block/` exports through SDK at `@v0`:

- `BlockOp` enum.
- `BlockDeviceSync` and `BlockDeviceAsync` traits (drivers
  implement; FS layers consume).
- `Cap<BlockDevice, _>` and badging (priority hints).

`BLOCK_ABI_MAJOR = 1`, `BLOCK_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
