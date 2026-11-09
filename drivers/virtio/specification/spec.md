# drivers/virtio — Specification

> Status: **v1.0** (Stage 3 design lock). v0.1 outlined the
> shared transport + per-device drivers; v1.0 locks the
> ring-format choice (split-only at v1.0, packed at v1.1+),
> the console-backend strategy, and the multi-queue sizing
> policy.

## 1. Purpose & scope

**Owns:** VirtIO device discovery (PCI + MMIO transports), feature
negotiation, virtqueue handling (split + packed), device-class glue to
blk/net/console/rng.

**Does NOT own:** Block-storage or network protocol stacks above VirtIO
(those belong to higher-level drivers/stacks).

## 2. Assumptions

- `io/` can allocate DMA buffers bound to this driver's IOMMU context.
- `interrupts/` can register an MSI/MSI-X or UIPI handler.
- `ipc/` provides Narf-Rings as the transport to whoever consumes block /
  network / console bytes. The virtio-mem class owns queue-0
  PLUG/UNPLUG/STATE transactions and continuously converges allocator-online
  blocks to the generation-stable `requested_size`.

## 3. Public interface

The PCI transport maps common configuration, notification, ISR and device
configuration BARs once through `bus::map_bar_control`, with Device attributes
even when the BAR is prefetchable. Each capability uses the returned BAR VA
directly; repeated capabilities and MSI-X table accesses share the same typed
mapping. Mapping conflicts return `VirtioPciError::BarMapFailed` without a
physical-address fallback. Shared-memory capabilities retain their separate
memory-window ownership and do not use this control-register path.

- Inbound: capability-gated `start(config: VirtioConfig)`. Before
  `start` is called, the framework invokes
  `negotiate(offered: FeatureSet) -> Result<FeatureSet, NegotiateError>`.
  The returned set is **immutable for the driver's lifetime** — no
  re-negotiation. This makes the negotiated state observable at a
  single point and removes a class of "feature appeared/disappeared
  mid-flight" bugs.
- Outbound: per device, **N Narf-Ring handles where N =
  min(negotiated_queue_count, cpu_count)**. Single-queue
  multiplexing was the original wording; that throws away virtio's
  native parallelism the moment we touch real hardware. `class_blk`
  and `class_net` modules consume the per-queue rings and present
  the unified block/net subsystem interfaces.
- Virtio-net gives each RX/TX queue pair its own bounded, prefilled DMA
  recycler. RX refill and TX completion use only that pair's recycler; a
  zero-copy TX frame records its selected pair before its buffer is acquired.
  No packet/completion path reaches the general allocator or an interface-wide
  recycler shared by independent queues.
- The primary virtio-net interface advertises TX checksum offload only after
  negotiating `VIRTIO_NET_F_CSUM`, and IPv4/TCP TSO only after additionally
  negotiating `VIRTIO_NET_F_HOST_TSO4`. A requested offload that was not
  negotiated, is malformed, or exceeds the bounded
  64-KiB TX DMA frame is rejected before descriptor publication. A requested
  VLAN insertion is performed in software at copy time instead: the tag bytes
  are inserted after the MAC addresses (the virtio-net header has no VLAN
  field), the zero-copy path falls back to a copy for tagged frames, and the
  checksum/TSO header layout is VLAN-aware so tagged offloads compose. The
  driver negotiates `VIRTIO_NET_F_CTRL_RX` and `VIRTIO_NET_F_CTRL_VLAN` when
  offered and exposes `VIRTIO_NET_CTRL_MAC_TABLE_SET` plus
  `VIRTIO_NET_CTRL_VLAN_ADD` / `VLAN_DEL` through the control queue; the
  device filters incoming tagged frames to the programmed VLAN table, and
  matching frames arrive with the tag intact for the stack to parse (RX
  stripping stays OFF per the net spec). The driver also negotiates
  `VIRTIO_NET_F_GUEST_ANNOUNCE` when offered: on a config-change interrupt
  that raises `VIRTIO_NET_S_ANNOUNCE` it sends a gratuitous ARP for the
  interface's primary IPv4 address and acks with
  `VIRTIO_NET_CTRL_ANNOUNCE_ACK`; the IPv6 unsolicited-NA half has no stack
  emit surface yet (issue #1536). The driver
  honors the frame-ring `TxMeta::more` batching hint while checking for a notify
  at an exhausted TX buffer pool, a full TX ring, or an explicit flush boundary.
  Copy-path TX buffer acquisition reclaims completed descriptors before
  reporting an empty pool, allowing the stack's copy fallback to recover even
  after its zero-copy pool is exhausted.
- The primary virtio-net interface opts into the kernel stack's
  per-interface software GRO stage. Every RX forwarder of the primary
  controller feeds GRO through the synchronous tap and flushes the current
  CPU's held flows after its queue drains and before it parks, so
  MQ-spread flows coalesce on every pair; secondary frame-ring-only
  interfaces neither offer to GRO nor flush, and do not alter the
  kernel-stack setting.
- virtio-gpu exposes `offered_features()`, `host_offers_virgl()`, and
  `virgl_enabled()`. The first two report the pre-negotiation host offer;
  `virgl_enabled()` is true only after immutable negotiation accepts
  `VIRTIO_GPU_F_VIRGL`. When enabled, the transport provides typed controlQ
  operations for context creation/destruction, resource attachment, 3D
  resource creation, and bounded `SUBMIT_3D` command streams. Fenced submits
  use a bounded four-slot controlQ pipeline with private coherent staging and
  return a shared per-submission completion object. Completion is tracked per
  fence, not by a device-global id watermark, because native-context rings may
  retire out of global order. Synchronous commands and fence reaping share one
  request gate and route every used entry back to its descriptor chain. The
  async fence-wait surface arms the controlQ MSI-X vector before its final
  completion probe, then parks the caller until that vector fires; if MSI-X
  cannot be configured it uses a bounded timer poll rather than a busy loop.
  The caller reaps the used ring after each wake, so hard IRQ context performs
  only generic wake delivery. The DRM render-node bridge owns per-open
  resource lifetime and validates all
  user-provided command sizes before it calls this surface. Resource and blob
  creation accept a bounded `MemEntry` scatter/gather list, matching Linux's
  shmem scatterlist translation; callers retain every segment until detach +
  unref completes. Context attach/detach and resource unref are separate
  operations so PRIME-imported resources can be shared across DRM opens, and
  an imported 3D resource can be placed directly on scanout with
  `SET_SCANOUT` + `RESOURCE_FLUSH`. A 2D-only host remains supported with the
  feature clear.
- Virtio block request futures register the caller's waker in their in-flight
  request slot and completion wakes it after removing the request from the
  used ring. Unsupported/no-op flush, discard, and cancel paths resolve
  immediately rather than returning a permanently pending future.
- The virtio-blk-pci sync driver negotiates VIRTIO_BLK_F_FLUSH when the
  device offers it and drains the device write cache with a T_FLUSH
  request; its `BlockDeviceSync::capabilities` reports `volatile_cache`
  exactly when flush was negotiated, so the SyncBlock Flush/Fua
  advertisement is honest (#841). A device that does not offer flush is
  treated as write-through, and a non-S_OK flush status surfaces as an
  error rather than silent success.
  `BlockDeviceSync::capacity` reads the mandatory device configuration's
  64-bit capacity in 512-byte sectors, bracketing the two word reads with
  `config_generation` to avoid torn resize snapshots. Missing/truncated
  configuration refuses probe; an unprobed controller or a configuration
  that changes throughout eight bounded samples reports unknown capacity
  (`0`). Filesystem adapters receive this capacity through `SyncBlock`.
  `VirtioBlkPci::write_sectors(sector, data)` accepts a nonempty, sector-aligned
  payload of up to `u16::MAX` sectors and sends it as one descriptor chain,
  retaining one contiguous DMA allocation through terminal completion. The
  sync adapter accepts multi-sector writes, validates buffer length and range
  overflow, and treats zero-sector writes as no-ops. It does not split a
  Btrfs metadata node into independent sector writes; `write_sector` delegates
  to the same request path.
- VirtIO sound PCI queries PCM_INFO for every stream and registers the
  first viable output stream as playback device 0 and, when the device
  reports one, the first viable input stream as capture device 0 with
  `drivers/sound`, including the actual PCI parent. "Viable" means S16
  plus 44.1/48 kHz plus sane channel bounds; later streams of the same
  direction are not exposed. `PcmDevice::capabilities` derives its
  format/rate/channel sets from the direction's PCM_INFO and supplies
  period/buffer bounds to side-effect-free ALSA negotiation. Each PCM
  lease supports the advertised subset of S16LE mono/stereo at 44.1/48
  kHz, configuration, prepare/start/stop, cumulative frame position,
  and drain; playback additionally supports writes, capture
  additionally supports reads, and the other direction's operation
  fails closed (playback `read` and capture `write` return BadState).
  Other opens and kernel convenience submits cannot bypass an active
  lease. MIDI is not advertised. Playback copies into coherent
  controller-owned scratch and splits long writes at whole-frame
  boundaries; the 4024-byte payload area ends before the completion
  status. Capture pre-posts empty period buffers on a 32-entry rx
  queue (10 three-descriptor messages) and reports each completion's
  recorded frames from the used-ring length minus the 8-byte status.
  Configuration changes issue STOP/RELEASE before SET_PARAMS/PREPARE/
  START; a merely-prepared stream takes RELEASE alone. Timeout poisons
  the controller and requires acknowledged reset before caller-owned
  DMA storage can be freed; unacknowledged reset is fatal rather than
  returning live DMA to an allocator.
- VirtIO sound services its event queue lazily, on every PCM pointer
  read and every control read: there is no pump task and no MSI-X on
  this driver, so polling at those points is the service model. Jack
  connect/disconnect events update per-jack state exposed as JackSense
  controls (seeded from JACK_INFO at probe); PCM period/xrun and
  control-notify events are consumed and reposted, and unknown or
  malformed events are dropped without touching state. Control
  elements exist only under the control-element extension (absent from
  VirtIO 1.2, verified against 1.4 §5.14.6.10): the driver negotiates
  VIRTIO_SND_F_CTLS only when the device offers it and reads the
  `controls` config field only then. Reported elements map role-first
  onto mixer kinds (output volume → MasterVolume, input volume →
  CaptureVolume, output mute → MasterMute, input gain → MicBoost);
  elements with no mixer kind (input mute, output gain, undefined
  role), unmapped types (INTEGER64, ENUMERATED, BYTES, IEC958), and
  uncarryable shapes (INTEGER with more than 2 members, BOOLEAN with
  more than 1) stay unadvertised rather than mislabeled. Control reads
  always round-trip live; control writes range-check against the
  device's own bounds. TLV metadata and enumerated item names are not
  surfaced. A device without CTL support still probes and plays (and
  captures, when it has an input stream) with an empty control list.

Internal modules: `transport_pci`, `transport_mmio`, `queue_split`,
`queue_packed`, `class_blk`, `class_net`, `class_console`.

The native sound lease preserves pending packets and completed frame count
across pause/resume, clears pending application data on RESET, and permits
ALSA silence/boundary playback through the common PCM bridge. Rewrites affect
unsubmitted packets; completed packets retain their completed ownership.

## 4. Invariants & safety properties

- The driver never touches memory outside its DMA buffers + MMIO window +
  its own domain.
- Feature negotiation always terminates; unknown bits are cleared.
- Virtqueue descriptor rings are validated on every wake (bounds,
  generation, indirect depth cap).
- A virtio-mem block enters the frame allocator only after host PLUG/STATE
  acknowledgement and kernel-linear-map validation. Unplug first proves the
  exact block free; device rejection transactionally restores it. Busy blocks
  remain online and are never force-reclaimed.

## 5. Architecture notes

### x86_64
- PCI MSI-X for IRQs; MMIO BAR for legacy.
### aarch64
- Discovered via devicetree (MMIO transport) under QEMU virt; PCI when
  the platform provides ECAM.

## 6. Dependencies

- **Consumes:** `drivers/` (framework), `io/`, `ipc/`, `interrupts/`,
  `capabilities/`, `memory/`, `arch/`.
- **Provides to:** `drivers/net/` (once virtio-net is used as base),
  future block paths, console fallback.

## 7. Stage assignment

Stage 3 — *the* Stage 3 milestone driver.

## 8. Resolved decisions

### 8.1 Ring format (resolved)

**Decision:** **split-only at v1.0; packed-ring support
at v1.1+**. The split-virtqueue format is universally
supported by every virtio device QEMU emits and is what
existing NARF code uses. Packed-ring is a 30-50%
throughput win on hot paths and lands as a separate driver
SDK feature in v1.1.

`narf-drivers-virtio` v1 enables only split via VIRTIO_F_RING_PACKED
NOT being negotiated; v1.1 will add the negotiation path.

### 8.2 virtio-console as console backend (resolved)

**Decision:** **virtio-console is an additive sink, not a
replacement** (per `console/spec` §8.2). The 16550A (x86_64)
or PL011 (aarch64) UART remains primary; virtio-console
mirrors output when the device is probed, providing a
clean log surface for VM environments.

This means NARF runs on bare metal without virtio-console
and inside QEMU with both — no fork in the console path.

### 8.3 Multi-queue sizing (resolved)

**Decision:** **CPU-count based with caps**. virtio-net,
virtio-blk allocate `min(cpu_count, max_supported_by_device)`
queues at probe time, one per CPU. Devices with smaller
hardware ceilings (e.g. virtio-blk-pci defaulting to 1
virtqueue) fall back to single-queue + IRQ steering.

Stage 4 work: per-driver tunable to override the
auto-sizing for fast-path workloads (`net/spec` §8.4).

## 9. ABI versioning

`narf-drivers-virtio`'s public surface (the per-device-class
match tables, the `enable_msix_for_probed` shape, the
shared transport helpers used by other virtio drivers) are
re-exported through SDK at `@v0`.

`VIRTIO_DRIVER_ABI_MAJOR = 1`, `VIRTIO_DRIVER_ABI_MINOR = 1`.
Adding a new device-class driver under `drivers/virtio/`
is a minor bump (registers a new match-table entry; doesn't
break existing).

## 10. Open questions

(none — all v0.1 questions resolved in §8)
