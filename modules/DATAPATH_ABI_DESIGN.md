# Device-datapath C-ABI — design

Status: **Stages 0–4 implemented (copy-mode e1000 reference)**. Owner: driver
dual-build effort.

## Problem

The original loadable-driver path could register a PCI match through
`narf_register_pci_driver`, but could not bring up or drive the device because
PCI config, BAR/MMIO, DMA, MSI-X/IRQ, polling, and subsystem registration were
Rust-ABI only. The staged C ABI below closes that gap for a copy-mode network
driver; e1000 is the reference implementation. Block registration and
zero-copy/IOMMU-backed module mappings remain later extensions.

See `modules/src/kabi.rs` for the existing (deliberately tiny) export surface
and its CRC/`kernel_abi`-hash versioning; this is a large, deliberate addition
to it.

## Non-goals (for the first slice)

- Zero-copy DMA into the module's own address space (frame payloads copied
  through kernel-domain accessors first; zero-copy is a later optimization).
- A general IOMMU per-domain mapping story (the IOMMU is identity-mode today —
  `io/src/iommu.rs`).
- Hot-unplug / surprise-removal of a module-driven device.
- Non-PCI buses (I²C/SPI/platform) — separate per-bus registration exports,
  out of scope here. USB has both halves: registration
  (`narf_register_usb_driver`) and the transfer datapath below
  ([USB transfer datapath](#usb-transfer-datapath)).

## The core constraint

From the primitive inventory, every rich kernel object a driver touches is
`repr(Rust)` and most of the execution primitives are `Future`-based:

| Primitive | Why it can't cross C-ABI as-is |
|---|---|
| `Cap<BusDeviceCap, Write>` | `repr(Rust)`; the module trampoline retains it only in a kernel-owned device context |
| `MmioRegion` (`bus/src/bar.rs`) | `repr(Rust)`; and its VA is a kernel mapping the module's PKS domain can't touch |
| `DmaBuffer` (`io/src/lib.rs`) | `repr(Rust)`; `cpu_ptr()` is a kernel direct-map pointer (but `dma_addr().raw()` is a plain `u64`) |
| `MsixTable` / `MsixVector` | `repr(Rust)` (private fields) |
| `spawn*` (`scheduler`) | all take `impl Future` — a `.ko` can only hand over an `extern "C" fn` |
| `wait_for_irq` | returns a `Future` — same problem; but the sync `SyncHandler = fn(u64) -> IrqStatus` path IS C-compatible |
| `iface::register` / `registry().register` | `SendFn`/`TxMeta`/`Interface` are `repr(Rust)`/trait objects |
| domain enter/exit | PKS/MTE-specific `repr(Rust)` scope guards |

## Architecture: handle table + callback trampolines

One pattern resolves all of the above — effectively an in-kernel "syscall"
interface for modules:

1. **The kernel keeps every rich object; the module holds only opaque `u64`
   handles.** On probe, the kernel mints a **device context** keyed by the
   device token, holding the `Cap<BusDeviceCap, Write>`, mapped BARs, DMA
   buffers, the MSI-X table, and the registered interface. Each resource the
   module creates (map a BAR, alloc DMA, claim a vector) returns a `u64`
   handle into that context. The module never sees a Rust object or a kernel
   pointer.

2. **Every module→kernel call is a C-ABI export** that takes a handle (+ the
   device token for cap lookup), **re-validates the stored cap**
   (`Cap::invoke()`), performs the op through the **kernel** bridge, and returns
   a primitive / errno. MMIO reads/writes, DMA descriptor access, config
   access, MSI-X programming, and netif RX all go through these.

3. **Every kernel→module call is a trampoline** that pins a Live module,
   enters its effective domain (`domain::enter`), calls the module's
   `extern "C"` callback, and exits. Hard IRQ handlers never execute module
   text: they account/wake in FRAME and an in-tree task performs the upcall.
   The module supplies callbacks for probe, deferred IRQ work, netif TX, and
   the background poll loop.

4. **The in-tree shim owns all `Future`s.** Because `spawn*`/`wait_for_irq` are
   `Future`-based and a `.ko` cannot produce a `Future`, a small in-tree shim
   owns the async task: it `await`s the IRQ/timer and then calls the module's
   `extern "C"` poll callback (trampolined into the module domain). The module
   is pure synchronous `extern "C"` code; the async machinery stays in-tree.

This makes the module boundary a narrow, auditable set of C functions +
callbacks, with the cap checked on every op and the PKS domain entered on every
upcall — the isolation model the module system already established holds.

### Handle / context model

```
DeviceCtx (kernel-side, keyed by dev_token):
    owner:      ModuleId                     // resolves effective load-time domain
    cap:        Cap<BusDeviceCap, Write>   // from probe; validated on every op
    device:     BusDevice
    bars:       Vec<MmioRegion>            // 1-based handle -> mapped BAR
    dmabufs:    Vec<Option<Cap<DmaBuffer, Write>>> // monotonic handle -> buffer
    msix:       Option<MsixTable>
    iface:      Option<(name, ifindex, tx_callback)> // legacy stack entry; cap-gated ABI
    irq_cbs:    Vec<(vector, extern "C" fn(u64) -> i32, cookie)>
    poll_cb:    Option<(extern "C" fn(u64) -> i32, cookie)>
```

Handles are indices into per-context tables (not raw pointers). DMA slots are
never reused during a context's lifetime, so a freed handle remains stale
instead of aliasing a later allocation; stale/forged handles return `-EINVAL`,
never a wild dereference. Context + all resources are torn down on module
unload (see Lifetime).

## Export surface (staged)

All `extern "C"`, all errno-returning `i32` (or `u64` handle, `0` = invalid),
added to the `kernel_abi!{}` block. `dev` = device token the probe received.

**Stage 1 — PCI + MMIO**
```
narf_pci_prepare_probe(dev) -> i32                 // park inherited DMA/decode, checked D0 entry
narf_pci_enable(dev, cmd_bits: u16) -> i32          // set/readback Command, cap-checked
narf_bar_map(dev, bar_idx: u8) -> u64               // -> mmio handle (0 = fail)
narf_mmio_read32(dev, mmio: u64, off: u64, out: *mut u32) -> i32
narf_mmio_write32(dev, mmio: u64, off: u64, val: u32) -> i32
narf_mmio_wait32(dev, mmio: u64, off: u64, mask: u32, expected: u32, timeout_ns: u64) -> i32
```

`narf_pci_prepare_probe` is for a fresh, exclusively executing probe token,
before mapping BARs or allocating DMA/MSI-X/pollers/interfaces. It refuses
existing resources (`-EBUSY`) and resolves the caller's exact device authority;
the D0 wait holds no context spinlock. It leaves BME and memory decode off and
INTx disabled. The module enables memory for setup, then BME only after owning
and programming every DMA ring. PCIe No Snoop Enable is cleared/readback for
cached coherent DMA; unrelated controls and RW1C Device Status are preserved.
`narf_pci_enable` returns `-EIO` when configuration disappears or requested bits
do not latch. Preparation is not a DMA completion or teardown fence.

The first ABI intentionally exports only the 32-bit MMIO width needed by
e1000. PCI configuration reads and additional MMIO widths are not part of the
implemented contract; they should be added only with a concrete driver and
their own ABI review.

**Stage 2 — DMA**
```
narf_dma_alloc(dev, len: usize) -> u64              // -> dma handle; allocated in the device's domain
narf_dma_addr(dev, dma: u64, off: u64, out: *mut u64) -> i32   // device-visible address for descriptors
narf_dma_write(dev, dma: u64, off: u64, src: *const u8, len: usize) -> i32  // kernel-domain memcpy in
narf_dma_read(dev, dma: u64, off: u64, dst: *mut u8, len: usize) -> i32     // kernel-domain memcpy out
narf_dma_wait8(dev, dma: u64, off: u64, mask: u8, expected: u8, timeout_ns: u64) -> i32
narf_dma_free(dev, dma: u64) -> i32
```

**Stage 3 — MSI-X / IRQ + poller**
```
narf_msix_enable(dev) -> i32
narf_msix_claim(dev, out_vector: *mut u16) -> i32   // alloc + program a vector to a kernel-alloc'd IDT slot
narf_irq_set_handler(dev, vector: u16, cb: usize, cookie: u64) -> i32
narf_spawn_poller(dev, cb: usize, cookie: u64) -> i32
  // in-tree shim spawns a Future that waits on the device's IRQ/a tick and calls cb (trampolined)
  // cb is the address of extern "C" fn(u64) -> i32; non-zero retires the pump
```

**Stage 4 — netif registration + the e1000.ko proof**
```
narf_netif_register(dev, mac: *const u8 /*6*/, tx_cb: extern "C" fn(frame: *const u8, len: usize) -> i32, out_ifindex: *mut u32) -> i32
narf_netif_register_with_context(dev, mac: *const u8 /*6*/, tx_cb: extern "C" fn(dev: u64, frame: *const u8, len: usize) -> i32, out_ifindex: *mut u32) -> i32
narf_netif_rx(dev, ifindex: u32, frame: *mut u8, len: usize) -> i32  // synchronous stack delivery; XDP may rewrite
```
The kernel registers a legacy-stack interface with a permanent in-tree
`SendCtxFn` trampoline; the unloadable callback address remains only in the
owner/device context. The module's TX callback receives borrowed frame bytes
and copies them into its DMA buffer; its poll/IRQ callback drains the RX ring
and calls `narf_netif_rx`. The KABI imports are link-time gated by
`NetIface:Write`, and every runtime operation revalidates the retained device
capability.

Rough surface: ~20 exports. Each adds a CRC entry and moves the
`kernel_abi` hash once (modules are already hash-gated, so this is expected);
`nm -u` gate + `clippy --module-config` already cover the `.ko` side.

## Framekernel: end-user frame/domain placement at load time

NARF is a framekernel: a minimal Ring-0 TCB (`DomainId::FRAME = 0`, the *frame*)
plus hardware-isolated domains (`DRIVER_0..`, `SCRATCH`, …). A loadable driver is
a service that lives **outside** the TCB, confined to a domain. The datapath ABI
above is precisely the frame boundary for that service — so this design must get
the *placement* decision right, not just the mechanics.

**Principle: the module author does not choose their own isolation; the end
user does.** Before this work the loader took the domain solely from the
module's own `target_domain=` modinfo. The implemented policy is:

- `target_domain=` becomes an **author hint / request**, not the authority.
- `init_module` accepts an **end-user domain selector at load time** (via a
  module param, e.g. `domain=driver2`, or a dedicated loader argument/policy),
  which **overrides** the manifest hint. The person running the kernel decides
  how much to isolate a module they didn't write.
- The effective domain is **clamped by policy**: a module can **never** be
  placed in `FRAME` (the TCB) — that is the invariant the framekernel rests on.
  A future signature/policy table may further restrict which non-FRAME domains
  a given signer may request.
- This stacks with the existing `required_caps` gating (also requests the
  loader grants or denies): the user controls both **where** a module runs
  (domain = isolation) and **what** it may do (caps = capability envelope).

The datapath ABI honors this automatically: each device context records its
owner `ModuleId`; every upcall resolves that owner's effective load-time domain
and enters it, while `narf_dma_alloc` takes the active domain from that gated
call context. Thus the selected placement flows through MMIO/DMA/IRQ/poll/TX
without trusting a module-supplied domain value.

Built-in drivers never consume the loader parameter. Their code placement and
resource domains are compile-time choices; the built-in e1000 path, for
example, assigns its coherent rings to `DomainId::DRIVER_0` statically.

Net effect: *even if someone else wrote the module, the end user chooses how it
is loaded* — which domain it is isolated in, and which capabilities (and thus
which parts of this ABI) it may use.

## Cap threading

`module_probe_trampoline` **stores** the `Cap<BusDeviceCap, Write>` in the
device context keyed by `dev_token` before calling the module's probe, and
removes it when the module unloads. Every device export looks the context
up by `dev` and invokes an operation through the retained cap before touching hardware — so a
module can only drive a device it was actually probed for, and only while its
cap is live.

## DMA safety (the load-bearing decision)

`alloc_coherent` draws from the flat buddy allocator (not a domain-tagged
heap) with the IOMMU in identity mode, and `DmaBuffer::cpu_ptr()` is a kernel
direct-map pointer. Module scope narrows PKS/PCID to the module's own domain
**plus the kernel's** (`modules/DESIGN.md`, "What this does NOT do"), and the
direct map is the kernel's, so a module's domain can in fact reach that
pointer; what a module lacks without an export is the pointer itself, and a
lifetime contract for it. Three options:

- **(A) Kernel-domain accessors (recommended for the slice).** The module never
  touches DMA memory directly; it builds descriptors and moves frame bytes via
  `narf_dma_write`/`narf_dma_read` (kernel-domain memcpy, cap-checked). PKS
  isolation is fully preserved; cost is one memcpy per packet (same as a
  copy-mode driver). Simplest to get right.
- **(B) Map DMA pages into the module domain.** Zero-copy, but relaxes PKS for
  those pages and, without a per-domain IOMMU, gives the device (and the
  module) broad physical reach. Defer until there's a per-domain IOMMU story.
- **(C) Bounce via the iface DMA pool.** Only helps net.

Recommendation (first slice): ship **(A)**; note (B) as a perf follow-up gated
on IOMMU per-domain mapping.

**(B) landed for ring-walking drivers** as `narf_dma_alloc_mapped` (see "PCI
identity, plain MSI and mapped DMA" below), alongside (A). Its justification is
the reachability fact above, not a per-domain mapping: the pointer grants no
access the module's domain did not already have, and the export is the
contract that a later per-domain DMA keying (with the IOMMU story) narrows. A
driver with tens of descriptor rings and multi-megabyte link-descriptor banks
(ath11k) cannot afford one cap-checked export call per descriptor word.

## Lifetime / unload (prerequisite)

Driving hardware from a module makes unload load-bearing: on `rmmod` the kernel
must quiesce the device (disable bus-master + MSI-X), stop the poller, drop the
registered interface, free DMA buffers, release BAR handles, and remove the
match + thunk from the bus registry — **before** the module's text is unmapped,
or an IRQ/poll/TX callback would call into freed code. Stage 0 now wires
owner-attributed match/context removal into `delete_module` and clears PCI
command bits enabled through the context. The underlying `ioremap` remains in
the bus-wide mapping cache, whose entries are shared and not reference-counted;
tearing it down per module would invalidate other users of the same BAR.

## Staging & proof

1. **Stage 0 — loader groundwork** (**implemented**):
   (a) device-context table + deregistration wired into `delete_module`
   (teardown before text unmap); (b) **end-user load-time domain placement** —
   `init_module` honors a user-supplied `domain=` selector that overrides the
   manifest `target_domain` hint, clamped so a module can never land in `FRAME`.
   Both are module-system changes independent of
   the ABI surface and gate the framekernel placement story.
2. **Stage 1 — PCI + MMIO** exports (**implemented**); cap stored in the context. Smoke: a `.ko`
   maps BAR0 and reads the e1000 device-status register.
3. **Stage 2 — DMA** exports (**implemented**). Smoke: the e1000 `.ko` allocates
   a coherent buffer in its operator-selected domain, writes a descriptor-shaped
   pattern, reads it back, resolves the device address, proves stale-handle
   rejection after free. The Stage-4 path then retains both rings and all
   per-descriptor buffers for unload cleanup.
4. **Stage 3 — MSI-X/IRQ + poller** (**implemented**). MSI-X-capable devices
   retain the table, allocate/program kernel vectors, and install a FRAME-only
   accounting handler; a timeout-bounded executor pump observes `fire_count`
   and invokes the module through its domain/lifecycle gate. QEMU's legacy
   82540EM may lack MSI-X, so the e1000 `.ko` also registers a recurring 1-ms
   poller; the smoke drives executor rounds and observes callbacks firing in
   the operator-selected domain.
5. **Stage 4 — netif + e1000.ko e2e** (**implemented**). The module resets the
   QEMU 82540EM, programs persistent copy-mode rings, registers an unload-safe
   interface, and transmits an ARP request through a real hardware descriptor
   completion. Because the normal kernel-test boot already owns the same NIC
   with the built-in driver, the RX half injects a device-shaped completion
   into the module-owned coherent ring and proves copy-out, gated stack
   ingress, callback scheduling, and descriptor rearm deterministically.
   `cargo xtask e1000-module-net-smoke --arch=x86_64` supplies the exclusive
   proof: it suppresses the built-in claimant, ABI-stamps and initramfs-loads
   `e1000.ko` before PCI probing with `modules_domain=driver2`, then carries
   live host-forwarded TCP and UDP exchanges plus a guest DNS query over the
   module-owned 82540EM. e1000 stays built-in by default; the `.ko` path is the
   reference ABI proof.

Each stage is independently reviewable and testable; we stop/reassess after any.

## Risks / open questions

- **Security surface.** ~20 exports giving a module DMA/MMIO/IRQ. Mitigated by:
  cap-checked every op, handle-table bounds checks, PKS-domain trampolines on
  every upcall, and (A)'s no-direct-DMA-access stance. Still the most
  sensitive ABI in the tree — wants careful review per export.
- **IRQ callback latency.** Resolved in favour of safety: module text never
  runs in hard-IRQ context. The in-tree handler advances `fire_count` and wakes
  a task-context pump. The pump's 10-ms timeout is only a teardown/missed-wake
  backstop; normal delivery is waker-driven.
- **ABI churn.** ~20 new CRC entries; every signature is a promise. Keep them
  primitive-only (handles + pointers + lengths), never a `repr(Rust)` type.
- **Beyond the reference consumer.** e1000 (net), ftdi (USB) and nvme
  (block) are the implemented runtime-load consumers. Other dual-build
  drivers should add exports only as their concrete datapaths require them
  rather than widening this ABI speculatively.
- **Perf.** Copy-mode DMA (A) is fine for bring-up/bulk-NIC but not for a
  high-rate datapath; (B) is the eventual answer and needs the IOMMU work.

## PCI identity, plain MSI and mapped DMA

Status: **implemented**; ath11k (WCN6855) is the first consumer. The
additive exports, all primitive-only:

```text
narf_pci_identity(dev:u64, out:*mut u8, len:usize)->i32
narf_msi_enable(dev:u64, want:u16, out_count:*mut u16, out_base_vector:*mut u16, out_addr:*mut u64, out_data:*mut u32)->i32
narf_msi_set_enabled(dev:u64, enabled:u32)->i32
narf_pcie_aspm(dev:u64, aspmc:u16, out_prev:*mut u16)->i32
narf_dma_alloc_mapped(dev:u64, len:usize, addr_bits:u32, out_cpu:*mut usize, out_bus:*mut u64, out_len:*mut usize)->u64
```

- **Identity** is a fixed 16-byte little-endian record (vendor, device,
  subsystem vendor/device, revision, 24-bit class, segment, bus, devfn).
  Board-data names and calibration files key on it, and a driver that
  registers one probe for several device ids learns which one it got.
- **Plain MSI** programs exactly `want` vectors (a power of two, ≤ 32) as
  one aligned kernel block, leaves delivery disabled and returns the block's
  first vector with the Message Address and vector 0's Message Data — a
  device that programs its own interrupt sources (ath11k writes `addr` and
  `data + i` into SRNG/CE registers) needs both. A smaller grant is a
  different interrupt layout, so it is refused with `-ENOSPC` and the module
  asks again with fewer. Each vector takes `narf_irq_set_handler` like an
  MSI-X claim; the hard handler is the same accounting stub. MSI and MSI-X are
  exclusive per context (`-EBUSY`). Teardown clears MSI Enable before
  detaching handlers and freeing the block.
- **ASPM** writes only Link Control bits 1:0 and returns the previous field;
  there is still no general config-space write.
- **Mapped DMA** is `narf_dma_alloc` under an address limit with the CPU
  mapping returned (see "DMA safety"). Handles share the `narf_dma_*`
  namespace and are still never reused, so a driver that allocates per packet
  pools large mapped buffers itself.

Runtime services added with them, not tied to a device:

```text
narf_udelay(ns:u64)->i32                                   // 1 ns..=1 s, sleep pumps keep ticking
narf_random_bytes(buf:*mut u8, len:usize)->i32             // ≤ 4096; -EAGAIN when no healthy source
narf_smbios_read(off:usize, buf:*mut u8, len:usize, out_total:*mut usize)->i32
narf_firmware_signed(handle:u64)->i32                      // 1 signed / 0 unsigned
narf_module_param(name:*const u8, name_len:usize, out:*mut u8, cap:usize, out_len:*mut usize)->i32
```

`narf_module_param` serves the module's `.narf_kparams` slots after the loader
applied `<module>.<param>=` from the kernel command line and then the load's
own arguments (`modules/MODULE_AUTHORING.md`, "Module parameters").

## Wireless copy-mode host services

The wireless extension uses permanent family host adapters. The loadable
frontend owns its PCI probe, opaque service/control operations and poller;
the native MCU/WFDMA engine stays in the host. This explicitly differs from
relocating that hardware engine into the module image. Real kernel netdev and
wiphy publication occurs only after that engine's firmware/identity admission.
Bus holds registration-neutral hooks and opaque ids, so it has no dependency
on wireless or firmware Rust objects.

The additive C exports are:

```text
narf_wireless_open(dev:u64, family:u32, version:u32, out_session:*mut u64)->i32
narf_wireless_open_with_event(dev:u64, family:u32, version:u32, event_callback:usize, out_session:*mut u64)->i32
narf_wireless_submit(dev:u64, session:u64, opcode:u32, bytes:*const u8, len:usize, out_op:*mut u64)->i32
narf_wireless_poll(dev:u64, session:u64, op:u64, bytes:*mut u8, len:usize, out_len:*mut usize)->i32
narf_wireless_cancel(dev:u64, session:u64, op:u64)->i32
narf_wireless_close(dev:u64, session:u64)->i32
```

All six require `NetIface` at symbol resolution. Module identity comes from
the existing call gate. Every lookup matches that identity, its exact device
token, never-reused session and original current probe cap/slot/generation.
No scalar id grants access to a different module/device. Unsupported versions
fail before host I/O. Maximum request/reply sizes are4096/65536 bytes; replies
remain in kernel storage and are copied during a final current device grant
with exact service/device-context presence held. Permanent host hooks run
outside registry locks. A kernel-only publish closure performs the actual
non-reentrant copy; MT76 encloses it with the existing native receive-epoch
publication gate, so rekey/close cannot interleave a stale module-byte copy.
`-EAGAIN` retains pending work. `-ENOBUFS` retains a terminal reply and reports
its required size. Zero consumes a copied terminal reply; negative native
terminal errors consume it too. A forged/stale handle never enters the host.

MT76 family `0x6d743736`, version1, uses the following little-endian records.
All reserved fields must be zero; input length must match exactly.

| Opcode | Request | Reply |
|---|---|---|
|1 INITIALIZE|empty|version u32, family u32, chip u16, band mask u8, hardware type u8, real MAC[6], reserved u16, ifindex u32, wiphy u64, firmware version[10], build date[15], name length u8, name bytes|
|2 SCAN|active u8, frequency count u8<=64, SSID count u8<=4, reserved u8, IE length u16<=512, reserved u16, frequencies u32[], SSIDs as length u8<=32+bytes, IE bytes|count u32; each BSSID[6], RSSI i8, SSID length u8, frequency u32, channel u32, security u8 (open/WEP/WPA/WPA2/WPA3=0..4), SSID bytes|
|3 ASSOCIATE|BSSID[6], channel u8, security u8(open/PSK/SAE=0..2), frequency u32, SSID/IE/secret lengths u16, reserved u16; SSID, IEs, secret bytes|empty after actual native completion|
|4 DISASSOCIATE|empty|empty after native completion|
|5 TRANSMIT|one Ethernet frame,14..2304 bytes|empty after actual native TX completion; queue acceptance is insufficient|
|6 RECEIVE|empty|one independently copied native Ethernet frame, or empty if no copy is queued|
|7 FIRMWARE_CHUNK|image u8(patch/RAM=0/1), reserved u8, length u16(1..4096), offset u32|complete image length u32, requested offset u32, complete image SHA-256[32], available bytes up to requested length|

PSK secrets are32 bytes, SAE passwords1..63 bytes, and Open has no secret;
SSID is1..32 bytes for association. Native admission validates frequency,
security, PHY and emission policy. RX copies retain their native epoch until
final delivery and lose validity when keys/port ownership changes, including
while a reply is waiting for a larger output buffer. The bounded independent
copy queue has64 slots and drops saturated copies only; it never steals stack
or IPC frames. Firmware chunks expose only the immutable executable images
already opened/verified for the exact current transport, with no arbitrary
registry name, lookup authority or direct firmware pointer.

MT76 allows one retained operation per session. Cancellation before its first
poll drops unstarted work and produces `-ECANCELED`. Once native work started,
its future stays retained through actual terminal completion. If a cancelled
operation succeeds natively, its reply is `-EALREADY`: effects may have occurred.
Cancellation never fabricates an ACK, descriptor retirement or hardware stop.
Close/unload removes the exact service and native generation, withdraws
publications, invokes proven-or-retain removal and revokes its old probe cap.
A permanent task finishes started futures without any module callback; DMA
whose retirement cannot be proved remains retained. Close remains available
after revocation. Device context teardown calls host close before its normal
cap revocation. Existing Ethernet/module exports keep their signatures and
semantics; their established CRC/hash policy applies to the additive exports.

Source fixtures for owner/device/version isolation, short-buffer retention,
late cap revocation, teardown ordering, native-future cancellation and wire
bounds are implemented. Their execution and dual module builds remain pending
in the final coordinated validation pass; no RF acceptance is implied.

WIFI family `0x77696669`, **version 2** (generic host, `narf-wireless`),
uses the following little-endian records. All reserved fields must be zero;
input length must match exactly. One session per probe device; one retained
operation per session (every v2 opcode completes at submit, the poll only
collects the reply); the same cancellation contract as MT76.
`open_with_event` registers the per-session event callback for native→module
events; a plain open has no event channel. The callback is invoked only
through the bus call gate and forgotten on close or device retirement.

A module opens its session **before** registering its netdev: the netif
bridge names a netdev on a device with a wireless session `wlan%d`, and
`REGISTER_WIPHY` binds the wiphy shell to it by ifindex, taking its name —
nl80211 resolves wiphy ↔ netdev by name, so the two form one `wlan0`.

| Opcode | Request | Reply |
|---|---|---|
|1 REGISTER_WIPHY|ifindex u32 (the module's own netdev on this device), MAC[6], modes u32, hw_caps u8, cipher count u8<=8, band count u8 1..3, flags u8, max scan SSIDs u8<=16, reserved u8, max scan IE len u16<=2048; cipher suites u32[]; per band freq u32, channel count u8 1..64, reserved u8, channels u8[]|assigned wiphy index u32|
|2 SCAN_RESULT|BSSID[6], channel u8, security u8 (open/WEP/WPA/WPA2/WPA3=0..4), frequency u32, RSSI i8, reserved u8, SSID len u8<=32, reserved u8, IE len u16<=2048, SSID, IEs|empty|
|3 SCAN_DONE|status i32 (0, or a negative errno)|empty|
|4 CONNECT_RESULT|802.11 status u16 (0 = success), reserved u16, BSSID[6], reserved u16, frequency u32|empty; success raises carrier|
|5 DISCONNECTED|reason u16, locally generated u8, reserved u8|empty; drops carrier, reports unsolicited loss to nl80211|

`flags` are the module's SME offloads: `PSK_OFFLOAD = 1` (4-way handshake
from a PMK), `SAE_OFFLOAD = 2` (WPA3-SAE from a password),
`REPORTS_DISCONNECT = 4`. The shell advertises them to nl80211, so a
CONNECT's PMK or SAE password reaches the module's supplicant (the FullMAC
split); a userspace SME (`SecurityConfig::External`) is refused.

| Event | Payload |
|---|---|
|1 SCAN_REQUEST|flags u8 (bit0 active), frequency count u8, SSID count u8, reserved u8, IE len u16, reserved u16, frequencies u32[], SSIDs (len u8 + bytes)[], IEs|
|2 CONNECT|BSSID[6] (zero = any), security u8 (open/PSK/SAE = 0..2), reserved u8, frequency u32 (0 = any), SSID len u8, reserved u8, IE len u16, secret len u16, reserved u16, SSID, IEs, secret (32-byte PMK or SAE password)|
|3 DISCONNECT|reason u16, reserved u16|
|4 SCAN_ABORT|empty|

The callback's return is acceptance; the outcome is the matching report. The
shell waits 15 s for `SCAN_DONE`, 20 s for `CONNECT_RESULT` and 3 s for
`DISCONNECTED`, aborting the scan or withdrawing the connect on timeout.
Modes are the `WirelessModes` bits (STATION=1, AP=2, MONITOR=4, P2P=8);
`hw_caps` bits are HT=1, VHT=2, HE=4, EHT=8. Perf class: no hot path
(control plane only; frames never pass through the host).

## USB transfer datapath

Status: **implemented; `ftdi.ko` (`drivers/usb/ftdi`) is the reference
consumer**, proven by `cargo xtask ftdi-module-serial-smoke`.

A USB module probe runs inside the async attach cascade, and module text
cannot produce or await a `Future`, so a blocking "do a transfer" export is
impossible. The USB exports therefore follow Linux's URB model on top of the
handle-table pattern above:

```text
narf_usb_config_descriptor(dev, buf, len, out_len) -> i32
narf_usb_configure(dev, endpoints, count, callback, cookie, out_urb) -> i32
narf_usb_control(dev, setup[8], data, len, callback, cookie, out_urb) -> i32
narf_usb_submit(dev, endpoint, data, len, callback, cookie, out_urb) -> i32
narf_usb_poll(dev, urb, buf, len, out_len) -> i32
narf_usb_cancel(dev, urb) -> i32
narf_usb_serial_register(dev, family, kick, cookie, out_port) -> i32
narf_usb_serial_tx(dev, port, buf, len, out_len) -> i32
narf_usb_serial_rx(dev, port, data, len) -> i32
narf_usb_wait(dev, urb, timeout_ns) -> i32
```

All ten require `BusDevice`. Their path is `kabi.rs` → `narf_bus::module_usb`
(shape checks; bus sits below the USB stack) → the USB stack's permanent
`Datapath` hooks (`drivers/usb/src/module_datapath.rs`).

- **Context, not capability.** USB devices carry no `Cap` object today
  (built-in class drivers hold an `Arc<USBDevice>`). The equivalent
  authority is the context the class registry mints for exactly one
  `(module, token)` immediately before that module's probe. Every export
  resolves the caller's identity from the module call gate together with
  the token, so a module reaches only devices it was probed for, and only
  until a declined probe, an unplug or its unload retires the context.
  Transfers additionally carry the xHCI slot generation, so a reused slot
  is stale.
- **Copy mode, kernel buffers.** OUT payloads are copied at submit and IN
  payloads at poll; transfer buffers are the xHCI endpoint pages. Module
  memory is never a DMA target, so the unload question from
  [DMA safety](#dma-safety-the-load-bearing-decision) does not arise.
- **Kernel-owned futures, module completions.** Control and configure
  requests run in in-tree tasks; bulk and interrupt receipts are polled by
  a per-context pump task while any are pending. A terminal request fires
  the module's optional `extern "C" fn(u64) -> i32` completion through the
  module callback gate, outside every lock, and the module collects it
  with `narf_usb_poll` (`-EAGAIN` pending; `-ENOBUFS` retains it; otherwise
  consumed, with a Linux URB status).
- **Attributes from the descriptor.** `narf_usb_configure` names endpoints
  by address; type, packet size and interval come from the configuration
  descriptor the device was matched with, so a module cannot program an
  endpoint the device does not describe. `SET_ADDRESS` is refused on EP0.
  Isochronous transfers are not offered.
- **Cancellation is a request.** A bulk TD is stopped in a kernel task and
  completes `-ECANCELED` (an OUT may already have reached the device); an
  interrupt-IN wait completes `-ECANCELED` with its kernel-page TRB left
  armed; control, configure and interrupt-OUT run to completion (`-EBUSY`).
- **A subsystem sink.** Like `narf_netif_*` for e1000, a USB driver needs a
  place to deliver data. `narf_usb_serial_*` publishes a module-backed
  `/dev/ttyUSB<N>`: writers' bytes queue in the node's TX ring and run the
  module's kick callback; the module drains them to bulk-OUT and delivers
  bulk-IN payloads to readers. HCI and WWAN sinks (for `btusb.ko` and
  `cdc_mbim.ko`) are the next extensions; they are not part of this slice.
  A storage module instead publishes a disk through the
  [block datapath](#block-datapath).
- **Synchronous waits for synchronous callers.** A block request callback
  must finish its request before returning, and it may run inside an
  executor poll, so it cannot wait for the per-context pump task.
  `narf_usb_wait` polls one bulk or interrupt request inline (the xHCI
  bulk poll drains the event ring itself, as the built-in MSC driver's
  `block_on_spin` bridge relies on) and needs no other task to run. It
  only accepts requests submitted without a completion callback, so it
  never swallows one or re-enters the module, and it refuses control and
  configure requests (`-EOPNOTSUPP`), which complete in kernel tasks.

Proof: `ftdi-module-serial-smoke` boots with QEMU's `usb-serial` (FTDI
FT232BM) wired to a host socket, the built-in FTDI binder stepped aside
(`narf-drivers-usb/ftdi-module-only`), and `ftdi.ko` autoloaded. The module
reads the device descriptor (control IN), configures its endpoints, runs
the FTDI bring-up (control OUT), and publishes `/dev/ttyUSB0`. The guest
shell's `echo` reaches the host socket through module-submitted bulk-OUT,
and the host's reply reaches the shell's `cat` through module-submitted
bulk-IN. In-kernel smokes (`drivers/usb/module-datapath`,
`modules/kabi`) cover argument validation, owner isolation, the serial
bridge, retirement and the control-request lifecycle. The kernel-test VM
never attaches its QEMU keyboard, so that lifecycle smoke runs against a
synthesised slot and compares bytes only when a slot really answers.

## Block datapath

Status: **implemented; `nvme.ko` (`drivers/nvme`, `module_probe.rs`) is the
reference consumer**, proven by `cargo xtask nvme-module-block-smoke`.

Every storage `.ko` (nvme, ahci, sdhci, the RAID HBAs) had only a
registration path: PCI/MMIO/DMA let a module drive a controller, but there
was nowhere to deliver sectors. The block sink is that place:

```text
narf_blk_register(dev, name, name_len, geometry[4], request, cookie) -> i32
narf_blk_copy_in(dev, request, dma, dma_off, req_off, len) -> i32
narf_blk_copy_out(dev, request, dma, dma_off, req_off, len) -> i32
narf_blk_fill(dev, request, req_off, src, len) -> i32
narf_blk_fetch(dev, request, req_off, dst, len) -> i32
```

All five require `BlockDevice`. They are implemented in the modules crate
(`modules/src/module_block.rs`), which owns the module call gate and can
reach both the bus DMA table and the block registry.

- **A real disk.** `narf_blk_register` validates the name (lowercase ASCII,
  at most 31 bytes, unused) and geometry (`[block size 512..=4096, capacity,
  max blocks <= 1 MiB of data, flags]`; bit 0 volatile write cache, bit 1
  read-only), checks that the caller holds a live probe context for `dev`
  (`narf_bus::module_device_live` for PCI, `module_usb::context_live` for
  USB), and registers an ordinary
  `BlockDeviceSync`. `/dev/<name>`, the disk-write policy, partition
  scanning and filesystems treat it like any built-in disk.
- **Synchronous requests, like the built-in polled drivers.** `read`,
  `write` and `flush` call the module's
  `extern "C" fn(cookie, request, op, lba, count) -> i32` through the module
  call gate and return when it does. Requests are split to the module's max
  blocks and serialised per disk, so a module sees one request at a time.
  A module that registers a disk from its probe and is then read during
  that registration (disk policy) is already in its own context; that
  nested request skips the gate and still takes the per-disk slot.
- **Kernel-side copies; the module never sees the caller's buffer.**
  Inside a request the module asks the kernel to copy between the request
  and either one of its own DMA buffers (`narf_blk_copy_in`/`copy_out`, via
  `narf_bus::module_dma_read`/`write`: PCI drivers) or module memory it
  names (`narf_blk_fetch`/`fill`: USB drivers, whose transfers already copy
  through module memory and who own no bus DMA buffers). A copy is
  checked against the request's owner, token, direction and length, and a
  second concurrent copy of the same request is `-EBUSY`. Request ids are
  never reused, so a copy after the callback returned is `-EINVAL`.
- **Unload and removal.** `delete_module` (and a failed init) calls
  `retire_owner` before the bus context goes: new requests fail
  `DeviceRemoved`, a running one is waited out (5 s bound), and every disk
  is unregistered, all before module text is unmapped. The bus also reports
  every retired PCI or USB device context
  (`narf_bus::module_context_retired`: unplug, reprobe, declined probe), and
  the disks registered for that one device are retired the same way, so an
  unplugged stick's disk disappears instead of failing in place.

The reference driver is deliberately small: one admin and one I/O queue,
polled with `narf_dma_wait8`, namespace 1 only, a 64 KiB data buffer with a
fixed PRP list. The built-in driver (MSI-X, every namespace, AER, power
states) stays the default. `narf-drivers-nvme/nvme-module-only` withdraws
the built-in PCI matches so a module loaded before PCI probing binds the
controller.

Proof: `nvme-module-block-smoke` serves a purpose-built 32 KiB image with a
host-only marker in sector 1. The guest shell writes a token into sector 0
of `/dev/nvme0n1` (a read-modify-write through the module), then reads the
whole disk back: the token and the marker must both come back. After QEMU
exits, the host image must hold the token at byte 0 with every other byte
unchanged. In-kernel smokes (`modules/block`, `modules/kabi`) cover name
and geometry validation, limits, request splitting, errno mapping, read-only
and flush flags, copy checks and retirement.

`usb-storage.ko` (`drivers/usb/storage`) is the USB consumer. Its probe and
the configure / `SET_CONFIGURATION` steps run from completions; the SCSI
bring-up (TEST UNIT READY, INQUIRY, READ CAPACITY(10)) and every block
request then run synchronously as CBW → data → CSW over callback-less bulk
requests waited with `narf_usb_wait`, at most 4 KiB per command (one
transfer). `narf-drivers-usb/msc-module-only` steps the built-in binder
aside. `usb-storage-module-block-smoke` proves it with the same
write/read-back/image check as the NVMe smoke, over QEMU's `usb-storage`.
