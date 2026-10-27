# narf-drivers-usb — USB host controllers and class drivers

## Sources (public only)

Class and host-controller code uses the public standards below. Since NARF's
2026-05-20 relicense to GPL-2.0-or-later, explicitly identified driver paths
also consult upstream Linux GPL sources.

### EHCI host controller (USB 2.0)
- "Enhanced Host Controller Interface Specification for Universal
  Serial Bus", Revision 1.0, March 12, 2002 (Intel).
  <https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/ehci-specification-for-usb.pdf>

### OHCI host controller (USB 1.1)
- "OpenHCI — Open Host Controller Interface Specification for USB",
  Release 1.0a, September 14, 1999 (Compaq / Microsoft / National
  Semiconductor).
  <https://composter.com.ua/documents/ohci_specification.pdf>

### UHCI host controller (USB 1.1)
- "Universal Host Controller Interface (UHCI) Design Guide",
  Revision 1.1, March 1996 (Intel).
  <https://ftp.netbsd.org/pub/NetBSD/misc/blymn/uhci11d.pdf>

### xHCI host controller

- **eXtensible Host Controller Interface for Universal Serial Bus
  (xHCI), Revision 1.2** — Intel. Public document.

### USB Mass Storage (BOT)

- **Universal Serial Bus Mass Storage Class Bulk-Only Transport,
  Revision 1.0** (Sep 1999) — USB-IF. Public.
- **SCSI Block Commands - 3 (SBC-3)** — for the embedded SCSI
  command opcodes (`READ(10)` / `WRITE(10)` / `INQUIRY` /
  `READ CAPACITY(10)`).

### USB HID

- **Device Class Definition for Human Interface Devices (HID),
  Version 1.11** — USB-IF. Public.
- **HID Usage Tables, Version 1.5** — USB-IF.

### USB Video Class 1.5

- **Universal Serial Bus Device Class Definition for Video Devices,
  Revision 1.5** (March 16, 2012) — USB-IF. Public.
  §3.1 (class triple), §3.7 (VC class-specific descriptors:
  HEADER, INPUT_TERMINAL camera, OUTPUT_TERMINAL, PROCESSING_UNIT,
  EXTENSION_UNIT), §3.9.2.1 (VS INPUT_HEADER), Annex A (terminal
  type codes).
- **Universal Serial Bus Device Class Definition for Video Devices:
  Uncompressed Payload, Revision 1.5** — USB-IF. Public. §3.1.1
  (FORMAT_UNCOMPRESSED + Format-GUID byte order), §3.1.2
  (FRAME_UNCOMPRESSED).
- **Universal Serial Bus Device Class Definition for Video Devices:
  Frame-Based Payload, Revision 1.5** — USB-IF. Public.

### UVC payload header (1.5 §2.4.3.3)

- **UVC 1.5 §2.4.3.3** "Video and Still Image Payload Headers" —
  USB-IF. Public. Bit Field Header layout (FID toggle, EOF, PTS
  flag, SCR flag, SI flag, Error, EOH).
- **UVC 1.5 §2.4.3.4** "Source Clock Reference and Presentation
  Time Stamp" — USB-IF. Public. PTS = LE 32-bit; SCR = LE 32-bit
  SOF tick + 11-bit clock counter packed across 6 bytes.

### USB CDC (Communications Device Class)

- **USB Class Definitions for Communications Devices, Revision 1.2,
  Errata 1** (USB-IF, November 2010 / errata July 2012). Public.
  Common chapters: §3 (CDC architecture overview), §5.2 (Functional
  Descriptors — Header / Union / Country Selection), §5.3 (Class-
  specific interface descriptors), §6.2 (Common class-specific
  requests).
- **USB CDC Subclass Specification for PSTN Devices, Revision 1.2**
  (USB-IF, February 2007). Public. §3.6.2.1 (ACM Functional
  Descriptor + bmCapabilities), §6.3.1 (`SEND_ENCAPSULATED_COMMAND`),
  §6.3.10 (`SET_LINE_CODING`), §6.3.11 (`GET_LINE_CODING`), §6.3.12
  (`SET_CONTROL_LINE_STATE`), §6.5.4 (`SerialState` notification).
- **USB Network Control Model (NCM) Specification, Revision 1.0
  with Errata and Adopters Agreement** (USB-IF, September 2010 /
  errata March 2014). Public. §3.2 (NTB-16 framing — NTH16 + NDP16
  + datagrams), §3.3 (NTB-32 framing), §6.2.1
  (`GET_NTB_PARAMETERS`), §6.2.4 (`GET_NTB_INPUT_SIZE`), §6.2.5
  (`SET_NTB_INPUT_SIZE`), §7 (NCM Functional Descriptor).
- **USB Ethernet Control Model (ECM) Specification, Revision 1.2**
  (USB-IF, February 2007). Public. §5.4 (Ethernet Networking
  Functional Descriptor), §6.2 (class-specific requests).

### USB DFU (Device Firmware Upgrade)

- **USB Device Class Specification for Device Firmware Upgrade,
  Version 1.1** (USB-IF, 5 August 2004). Public, usb.org. §3.1
  (class triple — class 0xFE, subclass 0x01, protocol 0x01/0x02
  for runtime / DFU mode), §4.1.3 (DFU Functional Descriptor —
  bmAttributes / wDetachTimeOut / wTransferSize / bcdDFUVersion),
  §4.1.4 + §6.1.2 (state machine + status block layout), §5
  (class-specific requests: DETACH, DNLOAD, UPLOAD, GETSTATUS,
  CLRSTATUS, GETSTATE, ABORT).

### USB Audio Class 1.0

- **Universal Serial Bus Device Class Definition for Audio Devices,
  Release 1.0** (March 18, 1998) — USB-IF. Public document.
  §4.3.2 (AC interface header + topology unit descriptors), §4.5.2
  (AS interface descriptors), §A.5/A.6 (subtype tables), §A.7
  (terminal type codes).
- **Universal Serial Bus Device Class Definition for Audio Data
  Formats, Release 1.0** (March 18, 1998) — USB-IF. Public.
  §A.1.1 (format tags), §A.2 (format type codes), §2.2.5 (Type-I
  PCM format descriptor layout).

### Qualcomm WCN6855 Bluetooth over USB

- **Linux `drivers/bluetooth/btusb.c`** — GPL-2.0-only, Qualcomm USB setup
  path: vendor requests `GET_TARGET_VERSION` / `CHECK_STATUS`, split
  control-header + endpoint-2 bulk firmware download, WCN6855 ROM table, and
  runtime rampatch/NVM naming. Consulted under NARF's GPL-2.0-or-later license.

## 3. Public interface

- `UsbHub::attach(xhci, slot_id, iface_num, device_protocol, speed)` binds an
  addressed hub and retains its negotiated speed plus Device Descriptor
  protocol so xHCI can set the multiple-TT bit correctly.
- `HubDescriptor::tt_think_time()` returns the USB 2.0
  `wHubCharacteristics[6:5]` encoding used directly in a low/full-speed
  child's xHCI Slot Context.
- Hub downstream idle-suspend: the supervisor marks ports bound via
  `attach::mark_ports_bound`, which also stamps each port's
  last-activity tick (a port's idle window runs from bind). Class
  drivers feed `attach::mark_port_activity` on each completed
  transfer and call `attach::resume_port` before a transfer to a
  port that may be suspended. `msc::try_bind_msc_already_addressed`
  takes the device's hub context — (index into `attach::HUBS`,
  downstream port), `None` on a root port — and `MscDevice` records
  it as `hub_port`; its BOT funnels resume-then-feed on every
  transaction. The pumped HID classes (boot keyboard, boot mouse,
  PTP touchpad, consumer control) record the same `hub_port`
  context through their `try_bind_*_already_addressed` binders;
  their pumps feed on each completed interrupt-IN report, and the
  supervisor resumes suspended HID-bound ports immediately before
  the pumps each cycle (`hid::resume_suspended_hub_ports`),
  opening a fresh idle window — a suspended port gates the very
  interrupt endpoint the pump polls, so the resume has to come
  from the supervisor side of the pump, not from report traffic.
- `Xhci::address_device_with(..., Topology)` retains the topology for later
  Evaluate Context operations; marking a downstream device as a hub must not
  erase its route string or parent-TT fields.
- `EndpointConfig` retains raw USB `wMaxPacketSize` and `bInterval` values.
  `Xhci::configure_endpoints` translates USB 2.0 periodic endpoints into xHCI
  Max Packet, Max Burst, Interval, CErr, and Max ESIT Payload fields using the
  addressed slot's negotiated speed.
- `Xhci::control_in` accepts only SETUP packets with the device-to-host
  direction bit set; `Xhci::control_out` accepts only host-to-device requests.
  Payload-bearing class requests (including HID `SET_REPORT`) must use the
  matching method so the xHCI Data Stage has the correct direction.
- `Xhci::get_device_descriptor(slot_id)` first reads the mandatory 8-byte
  descriptor prefix, validates and applies `bMaxPacketSize0` through Evaluate
  Context, then returns only a complete 18-byte Device Descriptor. Callers may
  therefore read `idVendor`/`idProduct` at offsets 8..12 without accepting a
  zero-filled short response.
- `Xhci::control_in` and `Xhci::control_out` identify Data and Status Stage
  completion events by their originating control-ring TRB and drain both before
  returning. A queued Status completion may never satisfy the next control TD.
- `USBDevice::{begin_bulk_in,begin_bulk_out}` submit one 1..4096-byte TD
  and return a `BulkToken`; `poll_bulk_in(token, out)` / `poll_bulk_out(token)`
  return `None` while the same TD remains active. A receive buffer must cover
  the original requested length. Polling never imposes an idle timeout.
  Receipts identify the slot generation, endpoint, private submission serial,
  direction and originating TRB. Only that TRB's exact terminal event can
  retire the submission; IN short packets are valid, malformed residue and
  error completions poison the endpoint. Copy-out precedes reuse.
- The controller retains bulk DMA ownership before any scratch-buffer mutation
  or TRB publication. Dropping a token or compatibility `bulk_in/out` future,
  and timeout/error returns, do not cancel or release that ownership. A second
  submission fails before touching the scratch page or ring. Recovery requires
  an explicit stop/drain/reset contract. `USBDevice::stop_bulk(token)` is the
  one-shot non-stream bulk cancellation path: it reserves slot configuration
  and the endpoint before awaiting Stop Endpoint and Set TR Dequeue Pointer.
  Both commands require their exact originating TRB/slot Success completion;
  output-context readback must show Stopped and the requested successor/DCS.
  Only then are old endpoint events discarded and the page/ring reopened.
  The old token becomes stale. It canonicalizes the Link-boundary enqueue
  cursor and preserves USB data-toggle state. Errors and Future Drop retain
  the endpoint/page plus the slot claim. Halted-endpoint recovery (including
  a halted EP0) is the separate `Xhci::reset_endpoint` contract below.
  `USBDevice` bulk operations reject stale slot generations. Periodic transfer
  methods cannot target bulk endpoints. The xHCI layer owns DMA cache
  maintenance and device barriers, including outer-shareable ordering on ARM.
- `Xhci::configure_endpoints` accepts new, distinct endpoint DCIs and refuses
  replacement of an existing endpoint without quiescence. It serializes slot
  configuration with new bulk submissions and preserves the highest existing
  DCI. Input Context and new rings are retained across a published command's
  cancellation or ambiguous failure; only the exact command TRB's successful
  completion permits adoption. An ambiguous configuration poisons the slot
  against retry/readdress rather than freeing hardware-owned DMA.
- `USBDevice` control, descriptor and endpoint-configuration operations carry
  the handle's retained generation into the controller. EP0 claims its shared
  page before mutation and releases it only after validated Data/Status
  terminal completions and copy-out. Error/cancellation keeps EP0 busy; a new
  software firmware owner cannot reuse an ambiguous TD's buffer. Disable Slot
  invalidates handles before command publication and retains all mappings.
- USB Ethernet class drivers (`r8152`, `cdc_ncm`) publish each bound device
  through `narf_net::iface::register_with_context` as `usb-rtl{N}` /
  `usb-ncm{N}`, where `N` is the driver's device-record index and the
  registration cookie is that same index. The send hook resolves the cookie
  to the bound device's own record (slot + bulk-OUT DCI) — there is no
  shared or default-device TX path. The published station address is read
  from the device at bind (never synthesised); a device that reports no
  valid address fails the bind. Link state is republished through
  `iface::set_link_metadata` as the driver samples it.
- Address Device reserves a slot before DMA setup, retains Input/Device
  Contexts plus EP0 ring/page before DCBAA publication, and adopts them only
  after the exact command TRB succeeds. Address, Configure, Evaluate, Disable
  and Enable command waits match originating command pointers. Evaluate
  Context also retains its Input Context across error/cancellation. EP0 Link
  initialization follows zeroing so the ring can wrap.
- `Xhci::reset_endpoint(slot, generation, dci)` recovers a halted endpoint
  (DCI 1 and bulk DCIs; interrupt/isochronous are refused). Under the slot's
  configuration claim it quarantines the endpoint's retained TD (the EP0
  claim in `ControlState`, the bulk token in its `bulk_owner::State`), issues
  Reset Endpoint, requires the output-context readback to show Stopped,
  issues Set TR Dequeue Pointer at the canonical Link-boundary enqueue
  cursor, requires readback Stopped at exactly that dequeue, purges the
  endpoint's queued Transfer Events, and only then releases the retained
  claim — a recovered TD's token is stale from that point. Any error after
  the claim leaves the claim in place (endpoint terminally busy), mirroring
  the bulk-stop profile. `USBDevice::clear_endpoint_halt(endpoint)` pairs
  it with the device-side CLEAR_FEATURE(ENDPOINT_HALT) so host and device
  data toggles restart together; EP0 skips the CLEAR_FEATURE step.
- `Xhci::reclaim_slot(slot)` is the explicit stop/drain/removal path that
  makes a disabled slot reusable. It refuses any slot that has not
  completed Disable Slot (the completion is the hardware-quiescence
  proof). It drains the hardware event ring, zeroes the slot's DCBAA
  entry, drops the retained `Device` — releasing the device/input
  contexts, EP0 ring/page and every endpoint ring/buffer, including a TD
  still posted at teardown — purges the slot's queued events, and only
  then returns the id to the allocatable pool. A reclaimed id is always
  re-addressed under a fresh generation from the monotonic
  controller-global counter, so no prior handle can match it. Readdress
  of an owned or published-failed slot that has not been disabled is
  still refused.
- HCE recovery has two paths. `soft_recover` (no reserved slots) halts,
  resets and re-runs bring-up against the retained controller DMA.
  `Xhci::recover_controller()` is the with-devices path: under the slot
  reservation it invalidates every generation, halts + HCRSTs, zeroes
  every live DCBAA entry and drops every `Device` (all slot DMA
  released), clears retained command receipts (their ring restarts at
  cursor 0), resets the slot table, re-runs bring-up, and bumps
  `Xhci::recovery_epoch()`. Every pre-reset handle is stale by
  construction; supervisors watch the epoch to trigger wholesale
  re-enumeration. Successful bulk stop still reuses retained pages only;
  it does not free mappings or enable slot reuse.
  Live Address Device/HID fixtures hold recycled hardware slots allocated
  until Enable Slot supplies a never-used software slot, using the same
  unused-generation predicate as production Address Device. They never clear
  retired ownership. Two real address/class-bind/Disable cycles cover the
  HID-before-address order and verify the prior slot stays retired when a
  different fresh slot is addressed, independently of hardware allocation
  order. Every fixture reservation is disabled on terminal cleanup; the
  bounded HID report wait uses the scheduler's self-driven sleep bridge.
- Command/EP0 waits inspect the bounded completion queues before each single
  hardware-event demux, check deadlines throughout, and yield after at most
  32 unrelated events. Queue pressure cannot make the waiter's own draining
  evict its completion, and a continuous producer cannot bypass its timeout
  or executor yield. Unmatched events retain the existing 64-entry policy.
- Event demux serializes pop→latch/queue publication under a short IRQ-safe
  guard, so a Stop command completion cannot overtake its preceding forced
  transfer events on another CPU. A stopping bulk owner quarantines every
  event for its slot/DCI, including forced events at a successor TRB. No
  wait/pump or slot reservation occurs under this publication guard; ring
  locks release before device/latch locks. `drain_events` uses this same
  owned-aware demux and is bounded to one event-ring capacity.
- ISR demux retains exact active bulk and EP0 Data/Status completions in
  per-owner latches before the shared queues. Command-ring entries reserve a
  receipt before publication and retain their exact completion there until
  consumed. Device ownership locks are short, blocking and IRQ-safe, so another
  CPU's contention cannot send an owned completion into a lossy fallback.
  Identical duplicates are idempotent; conflicting results poison reuse.
  Command-ring entries cannot overwrite an unconsumed or abandoned receipt.
- `class_registry::dispatch_probe(device, config)` evaluates exact VID/PID
  entries against the device descriptor and class-triple entries against
  Interface Descriptors in `config`. A class-only entry is an explicit
  `(0, 0)` VID/PID wildcard, not a match for an unrelated interface.
- Disconnect lifecycle: the supervisor polls connection state each cycle.
  A claimed root port (or bound hub downstream port) that leaves the
  connected set is detached via `attach::detach_slot`: class bindings are
  dropped first (evdev nodes unregister; registered drivers are reached
  through `class_registry::dispatch_unbind`, a broadcast of the optional
  hook from `register_class_driver_with_unbind`), a hub's bound subtree
  is detached recursively and its `HUBS` entry removed, then the slot is
  disabled and reclaimed (`Xhci::reclaim_slot`) so a replug re-runs
  attach from scratch. A controller recovery epoch change drops every
  binding wholesale (`attach::detach_all_bindings`) and re-enumeration
  follows; on that path the pumped classes are cleared from their
  registries and every MSC device is removed and unpublished
  (`msc::unbind_all_msc`). On the per-slot detach path, classes the
  supervisor does not pump (MSC / UAC / UVC / CDC-NCM / btusb / CCID)
  get the slot disable + reclaim but no class-registry removal yet;
  the remaining non-pumped classes keep their registries across
  recovery as well.
- `find_video_streaming_endpoints(config)` returns each UVC bulk/isochronous IN
  endpoint with its owning interface and alternate setting.
  `select_video_streaming_iso_endpoint(endpoints, payload)` chooses the smallest
  alternate that satisfies the PROBE-accepted payload, and
  `negotiate_and_activate_video_stream(xhci, device_index, desired)` runs the
  26-byte SET_CUR(PROBE) / GET_CUR(PROBE) / SET_CUR(COMMIT) sequence, configures
  the accepted endpoint, issues `SET_INTERFACE`, and starts an IRQ-driven
  packet/frame pump into the camera's registered `/dev/video<N>` queue.
- The V4L2 surface drives that composition. Bind
  (`try_bind_video_already_addressed`) retains the parsed `StreamFormat`
  table on the device and installs `video_stream_ops()` on the registered
  `/dev/video<N>` node. `VIDIOC_STREAMON` awaits the start hook — which
  maps the `VIDIOC_S_FMT`-committed format back through the retained
  table (frame interval: nearest 30 fps; no frame-rate surface reaches
  STREAMON) and runs the negotiation above — *before* the device is
  marked streaming; a negotiation or activation failure fails the ioctl
  (`EIO`, or `ENODEV` when the device/controller is gone) and leaves the
  device non-streaming. If activation fails after COMMIT succeeded, the
  VideoStreaming interface is returned to alternate setting 0 before the
  error propagates. `VIDIOC_STREAMOFF` awaits the reverse teardown
  (`deactivate_video_stream`: capture-pump stop request, then
  `SET_INTERFACE` to alternate setting 0) before local buffer state is
  reset. The composition (bind, negotiate, activate, deactivate, pump)
  is generic over the narrow `UvcTransport` seam (control in/out,
  endpoint configuration, isochronous receive); production implements
  it on `Xhci`, and the end-to-end kernel fixture
  (`smoke_uvc_streamon_composition_e2e`) implements it on a modelled
  camera and asserts the transfer conversation through the real V4L2
  dispatch. The pump receives through the single `UvcTransport::isoch_in`
  call site, behind which the depth-4 isochronous pipelining work (#808)
  slots in without changing the composition.
- `try_bind_btusb_already_addressed(xhci, slot_id, vendor_id, product_id,
  config)` binds the standard Bluetooth USB interface. For a recognised
  WCN6855 ID it completes the Qualcomm USB firmware/status protocol before
  running the full mandatory HCI sequence, adopting the ready controller, and
  publishing `/sys/class/bluetooth/hci<N>`. Firmware is selected from the
  verified registry using the controller-reported ROM/RAM/board identity.
  For Intel-quirk IDs it runs the btintel sequence first (Read Version
  0xFC05 → Read Boot Params 0xFC0D → `.sfi` secure-send download over
  0xFC09 → Intel Reset boot 0xFC01 → best-effort `.ddc` over 0xFC8B), and
  for MediaTek-quirk IDs the btmtk 79xx WMT RAM-code download (WMT
  PATCH_DWNLD over 0xFC6F, section-map probe + ≤250-byte flagged chunks,
  status from the 0xE4 WMT event); a failed vendor setup fails the bind.
  Firmware pairs are the `btusb_quirks::firmware_paths` names under the
  vendor prefix (`intel/`, `mediatek/`).
- `MSC_DEVICES` entries are tombstoned on detach, never shifted: a bind
  reuses the first tombstone, so the `usb-msc{idx}` block name is stable
  across unplug/replug. Each entry carries a monotonic bind generation
  stamped at bind; a `UsbMscBlockDevice` adapter captures it and fails
  with `BlockIoError::DeviceRemoved` once its device is detached *or*
  its index is reused by a later bind — a held adapter is never served
  by the next disk to occupy its index, and a rebind of the same disk
  (a new bind, a new generation) does not resurrect it.
- `msc::detach_msc(slot_id)` is MSC's publication teardown — tombstone the
  slot's entries, then unregister the `usb-msc{idx}` disk and its partition
  children (children first) from the block registry. It is registered as a
  class-registry unbind hook (`register_class_driver_with_unbind`, BOT
  class triple) and reached via `dispatch_unbind` on the supervisor's
  detach path; MSC binding itself stays in the attach cascade, and the
  registry probe always declines. `msc::unbind_all_msc()` is the wholesale
  variant for controller-recovery teardown.
- `serial::devfs_bridge::unregister_tty_usb(index)` is the detach half of
  `register_tty_usb`: it removes the port from the ttyUSB node table and
  withdraws the `/sys/class/tty/ttyUSB<N>` kobject. Indices are not
  recycled; a replugged adapter republishes under a fresh index.
- `ccid::devfs_bridge` publishes each bound CCID reader as `/dev/ccid<N>`
  (provider hooks installed by the `usb-ccid-devfs` Stage::Subsys
  initcall; node index = `CCID_READERS` index, assigned at bind). The
  node is clone-on-open: `write` submits one raw APDU via
  `CcidReader::send_apdu` and queues the response for `read` (one
  command in flight per fd; a second `write` with an unread response
  fails Busy). Card power and status are async ioctls via `ioctl_user`
  (NARF-local, type 'C': POWER_ON queues the ATR as the next read,
  POWER_OFF, SLOT_STATUS returns present/powered/changed bits,
  SET_SLOT selects the fd's slot). Slot presence is tracked from
  `RDR_to_PC_NotifySlotChange` reports consumed by the
  `usb-ccid-supervisor` Stage::Late pump on the Interrupt-IN endpoint;
  readers without an interrupt endpoint are polled via
  `CcidReader::get_slot_status`. The bridge depends on the narrow
  `CcidTransport` seam (production: the bound reader over xHCI);
  fixtures drive the published surface against a modelled card.
- FIDO2 authenticators (CTAP2 over USB HID, issue #999) bind via
  `ctap::try_bind_ctap_already_addressed`, late in the attach
  cascade after CCID. Discrimination is the fetched HID report
  descriptor, not the interface class: a token is an interface
  whose report descriptor declares the FIDO Alliance usage page
  (0xF1D0, usage 0x01) with 64-byte Input and Output fields and
  no report IDs (`ctap::descriptor_is_fido`); every HID
  interface on a composite device is scanned. The binder
  requires a 64-byte interrupt IN/OUT endpoint pair
  (`ctap::find_fido_endpoints`), issues SET_CONFIGURATION,
  configures both endpoints, arms the first interrupt-IN TRB,
  and registers the token in `ctap::CTAP_TOKENS` (append-only,
  mirroring `CCID_READERS`; detach removal is the #748
  follow-up, the slot itself is reclaimed by `detach_slot`).
  `ctap::open_client(token)` builds a `narf_ctap2::Client` over
  `ctap::XhciHidPipe` with `ctap::CryptoRandom` (narf-crypto's
  HW-entropy-gated fill) for the suspend service. Interrupt-OUT
  transfers are `Xhci::arm_interrupt_out` /
  `Xhci::poll_interrupt_out`, the mirror of the interrupt-IN
  pair: one Normal TRB carries one 64-byte report from the
  endpoint's DMA page; polling reports bytes consumed or a
  controller error; the pipe bounds its poll loop and surfaces
  exhaustion as a CTAP Timeout rather than blocking.

## Scope

### Target laptop USB profile (silicon validation pending)

| USB ID | Device | In-tree path | Remaining validation |
|---|---|---|---|
| `05e3:0610` | Genesys Logic USB 2.0 hub | Hub class enumeration, multiple-TT flag, TT think-time propagation, downstream route addressing | Boot on the target xHCI controller and enumerate every downstream port |
| `27c6:6594` | Goodix USB2.0 MISC fingerprint reader | Explicit Goodix match, vendor-class bulk-IN/bulk-OUT transport, `/dev/fp0` handoff | Userspace Goodix MOC enrol/match protocol |
| `10ab:9309` | USI/Qualcomm WCN6855 Bluetooth | Explicit WCN6855 quirk match, runtime version/status query, rampatch + board-NVM USB download, full mandatory HCI bring-up, ready-controller registration, and `hci<N>` sysfs publication | Production-sign the imported firmware and validate the full sequence on silicon |
| `8087:0032` | Intel AX210 Bluetooth (Renoir target) | Explicit Intel quirk match, version-TLV + boot-params read, `.sfi` secure-send download + Intel Reset boot + `.ddc` config, full mandatory HCI bring-up, ready-controller registration, `hci<N>` sysfs publication, HCI pump | Stage the `intel/ibt-*` blobs and validate the full sequence on silicon |
| `0e8d:7922` | MediaTek MT7922 Bluetooth (Phoenix target) | Explicit MediaTek quirk match, WMT 79xx RAM-code download (section probe + flagged chunks), full mandatory HCI bring-up, ready-controller registration, `hci<N>` sysfs publication, HCI pump | Stage the `mediatek/BT_RAM_CODE_MT7922_*` blob and validate the full sequence on silicon |
| `30c9:00cd` | Luxvisions integrated camera | Generic UVC bind, `/dev/video<N>` registration, PROBE/COMMIT negotiation, streaming-alternate selection, USB 2.0 high-bandwidth xHCI programming, and frame delivery | Validate negotiation and end-to-end isochronous video capture on silicon |

The `1d6b:0002` and `1d6b:0003` entries are synthetic root hubs exposed by
the host controller and are not matched as downstream USB devices.

### WCN6855 firmware staging

For bring-up, import the Qualcomm tree and place both the generic WCN6855
files and the QCA2066 board-ID fallback in the initramfs:

```sh
cargo xtask import-firmware --vendor qca --clean
cargo xtask image --arch=x86_64 \
  --initramfs-firmware 'qca/*' \
  --initramfs-firmware 'qca/QCA2066/*'
```

The second glob is required for board IDs `030a`/`030b`; firmware globs are
single-directory patterns, so `qca/*` does not cross into `qca/QCA2066/`.
`import-firmware` produces developer-only unsigned NARF trailers, while the
production image must use externally generated signatures and a configured
`NARF_FIRMWARE_TRUSTED_KEYS` set. The two-pattern bundle was boot-validated
with 146 Qualcomm entries and a successful `firmware-scan-initramfs` pass;
the USB download itself remains a target-silicon gate.

### Landed
- **xHCI** (`xhci`): MMIO bring-up, BAR mapping, command/event ring
  setup, device enumeration.
- **HID** (`hid`): Boot keyboard report decoder, modifier+keycode
  state tracking, usage-table mapping for alphanumeric input.
- **HID Boot Mouse** (`hid::mouse`): HID 1.11 §B.2 boot-mouse report.
  <https://www.usb.org/document-library/device-class-definition-hid-111>
  decoder (3-byte: button mask + signed dx/dy), Set-Protocol(Boot)
  attach via xHCI control-IN, descriptor-walker that locates the
  HID/Boot/Mouse interface (class 0x03 / sub 0x01 / proto 0x02) and
  its interrupt-IN endpoint, diff-on-button-or-delta translator that
  emits `narf_input::PointerEvent`s onto the global ring. Held
  buttons with zero motion are silent (auto-repeat is a userspace
  concern). Wheel byte (extra report byte some mice send in boot
  mode) is accepted on the wire but discarded — vertical/horizontal
  wheel + multi-touch land with the Report-Descriptor parser.
- **MSC** (`msc`): Bulk-Only Transport CBW/CSW codec, INQUIRY,
  READ_CAPACITY(10), READ(10), WRITE(10) for single-block transfers.
  The `BlockDeviceSync` adapter also performs SYNCHRONIZE
  CACHE(10) for `flush()` and WRITE(10) with the FUA bit for
  `write_fua()`, so the Flush/FUA capabilities it advertises are
  issued on the wire, not merely promised (#829).
- **Hub** (`hub`): hub class enumeration, multiple-TT detection from the
  Device Descriptor protocol, TT think-time propagation, and downstream
  route addressing so low/full-speed devices behind high-speed hubs are
  visible.
- **UVC 1.5** (`uvc`): UVC descriptor parser and USB 2.0 streaming-alternate
  activation. VC HEADER (bcdUVC,
  clock frequency, controlled VS interfaces), INPUT_TERMINAL with
  the camera-specific extension (objective focal length range,
  controls bitmap), OUTPUT_TERMINAL, PROCESSING_UNIT, VS
  INPUT_HEADER (with the per-format control bitmap list), VS
  FORMAT_UNCOMPRESSED with 16-byte Format-GUIDs (YUY2, NV12), VS
  FRAME_UNCOMPRESSED with both discrete and continuous frame-
  interval forms, VS FORMAT_MJPEG. Bind retains each VideoStreaming alternate's
  endpoint and bandwidth metadata; the negotiation path performs PROBE/COMMIT,
  configures the smallest fitting isochronous alternate, and issues
  SET_INTERFACE. Its capture task reassembles UVC payloads and delivers complete
  frames to the registered `/dev/video<N>` queue. STREAMOFF/cancellation and
  bulk-streaming orchestration remain follow-ups.
- **UAC1 + UAC2** (`uac`, `uac_card`): USB Audio Class descriptor
  decode for both protocol revisions — v1 AC HEADER, INPUT_TERMINAL,
  OUTPUT_TERMINAL, FEATURE_UNIT (per-channel control bitmaps),
  AS_GENERAL, Type-I FORMAT_TYPE (discrete sample-rate list and
  continuous-range form), and the v2 layouts including the clock
  entity family (CLOCK_SOURCE / SELECTOR / MULTIPLIER). A topology
  walker composes the decoders over a whole configuration. Bind is
  a pure, ordered control-transfer plan executed against the xHCI:
  SET_CONFIGURATION, per-stream SET_INTERFACE alt selection,
  sampling-frequency SET_CUR (v1 endpoint control; v2 clock entity,
  RANGE-resolved), and FeatureUnit GET_MIN/MAX/RES + SET_CUR
  volume/mute. The bound device registers as a sound card
  (`narf-drivers-sound`, driver `snd-usb-audio`): PCM leases select
  alts at prepare, program rates, and run a per-stream isochronous
  pump; FeatureUnit volume/mute surface as ALSA controls. Unbind
  unregisters the card and drops the registry entry.
- **CDC** (`cdc`): shared CDC functional-descriptor parser
  (Header / Union / Country / ACM / NCM / ECM subtypes), CDC-Comm
  + CDC-Data class-triple constants. Used by the per-subclass
  drivers below.
- **CDC-ACM** (`cdc_acm`): Abstract Control Model (USB serial)
  codec. `LineCoding` builder/parser (baud + data bits + parity +
  stop bits), `SET_LINE_CODING` / `GET_LINE_CODING` /
  `SET_CONTROL_LINE_STATE` setup-packet builders, `SerialState`
  notification decoder, ACM functional-descriptor capability bits.
- **DFU** (`dfu`): USB Device Firmware Upgrade 1.1 codec.
  Class triple constants for runtime + DFU modes, DFU Functional
  Descriptor parser (handles both 7-byte DFU-1.0 and 9-byte
  DFU-1.1 forms), all 7 class-specific SETUP-packet builders
  (DETACH / DNLOAD / UPLOAD / GETSTATUS / CLRSTATUS / GETSTATE /
  ABORT), 6-byte status-block decoder + DfuState (11 variants)
  / DfuStatusCode (16 variants) enums.
- **CDC-NCM** (`cdc_ncm`): Network Control Model 1.0 codec for
  USB-Ethernet. NTB-16 framing — NTH16 (signature, header length,
  sequence, block length, NDP index) + NDP16 (datagram-pointer
  table with per-datagram offset + length entries). Encoder
  packs N Ethernet datagrams into a single NTB; decoder validates
  signatures + bounds and yields a borrow per datagram.
  `NCM_NTB_PARAMETERS_STRUCTURE` decoder for the device-reported
  size limits.

### Out of scope (deferred)
- UAC3 (protocol byte 0x30; descriptor layouts differ again).
- UAC mixer/selector-unit routing beyond Feature Units, and runtime
  clock-selector switching (bind resolves one clock per stream).
- Non-QCA Bluetooth vendor firmware protocols (Intel, Realtek, MediaTek,
  Broadcom).
