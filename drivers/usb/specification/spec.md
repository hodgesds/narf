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
  `READ CAPACITY(10)`, and the `(16)` forms for > 2 TiB media).
- **SCSI Primary Commands - 4 (SPC-4)** — `REQUEST SENSE` and the
  fixed-format sense data (sense key / ASC / ASCQ) used for error
  reporting and the retry policy.

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
- **Universal Serial Bus Device Class Definition for Video Devices:
  Stream Based Payload, Revision 1.5** — USB-IF. Public. §2.1
  (payload header — FID/EOF meaningful only per `bmFramingInfo`
  D0/D1), §2.2 (packet-oriented iff `dwPacketLength` non-zero, else
  byte-oriented; empty (micro)frames legal mid-stream), §3.1.1
  (24-byte `VS_FORMAT_STREAM_BASED` descriptor).

### UVC payload header (1.5 §2.4.3.3)

- **UVC 1.5 §2.4.3.3** "Video and Still Image Payload Headers" —
  USB-IF. Public. Bit Field Header layout (FID toggle, EOF, PTS
  flag, SCR flag, payload-specific bit D4 — assigned by the
  individual payload specification, NOT reserved — SI flag, Error,
  EOH). The header is shared across format classes: frame-based
  and temporally-encoded formats use this same header.
- **UVC 1.5 §2.4.3.4** "Source Clock Reference and Presentation
  Time Stamp" — USB-IF. Public. PTS = LE 32-bit; SCR = LE 32-bit
  SOF tick + 11-bit clock counter packed across 6 bytes.
- **UVC 1.5 §2.4.3.7** "Data Format Classes" — USB-IF. Public.
  Frame-based formats require FID; temporally-encoded formats
  (H.264, VP8) require EOF and the EOS slice marker; stream-based
  formats leave FID/EOF optional.
- **UVC 1.5 §4.3.1.1** "Video Probe and Commit Controls" — USB-IF.
  Public. Version fields carry the payload-format-spec minor
  version (1–255); the host inits them to zero on the first Probe
  SET, the device returns its preferred version plus its supported
  [min, max] range, and the host may only pick a preferred value
  inside that range (host must not alter min/max).

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

- Multiple xHCI controllers: every controller that probes is brought up and
  retained as `xhci<N>` (`Xhci::id() == N`, probe order, at most
  `xhci::MAX_CONTROLLERS`); a controller whose bring-up fails logs its error
  and does not prevent the others. `xhci::controllers()` lists them,
  `xhci::controller_by_id(id)` resolves one, and `xhci::first_controller()`
  exists only for callers with no device context (diagnostics, fixtures).
  Slot ids and root-port numbers are unique only within a controller, so
  every binding carries its controller: slot/port-keyed registries are
  `xhci::PerController` (one registry per controller: hubs, boot/report
  keyboards, mice, touchpads, RMI/Elan touchpads, consumer, generic HID, ACM, vendor serial,
  xpad), and index-keyed records (MSC, fingerprint, CDC-NCM/ECM, r8152, UVC,
  UAC, CCID, CTAP, btusb) store a `controller` field. Per-slot detach and
  recovery teardown take the controller (`attach::detach_all_bindings(id)`,
  `class_registry::UsbUnbindFn = fn(controller, slot)`), and device paths
  (devfs, block, net, sound, video) reach their own controller via
  `controller_by_id`. One supervisor task runs per controller; a controller
  bound after the supervisors start gets its own. The interrupt handler
  services every controller. System PM halts/resumes every controller, and
  class resume replays run per controller.
- Runtime suspend dispatch is
  `class_registry::dispatch_suspend(controller, hub_slot, port)`;
  `UsbSuspendFn` receives the same three coordinates. r8152, CDC-NCM,
  CDC-ECM, btusb and UVC match the controller before selecting a record or
  vetoing a port suspend. Resume and `suspended_hub_ports(controller)` wake
  snapshots use the same identity, including when two controllers assign
  the same slot and downstream port. Detaching one controller's device
  preserves the other device's interface and devfs/sysfs publication.
  Class drivers and suspend hooks each have a 32-entry registration budget;
  repeated registration under the same name does not consume another entry.
- UVC registry indices are append-only. Detach marks matching entries retired,
  stops their streams, releases descriptor/control tables and withdraws video
  nodes. Indexed operations reject retired entries. Removing a camera never
  shifts another camera's capture-pump or pending-control index; a replug
  receives a new index and video node.
- Before an installed `narf.disks=root-ro|root-rw` root is mounted, USB late
  initialization primes the normal supervisors (one per controller; the
  root may sit behind any of them) if the unique `root=UUID=` is
  valid but not registered. This wait is bounded to 30 seconds and uses the
  synchronous spin bridge outside the executor, without holding a lock.
  The same pinned supervisor futures are then spawned, preserving claimed
  ports, pending transfers and hub state; enumeration is not restarted.
  An already registered root incurs no wait. A missing or ambiguous root
  still fails through the normal root selector and disk-policy checks.

- `UsbHub::attach(xhci, slot_id, iface_num, device_protocol, speed, config)`
  binds an addressed, configured hub. A high-speed protocol-2 hub must expose
  a multiple-TT alternate for that interface; if it refuses `SET_INTERFACE`
  the hub continues single-TT in alternate 0 (Linux `hub_configure`).
  `interface_alt` and `interface_protocol` retain the selected mode;
  `is_multi_tt()` describes that active mode, rather than the Device
  Descriptor capability. `Xhci::mark_as_hub(slot, ports, multi_tt, ttt)`
  programs Hub, MTT, Number of Ports and (high-speed hubs) TT Think Time with
  Configure Endpoint on a copy of the slot context; its failure prevents
  publication of the hub and downstream children. Hub port power-on waits
  `bPwrOn2PwrGood` (at least 100 ms); a hub port reset waits 10 ms before the
  first status read, allows 800 ms and then 50 ms of reset recovery.
- `hid::BootKeyboard::attach(..., identity: InputId)` publishes an evdev
  keyboard only after protocol selection and interrupt-IN arming succeed.
  Its live report pump uses the shared evdev-aware keyboard decoder, sending
  key/modifier transitions to both the console ring and `/dev/input/eventN`.
  Unplug, controller recovery and binding destruction release held keys and
  remove the evdev node. The USB identity comes from the Device Descriptor.
- HID boot-interface selectors return an endpoint together with its owning
  alternate-zero interface. Declared boot interfaces take precedence over
  subclass-zero compatibility matches; a declared boot mouse prevents its
  auxiliary non-boot keyboard interface from claiming the whole device.
- `HubDescriptor::tt_think_time()` returns the USB 2.0
  `wHubCharacteristics[6:5]` encoding programmed into the high-speed hub's
  own xHCI Slot Context. A low/full-speed child's `Topology` carries the TT
  hub slot and port plus `mtt` (set when the hub runs multiple TTs).
- Hub downstream idle-suspend: the supervisor marks ports bound via
  `attach::mark_ports_bound`, which also stamps each port's
  last-activity tick (a port's idle window runs from bind). Class
  drivers feed `attach::mark_port_activity` on each completed
  transfer and call `attach::resume_port` before a transfer to a
  port that may be suspended. `msc::try_bind_msc_already_addressed`
  takes the device's hub context — (parent hub slot id,
  downstream port), `None` on a root port — and `MscDevice` records
  it as `hub_port`; its BOT funnels resume-then-feed on every
  transaction. The slot id, not a `HUBS` index, is the context key:
  hub detach removes a `HUBS` entry with `retain`, shifting every
  later index, so a cached index silently retargets after a detach
  (#892); every use resolves the hub by slot id under one lock
  hold. The pumped HID classes (boot keyboard, boot mouse,
  PTP touchpad, RMI/Elan touchpad, consumer control, generic HID) record the same `hub_port`
  context through their `try_bind_*_already_addressed` binders;
  their pumps feed on each completed interrupt-IN report, and the
  supervisor resumes suspended HID-bound ports immediately before
  the pumps each cycle (`hid::resume_suspended_hub_ports`),
  opening a fresh idle window — a suspended port gates the very
  interrupt endpoint the pump polls, so the resume has to come
  from the supervisor side of the pump, not from report traffic.
- USB-HID RMI4 / Elan touchpads (issue #1681): after the PTP branch
  in the attach cascade, `hid::rmi_elan` classifies by VID/PID
  against the existing `RMI_DEVICE_TABLE` / `ELAN_DEVICE_TABLE`
  (Elan I2C-HID rows never match on USB), binds the HID interface
  (Elan prefers interface 1, per Linux `hid-elan.c`), and probes
  through a synchronous `HidIo` / `ElanHidIo` backend over xHCI
  (interrupt-OUT output reports, control SET_REPORT Feature
  reports, control GET_REPORT Feature reads, bounded interrupt-IN
  wait). The sync backend bridges to the async xHCI control path
  with `block_on_spin` (the `btusb` precedent — the halting
  `block_on` would panic inside the supervisor's executor poll).
  A failed vendor probe falls back to generic HID for the same
  interface (`hid::generic::try_bind_generic_already_armed`, which
  does not re-arm the already-armed interrupt-IN endpoint), so the
  device is never dropped by this branch. The generic HID pump is
  wired into the supervisor's pump cycle so fallback bindings
  actually deliver reports.
- NIC idle-suspend (#1256): the USB NIC drivers (r8152, CDC-NCM,
  CDC-ECM) participate in hub idle-suspend through a class
  suspend-hook registry (`class_registry::register_suspend_hook`,
  `dispatch_suspend`) alongside the class-driver registry.
  Registry probes and the NCM/ECM walk arms receive the same
  hub context — (parent hub slot id, downstream port), `None`
  on a root port — and each NIC record stores it as `hub_port`
  plus a `suspended` park flag and a `wakeup_armed` flag. The
  supervisor's `idle_suspend_pass` calls `dispatch_suspend`
  with the controller ID for a candidate port BEFORE gating it (a gated port blocks
  all transfers, including the arming transfer); if any hook
  reports a failed park, gating is skipped that cycle and
  retried next cycle. Hooks are async (a sync hook bridging
  with `block_on` would panic inside the supervisor's executor
  poll) and self-filter by controller and hub context; they never hold their
  record lock across an await. Per-family park shapes: all
  three pumps park in place (yield without transfers, error
  counts, or link sampling; `pump_running` stays true, so
  resume needs no re-spawn) and detach dominates park. r8152
  additionally reprograms its chip wake filter from the
  bind-time snapshot via `apply_wol` — a failed filter program
  is `ParkFailed`, because gating without the wake filter
  would leave the device unable to wake on magic packet — and
  then issues SET_FEATURE(DEVICE_REMOTE_WAKEUP) (USB 2.0
  §9.4.2, feature selector 1, device recipient, `wIndex` 0);
  a stall on that transfer only clears `wakeup_armed` and the
  park still proceeds. NCM and ECM have no chip wake filter,
  so their hooks arm remote wakeup only. NIC pumps mark port
  activity only on delivered frames, never on empty polls, so
  an idle NIC still becomes a suspend candidate after the 30 s
  window; a TX-demand resume (send path resumes a parked port
  first, fails fast if resume fails, and opens a fresh idle
  window) wakes a parked device for traffic, following Linux
  usbnet runtime-PM semantics. The supervisor's wake-watch
  step (`wake_suspended_nic_ports`, after `resume_bound_ports`
  and before the pumps) resumes a parked NIC port only on an
  observed remote-wakeup edge — the `C_PORT_SUSPEND` change
  bit (bit 2 of the high half, i.e. bit 18) of the hub port
  status word — because an unconditional resume would defeat
  autosuspend and WoL. r8152 link state restores via the
  pump's existing 32-turn sampling once unparked; ECM link
  state re-reports via its notification pump. Root-port NICs
  never park (no hub to gate them). SuperSpeed/U3 is out of
  scope: the hub layer is USB-2.0-centric, so this covers the
  USB 2.0 port_suspend/port_resume path; an SS device whose
  SET_FEATURE(DEVICE_REMOTE_WAKEUP) stalls parks unarmed.
  Merge-order notes: the r8152 RX-checksum verdict (#1374) is
  driver-local pure logic, unaffected by suspend; the pending
  PLA_RMS MTU write (#1375) is applied by the RX pump on its
  next turn — whoever lands second must verify the park check
  sits before transfers but does not bypass a pending
  application, so the first post-resume pump turn still
  applies it.
- Fingerprint matching has a single authority (issue #918):
  `narf_drivers_fingerprint::FINGERPRINT_DEVICES` (31 entries: the
  scaffold table union the pre-#918 USB table). The USB binder owns
  no table of its own; `fingerprint::classify_vid_pid` maps the
  authority's `Family` to the transport vendor (`FpVendor`:
  Synaptics/Goodix/Validity → bulk-IN + bulk-OUT, ELAN →
  interrupt-IN), and `fingerprint::find_fp_endpoints` resolves
  endpoints from the configuration blob. A device whose blob lacks
  its vendor's endpoints fails with `EndpointsMissing` and falls
  through the attach cascade; it never binds with a bogus pair.
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
- Fingerprint readers publish one `/dev/fp<N>` node per bound reader
  through the devfs provider registry (`fingerprint::lookup_fp` /
  `enumerate_fp`, installed by the `usb-fp-devfs` initcall). The
  node index is the `FP_DEVICES` registry index: the first bound
  reader is `fp0`, the second `fp1`, and so on; lookup and
  enumeration agree by construction, so readdir never advertises a
  phantom node. There is no static `fp0` entry and no separate
  node global anymore (#920).
- The fingerprint bind, data-plane, and WBDI-recognition paths
  talk to the controller through one seam, `fingerprint::FpTransport`
  (issue #923): endpoint configuration, SET_CONFIGURATION, bulk
  transfers, interrupt-IN arm/poll, and EP0 control transfers.
  Production implements it as `XhciFpTransport` (resolving the
  controller by id per call); the attach cascade builds it for the
  controller it holds, and `/dev/fp<N>` nodes carry it, so the
  bind conversation (`try_bind_fingerprint_already_addressed`),
  the WBDI conversation (BOS fetch → vendor request → bridge),
  and node read/write are all fixture-testable against a modelled
  device. `lookup_fp` consults a test-only transport override so
  fixtures can drive the devfs-returned node over the model.
- The `/dev/fp<N>` control surface is two NARF-local ioctls
  (Linux `_IOC` encoding, type `'P'`, 0x50):
  `FP_IOC_CTRL_TRANSFER` (nr 0) issues one EP0 vendor control
  transfer, and `FP_IOC_GET_INFO` (nr 1) returns a packed `u64`
  (slot id bits 0..8, vendor code bits 8..16 — Synaptics 0, Goodix
  1, ELAN 2, Validity 3 — IN DCI bits 16..24, OUT DCI bits 24..32) so a daemon
  enumerating nodes can tell readers apart. The control-transfer
  argument is a 24-byte little-endian struct: `bm_request_type`
  `[0]`, `b_request` `[1]`, `w_value` `[2..4]`, `w_index`
  `[4..6]`, `data_len` `[8..12]` (in: requested length; out:
  actual length), `data_ptr` `[16..24]` (userspace buffer).
  Only vendor-type requests to the device recipient are issuable:
  standard requests (including `SET_CONFIGURATION` /
  `SET_INTERFACE`, which the driver owns) and class or
  other-recipient requests are rejected before any transfer, and
  `data_len` is capped at 4096 (the xHCI control data-stage cap).
  IN short reads are normal and return the actual count (also
  written back into `data_len`); OUT short transfers are errors,
  mirroring `send_command`'s full-transfer rule. A zero-length
  transfer has no data stage, so `data_ptr` is never dereferenced
  for one. The synchronous `ioctl` stays `Unsupported`: control
  transfers await USB transfers, so only the async `ioctl_user`
  dispatches them.
- Opening a `/dev/fp<N>` node requires the caller to hold
  `CAP_SYS_RAWIO` (Linux capability 17), checked in
  `open_instance_checked` after DAC checks, for reads as well as
  writes: reads return biometric images and writes issue sensor
  commands. The check fails closed while userspace has not
  installed the capability hook. The capability choice is a
  design decision, not a spec claim: no Linux capability names
  fingerprint sensors, and the raw sensor command channel is
  raw-hardware access. (#1237's WBDI bridge rebased onto the
  provider in the same change — its first device then gets `fp0`
  automatically.)
- `Xhci::get_device_descriptor(slot_id)` first reads the mandatory 8-byte
  descriptor prefix, validates and applies `bMaxPacketSize0` through Evaluate
  Context, then returns only a complete 18-byte Device Descriptor. Callers may
  therefore read `idVendor`/`idProduct` at offsets 8..12 without accepting a
  zero-filled short response.
- USB HID evdev identity (`hid::identity`, issue #874): the mouse,
  touchpad, generic, and evdev-registering keyboard binders resolve
  identity at bind time via `resolve_usb_identity` — `idVendor` /
  `idProduct` / `bcdDevice` from the device descriptor (USB 2.0
  §9.6.1 offsets 8..14), the product string via `GET_DESCRIPTOR
  (STRING)` (LANGID from string-0, en-US 0x0409 fallback; `iProduct
  == 0` or any fetch failure falls back to a per-class name), and a
  NARF-local phys (`usb-{port}` on a root port, `usb-{hub}-{port}`
  downstream, where `hub` is the parent hub's xHCI slot id at bind
  time) — applied with `DeviceCaps::set_identity` on `BUS_USB`,
  `uniq` empty. Binders pass the topology as `hid::identity::
  BindTopology { port, hub_port }` where their parameter count
  would otherwise exceed clippy's argument limit (touchpad), or as
  separate `port` + `hub_port` arguments elsewhere. Resolution is
  best-effort: on descriptor-fetch failure the binder keeps
  synthetic caps and the bind proceeds, so identity can never
  regress a working bind. Deliberately out of
  scope: the live boot-keyboard path feeds the shared input ring
  and owns no evdev node by design, and no USB MT publication
  exists (the USB touchpad is relative-mode only).
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
- Isochronous transfers (`Xhci::isoch_in` / `Xhci::isoch_out`, #885) carry
  the same completion-identity contract as bulk: `begin_isoch_in` /
  `begin_isoch_out` submit one 1..4096-byte Isoch TD (SIA, IOC set,
  xHCI 1.2 §6.4.1.3) and return an `IsochToken` naming the slot
  generation, endpoint, private submission serial, direction, and
  originating Isoch TRB; only that TRB's exact Transfer Event
  (§6.4.2.1: TRB Pointer, Completion Code, residue) can retire the
  submission, latched into the endpoint's own owner state by the
  event demux — never the lossy shared transfer-event queue. Short
  Packet (CC 13) is a normal completion in either direction for
  isochronous transfers. At most one isoch TD is in flight per
  endpoint; a second begin is `NotReady` before touching the scratch
  page or ring. The compatibility `isoch_in` / `isoch_out` wait the
  token, and on timeout retire the posted TRB first — Stop Endpoint
  + Set TR Dequeue Pointer via the same coordinator as `stop_bulk`
  (`Xhci::stop_isoch`, also callable directly) — then report the
  timeout, so a late completion can never alias the next transfer.
  A failed stop keeps the endpoint claim closed rather than risking
  silent misattribution. Multi-TRB isoch pipelining (depth > 1) is
  out of scope here: the one-shot path stays depth-1, which is what
  the UVC pump seam (#1672) advertises.
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
- `r8152` binds with a version-switched PHY init: the chip version
  decoded from the `PLA_TCR1` field selects a table of OCP/SRAM/MDIO
  register writes (EEE/ALDPS configuration, flow-control
  advertisement) executed before CR RE/TE enable; RTL8153
  VER_03–VER_06 tables are implemented, other versions run on
  reset defaults. After bind it advertises TX checksum, TSO,
  VLAN-insert and RX checksum offloads via `iface::set_offloads`;
  TX metadata the hardware cannot encode is rejected, and TCP
  super-frames fall back to the stack's software GSO splitter.
  RX checksum is decoded from the v1 RX descriptor report bits
  (`opts2` `RD_IPV4_CS` / `RD_IPV6_CS` / `RD_TCP_CS` /
  `RD_UDP_CS`, `opts3` `RX_IPF` / `RX_UDPF` / `RX_TCPF`): a
  device-verified corrupt frame is dropped in the RX pump, since
  the stack has no RX metadata consumer and a mark would be dead
  data — the drop is the outcome software verification would
  produce. The one exception is an IPv4/UDP frame with a zero
  checksum field (legal "no checksum" per RFC 768), which is
  delivered despite a UDP fail bit; contradictory descriptors
  fail closed to drop. The v1 RX walk follows Linux `rx_bottom`:
  the `opts1` length counts frame + FCS (`ETH_FCS_LEN` = 4), the
  walk delivers length − 4 bytes, and the next descriptor starts
  at the next 8-byte boundary (`RX_ALIGN`). The RTL8157 (VER_16)
  uses the v2 descriptor layout instead (16-byte `rx_desc_v2` /
  `tx_desc_v2`): RX length in `opts1` bits 17..31 counting frame
  + FCS (the walk strips the FCS and aligns segments to 16
  bytes), VLAN present-bit in `opts1` bit 3 with the TCI in the
  high half of `opts2`, all checksum report/fail bits in `opts3`;
  TX adds `opts3 = len << 4` and `opts4 = TX_SIG` with a tighter
  checksum transport-offset cap (0x3FF). RX VLAN tags are delivered in-band: with VLAN
  receive enabled the driver splices the tag reported in the RX
  descriptor back into the frame for the stack. Wake-on-LAN options are snapshotted from the device
  at bind and programmed through the `PLA_CRWECR` config window
  (`MAGIC` / link-on-wake / unicast / broadcast / multicast);
  USB remote-wakeup arming is not yet wired (per-NIC suspend
  remainder).
- `ax88179` binds the ASIX AX88179 (USB 3.0 GbE, reference PID
  `0b95:1790` only in v1) over vendor control transfers (`bRequest`
  is the access class: MAC `0x01`, PHY `0x02`, EEPROM `0x04`,
  EFUS `0x05`): MAC access packs `wValue` = register,
  `wIndex` = byte count; PHY access packs `wValue` = PHY id
  (`0x03`), `wIndex` = register. Bind runs the reset sequence
  (PHY power-up + IPRL, 500 ms, clock select, 200 ms, best-effort
  auto-detach, station-address read from `AX_NODE_ID`, bulk-IN
  queue config, pause watermarks, checksum controls, RX control,
  monitor mode, giga medium mode, autoneg restart) and publishes
  as `usb-ax{N}` with the same tombstone-detach and no-invented-
  address rules as `r8152`. TX prepends an 8-byte header (length
  + zero GSO size in v1 + padding flag when `(len + 8) %
  maxpacket == 0`); RX parses concatenated-frame bulk buffers with
  a trailing `rx_hdr` (`pkt_cnt`/`hdr_off`) and per-packet metadata
  (CRC/DROP errors and runts dropped, dummy headers skipped).
  Audit item 2 is implemented on top: the interrupt-IN endpoint
  (found by the shared r8152 finder walk) feeds a status task
  that decodes the link bit (first word, bit 16) and, on
  link-up, runs the Linux link-change sequence (TX FIFO quiesce
  poll, PHYSICAL_LINK_STATUS + PHYSR read, bulkin/medium
  programming, speed + duplex reporting); TX checksum offload
  is advertised (`tx_checksum`, RX checksum deliberately not —
  no verdict channel in `on_rx_frame_from`) and the multicast
  filter is programmed via the stack's `DeviceControl` hook
  (Linux `set_multicast` semantics, `ether_crc` filter hash).
  VLAN and jumbo frames remain follow-ups (ungrounded per
  audit §6).
- `r8152` installs an `iface::DeviceControl` at bind, so registry
  MTU changes validate against the chip version (68..=1500 for
  FE / unknown versions, 68..=9194 / 15338 / 16362 for the GbE
  version classes, matching Linux's probe switch) and reprogram
  `PLA_RMS` to MTU + 22 (VLAN header + FCS) on GbE; FE versions
  never reprogram, matching Linux, which leaves `PLA_RMS`
  untouched for VER_01/02/07. Because `configure` is synchronous
  and USB control transfers are async, the hook records a
  pending bound the RX pump applies on its next turn; registry
  metadata commits after validation, with hardware following
  within one pump turn. Version-specific FIFO tuning from
  Linux's `change_mtu` variants (`PLA_MTPS`, `PLA_TXFIFO_*`) is
  not programmed by this path.
- `lan95xx` is the core driver for the SMSC/Microchip LAN95xx
  USB 2.0 10/100 family (LAN9500 / 9500A / 9512 / 9514 / 9530 /
  9730 / 89530, issue #788): vendor control transport (`0xA1` /
  `0xA0`, `wValue = 0`, `wIndex = register`), lite reset in
  Linux's order, internal-PHY autoneg via `MII_ADDR` / `MII_DATA`,
  EEPROM station address (offset `0x01`), TX command-word
  framing with checksum-preamble offload, RX status-header
  framing with FCS stripping, publication as `usb-lan95xx{N}`,
  and detach. Register values are Linux-driver-observed
  (`smsc95xx.c` / `smsc95xx.h` @ cbbddb6); no public LAN95xx
  datasheet copy exists in the workspace. Deliberate limits:
  station address from EEPROM only (a device reporting no valid
  address fails the bind; the EEPROM-less fallback is a
  follow-up); external PHY fails the bind; link state is
  published once from the bind-time PHY read (the
  interrupt-endpoint link-change task is a follow-up);
  multicast programming is not implemented (receive-own only);
  RX checksum offload stays disabled (no RX verdict channel on
  the USB RX path); no TSO, no VLAN insert/strip, no
  suspend/WoL, no hub-combo verification yet.
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
- The supervisor drives root and hub enumeration to a terminal result using
  the hardware operations' individual deadlines. It does not cancel an
  in-flight owner at a whole-port deadline. Pending enumeration and hub-status
  waits service existing nonblocking report pumps, with bound suspended ports
  resumed before the first pump in each supervisor cycle.
- Terminal enumeration failures and device detach share slot cleanup. They
  await successful Disable Slot completion before reclaiming the reservation
  and retained DMA, so a retry can address the hardware's returned slot under
  a fresh generation. Failed or cancelled disable operations do not reclaim.
  Class probes that merely decline a device still leave its addressed slot
  available to later probes; cleanup runs only at the terminal failure.
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
  hook from `register_class_driver_with_unbind`; a hook reports
  failure with `Err(())` and dispatch continues past it, so one
  hook's failure never aborts detach for every class (#893) —
  a hook that panics cannot be contained (panic is fatal by
  kernel policy), so hooks must be panic-free and idempotent),
  a hub's bound subtree
  is detached recursively and its `HUBS` entry removed, then the slot is
  disabled and reclaimed (`Xhci::reclaim_slot`) so a replug re-runs
  attach from scratch. A controller recovery epoch change drops every
  binding wholesale (`attach::detach_all_bindings`) and re-enumeration
  follows; on that path the pumped classes are cleared from their
  registries and every MSC device is removed and unpublished
  (`msc::unbind_all_msc`), every CDC-NCM / r8152 / CDC-ECM binding is
  tombstoned and its net iface unregistered
  (`cdc_ncm::detach_all_ncm`, `r8152::detach_all_r8152`,
  `cdc_ecm::detach_all_ecm`), and
  every UVC binding is dropped and its video node unregistered
  (`uvc::detach_all_uvc`), and every bound fingerprint reader,
  including WBDI-bridged sensors, is removed and unpublished
  (`fingerprint::unbind_all_fp`, #922).
  On the per-slot detach path, classes
  the supervisor does not pump (CCID) get
  the slot disable + reclaim but no class-registry removal yet;
  the remaining non-pumped classes keep their registries across
  recovery as well. btusb is not in that set: its unbind hook
  (`btusb::detach_btusb_slot`, registered in
  `btusb::register_initcalls`) runs on the per-slot path via
  `dispatch_unbind` (see below), stopping the pump and unregistering
  the controller (mgmt INDEX_REMOVED, sysfs removal, BTUSB_DEVICES
  removal; #890). CDC-NCM and r8152 are not in that set: their
  unbind hooks run on the per-slot path via `dispatch_unbind`
  (see below). UVC is not in that set either: its unbind hook
  runs on the per-slot path via `dispatch_unbind` (see below).
  UAC is not in that set either: its unbind hook
  (`uac::detach_uac_slot`, registered in `uac::register_initcalls`)
  runs on the per-slot path via `dispatch_unbind` (see below),
  dropping the slot's UAC devices and unregistering their sound
  cards (#1318).
- Fingerprint lifecycle (#922): per-slot detach runs through the
  class-registry unbind dispatch — `fingerprint::detach_fp` removes
  every `FP_DEVICES` entry for the slot, and its outcome reports
  whether the removed set included the pre-removal index-0 entry
  (the `/dev/fp0` name's occupant; bind only appends, so the
  occupant can only leave index 0 by being removed). This includes
  WBDI-bridged readers: recognition is stateless and binding places
  them in `FP_DEVICES`, so there is no separate WBDI teardown hook.
  The fingerprint hook is infallible and idempotent, registered with
  a never-claim probe (empty matches) so the cascade keeps binding
  fingerprint. Nodes are provider-resolved
  from the registry by index (#920, merged as #1238): removal itself
  unpublishes, and a survivor now at index 0 resolves as fp0 —
  detach performs no renumbering. Suspend/resume
  runs through the `usb-fp` async system-PM hook: prepare is a
  no-op (no pump, no background task, transfers are synchronous
  per-call); resume fails loudly with `DriverError` when the xHCI
  controller never came back while devices are still bound, and
  otherwise resets every ELAN interrupt-IN arming flag (the
  controller fan-out rebuilds endpoint state, invalidating the
  staged TRB; the next read re-arms). A device unplugged while
  suspended is not validated at resume — the supervisor's
  disconnect polling detaches it on the next cycle.
- `find_video_streaming_endpoints(config)` returns each UVC bulk/isochronous IN
  endpoint with its owning interface and alternate setting.
  `select_video_streaming_iso_endpoint(endpoints, payload)` chooses the smallest
  alternate that satisfies the PROBE-accepted payload; when no isochronous
  alternate qualifies, activation falls back to
  `select_video_streaming_bulk_endpoint(endpoints)` (least-bandwidth bulk
  alternate, no payload gate — bulk transfers reserve no interval
  bandwidth, so the PROBE figure is not a per-transfer cap there), and
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
  endpoint configuration, isochronous receive, bulk receive); production implements
  it on `Xhci`, and the end-to-end kernel fixture
  (`smoke_uvc_streamon_composition_e2e`) implements it on a modelled
  camera and asserts the transfer conversation through the real V4L2
  dispatch. The pump receives through a single receive call site that
  dispatches on the active endpoint's transport (`isoch_in` /
  `bulk_in`); isochronous streams whose transport advertises
  `isoch_pipeline_depth() > 1` run the pipelined receive (#808,
  `pump_video_frames_pipelined`), which adopts the video crate's
  depth-4 `IsocScheduler` over the owned-buffer receive
  (`isoch_in_owned`, one buffer per in-flight transfer, packets fed
  in submission order) and is proven by the high-bandwidth fixture
  (`smoke_uvc_isoc_pipeline_high_bandwidth`: six four-packet frames,
  `ISOC_DEPTH` transfers observed in flight at once, frames
  dequeued byte-exact and in order). Bulk streams and depth-1
  transports stay on the single-shot receive. The live `Xhci`
  transport advertises depth 1 — its isochronous transfers share
  one 4096-byte DMA page per endpoint and completions carry slot +
  endpoint identity only — so multi-TRB pipelining on hardware
  awaits #885 (per-transfer buffers and TRB identity).
- UVC suspend/resume (#807): the binders take the device's hub
  context — (parent hub slot id, downstream port), `None` on a root
  port — and `UvcDevice` records it as `hub_port`, the device-accepted
  PROBE/COMMIT values as `last_stream`, and the stream live at
  suspend as `suspended_stream`. System suspend runs the async
  system-PM hook (`uvc::register_pm`, `narf_power::system_pm`):
  prepare latches the quiesce flag (STREAMON then fails busy) and
  runs the STREAMOFF teardown (pump stop + alternate setting 0) for
  every streaming camera, recording its parameters; resume
  re-negotiates (PROBE/COMMIT) and re-activates each recorded stream
  and respawns its pump. A synchronous device-PM backstop
  (`narf_power::device_pm`, same registration) only latches the flag
  and stop-requests the pumps — it cannot do I/O, so it never selects
  alternate setting 0. Hub idle-suspend: the pump feeds
  `attach::mark_port_activity` on every completed transfer (a
  streaming camera never idles), the class suspend hook
  (`uvc::register`, `class_registry::register_suspend_hook`) vetoes
  gating a live stream (`ParkFailed`) and parks an idle camera
  (`Parked`), and STREAMON resumes a gated port before negotiating
  (`ensure_uvc_port_awake`).
- UVC payload headers (1.5 §2.4.3.3) are decoded by
  `uvc::UvcPayloadHeader::parse` (mirrored by `narf-drivers-video`'s
  `PayloadHeader::decode`) for every format class: frame-based
  formats and temporally-encoded formats (H.264/VP8,
  `VS_FORMAT_FRAME_BASED`) share the §2.4.3.3 header (HLE + BFH +
  optional PTS/SCR), with frame boundaries from the FID toggle and
  EOF completion (§2.4.3.7). BFH D4 is the payload-specific bit (not
  reserved) and is surfaced, not acted on; D5 (STI) reads as
  intra-coded for temporally-encoded streams.
- Stream-based completion (#1334, UVC 1.5 §2.4.3.7 + §4.3.1.1 Table
  4-47, Stream Based Payload 1.5 §2.1/§2.2/§3.1.1): stream-based
  formats (`VS_FORMAT_STREAM_BASED`, 0x12) carry boundaries in-band,
  so FID/EOF are optional — each bit is meaningful only when the
  negotiated `bmFramingInfo` says so (D0 = FID required, sender
  toggles FID at least every `dwMaxVideoFrameSize` bytes; D1 = EOF
  may be present). Both reassemblers (`uvc::UvcFrameReassembler`,
  mirrored by `narf-drivers-video`'s `FrameReassembler`) therefore
  take a `ReassemblyConfig`: in stream-based mode FID/EOF are
  honoured only per `bmFramingInfo`, and a segment completes when
  accumulation reaches the negotiated `dwMaxVideoFrameSize` —
  buffer-fullness completion, the fallback §2.4.3.7 names
  explicitly. That same negotiated size caps accumulation in every
  mode (a push past it is clamped, the frame completes at the bound,
  excess bytes are dropped and counted), so no stream can grow the
  buffer unbounded. The pump derives the config from the negotiated
  control retained on the device record at activation
  (`UvcDevice::negotiated`); a stream-based format is recognised
  from the retained format table (`VS_FORMAT_STREAM_BASED`
  descriptors are parsed into `PixelFmt::StreamBased` with no frame
  modes — frame size comes from Probe/Commit). Short or empty
  transfers are NOT boundaries: §2.2.1 allows empty (micro)frames
  mid-stream. Not yet wired: STREAMON selection of stream-based
  formats (no V4L2 fourcc mapping) and `bmFramingInfo` validation
  (D1/D2 without D0 is a device error per Table 4-47).
- GET_CUR(PROBE) version validation (#1244, 1.5 §4.3.1.1): on a
  34-byte (1.1+) response the device's preferred version must lie
  inside its own declared [min, max] range (device resets min/max
  to 1–255); a malformed triple fails negotiation (`ProbeFailed`)
  before any COMMIT is sent. The host's first-SET 0x10 declaration
  is a #1225 design choice, retained unchanged; the spec-correct
  encoding (payload-format-spec minor version, host inits to zero
  on first Probe SET) is documented on
  `VsProbeCommit::preferred_version` for future work.
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
  status from the 0xE4 WMT event). USB alias `0e8d:0616` enters the
  MediaTek path; setup verifies the chip register and selects the exact ROM
  revision/flavor firmware name before download. WMT length counts the flag
  plus data, raw patch flags 0/1/2 mean undone/progress/done, and events are
  polled through vendor EP0 request IN 1/value48 with the Linux 500us gap for
  empty replies. After download, endpoint reset options and WMT FUNC_CTRL
  protocol enable must succeed before generic HCI Reset. Transfers retain
  the original xHCI slot generation. For Realtek-quirk IDs the btrtl
  sequence (ROM version over 0xFC6D → security key id over 0xFC61 →
  epatch v1/v2 parse with the patch selected by ROM version + 1 and
  the file's project id verified against the product id's chip
  family, config bytes appended verbatim when the key id is zero →
  0xFC20 fragment download with the echoed fragment index
  verified); for Broadcom-quirk IDs the btbcm patchram upload
  (HCI_Reset → Download Minidriver over 0xFC2E → 50 ms delay →
  the `.hcd` command stream in file order → 250 ms delay); a failed
  vendor setup fails the bind. Firmware pairs are the
  `btusb_quirks::firmware_paths` names under the vendor prefix
  (`intel/`, `mediatek/`, `rtl_bt/`, `brcm/`). SCO/eSCO rides
  isochronous endpoints (issue #817): `find_bt_endpoints` records
  the isoch IN/OUT pair of every alternate setting of the HCI
  interface; bind configures the largest-budget complete alternate
  together with the base three endpoints and SET_INTERFACEs to it
  after SET_CONFIGURATION, and the registered transport carries SCO
  over `isoch_out` / `isoch_in` (`send_sco` / `recv_sco`), with
  `select_sco_alt_setting` switching down to the smallest alternate
  that fits a given payload. A device with no isoch endpoints still
  binds; its transport refuses SCO with
  `TransportError::Unsupported`, never routing it to bulk-OUT.
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
- `cdc_ncm::detach_ncm_slot(slot_id)` and
  `r8152::detach_r8152_slot(slot_id)` are the USB-Ethernet
  publication teardowns — tombstone every record bound to the slot
  (pump-stop flag set first, so a running pump exits on its own;
  the NCM pump additionally checks the tombstone at its loop top)
  and unregister each record's net iface via
  `narf_net::iface::unregister(name)`. Records are never removed:
  net-registry TX cookies are record indices, so removal would
  retarget every later device's cookie at the wrong device
  (the ECM rule); TX/RX on a tombstoned index fail closed
  (`NotNcm` / `None`). Both are registered as class-registry
  unbind hooks (`register_class_driver_with_unbind`) and reached
  via `dispatch_unbind` on the supervisor's detach path; NCM
  binding stays in the attach cascade and r8152 binding stays in
  its class-registry probe, and both probes decline nothing they
  previously accepted. `cdc_ncm::detach_all_ncm()` and
  `r8152::detach_all_r8152()` are the wholesale variants for
  controller-recovery teardown. `cdc_ecm::detach_ecm_slot(slot_id)`
  is ECM's equivalent slot teardown (same tombstone +
  unregister contract, collect-then-unregister so the net
  registry lock is never taken under the ECM registry lock)
  with `cdc_ecm::detach_all_ecm()` as its wholesale variant.
  Indices are not recycled; a
  replugged adapter republishes under a fresh index.
- `uvc::detach_uvc(slot_id)` is UVC's publication teardown — drop
  every `UVC_DEVICES` entry bound to the slot (capture-stop flag
  set first, so a running pump exits on its own) and unregister
  each entry's `/dev/video<N>` node via
  `video::devfs_bridge::unregister_video(index)`, which removes the
  node from the video registry by its `index` field, never by vector
  position, so no other node's minor is renumbered. It is registered
  as a class-registry unbind hook
  (`register_class_driver_with_unbind`, video class triple) and
  reached via `dispatch_unbind` on the supervisor's detach path; UVC
  binding itself stays in the attach cascade, and the registry probe
  always declines. `uvc::detach_all_uvc()` is the wholesale variant
  for controller-recovery teardown. Indices are not recycled; a
  replugged camera republishes under a fresh index. Known remainder:
  the `/sys/class/video4linux/video<N>` kobject has no in-tree
  removal API, so it lingers after detach; the live paths (devfs
  node, registry) are the ones withdrawn.
- `cdc_acm_bridge::register_tty_acm(transport)` / `unregister_tty_acm(index)`
  are the publish/withdraw pair for CDC-ACM's `/dev/ttyACM<N>` nodes
  (major 166): the ACM bind path registers after its endpoints are
  configured and armed, passing an `AcmTransport` seam (production:
  `XhciAcmTransport` over the bound `CdcAcmPort`); `cdc_acm::detach_acm` /
  `clear_acm` unregister every index the removed binding published.
  Indices are monotonic for the boot, as with ttyUSB.
- `serial::port` is the bind + transfer layer for vendor USB-serial
  adapters (FTDI, Silicon Labs CP210x, Prolific PL2303, WCH CH341 —
  dispatched by exact VID/PID via `serial::identify`, which no other
  driver claims). `try_bind_serial_already_addressed` is the attach
  cascade step: it selects the first vendor-class (0xFF) interface with
  a bulk pair from the configuration blob, configures the endpoints,
  issues `SET_CONFIGURATION`, executes the family's open plan, arms the
  bulk-IN endpoint, and publishes the port via `register_tty_usb`. A
  family's open/configure plan is a pure `ControlXfer` list built from
  the family codec encoders per the vendor programming guides (FTDI
  AN120/AN232B divisor + line encodings — BM/R divisor against the
  3 MHz effective base, H against 12 MHz; Silicon Labs AN571 request
  set with the baud rate as a data stage; PL2303 CDC line coding;
  CH341 register writes). `pump_all` (supervisor cycle) moves bulk-IN
  bytes into the tty RX ring — FTDI packets have their 2-byte status
  prefix stripped into the modem cache first, other families are raw —
  and submits tty TX ring bytes as bulk-OUT, removing them from the
  ring only on transfer completion. `set_line_settings` replays the
  configure plan on the live device; settings a family cannot express
  (e.g. CP210x `SET_FLOW`) fail with a typed `PortError::Unsupported`
  rather than a silent no-op. `detach_serial` / `clear_serial` are the
  per-slot and controller-recovery teardowns. One port per device in
  this layer: multi-port chips bind their first interface.
  Suspend/resume (#763): the `usb-serial-pm` Stage::Subsys initcall
  registers an async system-PM hook (`serial::port::register_pm`).
  Prepare quiesces `pump_all`; resume — after the synchronous
  device fan-out restores xHCI — replays each bound port's bind-time
  open plan (`resume_snapshot` / `resume_replay`), rebuilt from the
  retained `settings` the reconfiguration path commits only on full
  success, so line format, modem lines and flow state survive S3.
  A port whose slot refuses the replay fails the hook with a typed
  `DriverError` without stopping the other ports; a port that
  detached while suspended is absent and gets no replay. Bind
  records the (hub index, downstream port) a port sits behind, and
  the supervisor wakes suspended hub ports for live serial bindings
  before the pumps (`resume_suspended_hub_ports`), mirroring HID
  (#840). Plan execution goes through the `ControlTransport` seam
  (production: `Xhci`; fixtures: a recording fake), which
  `cdc_acm`'s replay shares.
- `serial::devfs_bridge` implements the ttyUSB termios + modem ioctl
  surface (#756) via `FileOps::ioctl_user`, at parity with ttyS0's
  devfs contract: TCGETS / TCSETS(W)(F) and the termios2 forms
  (BOTHER rates ride `c_ospeed`), TIOCMGET / TIOCMSET / TIOCMBIS /
  TIOCMBIC, TCSBRK, TIOCSBRK / TIOCCBRK, TCFLSH, TCXONC, FIONREAD,
  TIOCGWINSZ / TIOCSWINSZ; anything else returns `Unsupported`
  (ENOTTY). The node keeps the 36-byte kernel termios image verbatim
  (line-discipline bits round-trip; this pipe has no ldisc) and
  decodes its hardware-facing subset — baud, data bits, parity,
  stop bits, CRTSCTS — into `port::LineSettings`, actuated on the
  bound device via `serial::port::set_line_settings` /
  `set_modem_lines` / `set_break_state`; B0 drops DTR/RTS as a
  hangup without reprogramming the baud. Break is grounded for FTDI
  (SET_DATA bit 14) and CP210x (AN571 `SET_BREAK`); PL2303 and
  CH341 break encodings are not modelled and return a typed
  `PortError::Unsupported`. TCXONC's TCOOFF parks the pump's TX
  drain via the node's `tx_stopped` flag.
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
- WBDI fingerprint readers (issue #919): `wbdi` recognises a
  sensor by its MS OS 2.0 Compatible-ID (WINUSB with a WBDI
  sub-compatible-ID) and runs last in the attach cascade, after
  the VID/PID table bind — it catches only readers the table
  missed and never shadows a table bind. Recognition alone
  configures nothing; the cascade bridges a recognised reader
  into the fingerprint stack via
  `fingerprint::try_bridge_wbdi_already_addressed`, which
  discovers endpoints generically for the `FpVendor::Wbdi`
  vendor (bulk-IN + bulk-OUT preferred, interrupt-IN fallback —
  a design choice, not a spec claim, since no public spec pins
  a WBDI sensor's endpoint shape), issues SET_CONFIGURATION,
  configures the endpoints, and registers a
  `FingerprintDevice` in `FP_DEVICES`, which publishes as
  `/dev/fp<N>` by registry index via the devfs provider
  registry — the same consumer surface a table-bound reader
  gets. The bridge is non-fatal: on failure the outcome is
  still `WbdiFingerprint` and the slot stays alive as
  recognition alone left it, and a reader with no usable
  endpoint is never registered. The pre-#919 `WBDI_DEVICES`
  registry was deleted in the same change: it had no consumer
  anywhere in the tree, so it stranded every recognised reader.
  Detach removal for `FP_DEVICES` is the #922 follow-up, shared
  with the table path (append-only for now).

## Scope

### Target laptop USB profile (silicon validation pending)

| USB ID | Device | In-tree path | Remaining validation |
|---|---|---|---|
| `05e3:0610` | Genesys Logic USB 2.0 hub | Hub class enumeration, multiple-TT flag, TT think-time propagation, downstream route addressing | Boot on the target xHCI controller and enumerate every downstream port |
| `27c6:6594` | Goodix USB2.0 MISC fingerprint reader | Explicit Goodix match, vendor-class bulk-IN/bulk-OUT transport, `/dev/fp0` handoff | Userspace Goodix MOC enrol/match protocol |
| `138a:0011` | Validity VFS5011 fingerprint reader | Explicit Validity match (single authority table, #918), vendor-class bulk-IN/bulk-OUT transport, `/dev/fp0` handoff | Userspace Validity enrol/match protocol; silicon validation on a VFS5011-fitted machine |
| `10ab:9309` | USI/Qualcomm WCN6855 Bluetooth | Explicit WCN6855 quirk match, runtime version/status query, rampatch + board-NVM USB download, full mandatory HCI bring-up, ready-controller registration, and `hci<N>` sysfs publication | Production-sign the imported firmware and validate the full sequence on silicon |
| `8087:0032` | Intel AX210 Bluetooth (Renoir target) | Explicit Intel quirk match, version-TLV + boot-params read, `.sfi` secure-send download + Intel Reset boot + `.ddc` config, full mandatory HCI bring-up, ready-controller registration, `hci<N>` sysfs publication, HCI pump | Stage the `intel/ibt-*` blobs and validate the full sequence on silicon |
| `0e8d:0616`, `0e8d:7922` | MediaTek MT7922 Bluetooth (Phoenix target) | Explicit MediaTek quirk match, WMT 79xx RAM-code download (section probe + flagged chunks), full mandatory HCI bring-up, ready-controller registration, `hci<N>` sysfs publication, HCI pump | Stage the `mediatek/BT_RAM_CODE_MT7922_*` blob and validate the full sequence on silicon |
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
  TEST UNIT READY, REQUEST SENSE, READ CAPACITY(10), READ(10),
  WRITE(10). Bind issues GET MAX LUN (BOT §3.3; any failure means a
  single LUN) and binds every populated LUN as its own block device —
  empty slots in a multi-LUN reader are skipped, not fatal. A LUN
  whose READ CAPACITY(10) saturates at 0xFFFFFFFF escalates to READ
  CAPACITY(16); LUNs past 2 TiB use the 16-byte READ(16) / WRITE(16)
  command forms with 64-bit LBAs throughout the driver and adapter.
  The driver's read/write entry points chunk arbitrary-size requests
  internally into sequential BOT commands of at most 4 KiB (also at
  most eight logical blocks), so no caller has to split; the
  `BlockDeviceSync` adapter keeps one per-device claim held for the
  entire request. This supports 16 KiB btrfs metadata on both
  512-byte and 4 KiB logical-block media without exceeding the xHCI
  DMA buffer. The adapter also performs SYNCHRONIZE CACHE(10) for
  `flush()` and WRITE with the FUA bit for `write_fua()`, so its
  advertised Flush/FUA capabilities are issued on the wire (#829).
  FUA requests use the same bounded chunks and whole-request range
  validation as ordinary writes; every chunk carries FUA and the
  claim remains held until completion.
  Error recovery follows BOT §5.3/§6: a stalled pipe is cleared on
  both sides (host Reset Endpoint + device CLEAR_FEATURE) before
  the CSW is read; a Command Failed status is drained with REQUEST
  SENSE and the command retried once when the sense is a transient
  condition (UNIT ATTENTION, or NOT READY while the medium spins
  up) — any other sense fails the command with the parsed sense
  attached; a Phase Error or an invalid CSW triggers Reset
  Recovery (Mass Storage Reset + both pipes cleared) and one
  retry. The BOT exchanges sit behind a `BotTransport` seam so the
  conversation is fixture-testable without an xHCI.
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
  endpoint and bandwidth metadata; the negotiation path performs version-aware
  PROBE/COMMIT — 26-byte UVC 1.0 for bcdUVC < 0x0110, 34-byte UVC 1.1+
  (VC HEADER device clock + 1.0 payload-version declaration) otherwise —
  configures the smallest fitting isochronous alternate (bulk fallback
  when none qualifies, #1243), and issues
  SET_INTERFACE. Its capture task reassembles UVC payloads and delivers complete
  frames to the registered `/dev/video<N>` queue. STREAMOFF/cancellation
  remain follow-ups.
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
  volume/mute. For UAC2, when the resolved clock source is reached
  through a clock selector, bind first reads the selector's current
  pin (GET_CUR on the selector control, §5.2.5.2.1) and switches it
  to the resolved source's pin (SET_CUR, issued only when the pin
  differs; skipped for single-pin selectors and absent controls).
  MIXER_UNIT descriptors decode in both revisions (per-input-channel
  × output-channel programmable-gain matrix, MCN-addressed) and
  SELECTOR_UNIT descriptors decode alongside them; the topology walk
  traverses mixer/selector units in both directions, so a Feature
  Unit behind a mixer/selector unit is found and its volume/mute
  controls are programmed like a directly-linked one. The bound device registers as a sound card
  (`narf-drivers-sound`, driver `snd-usb-audio`): PCM leases select
  alts at prepare, program rates, and run a per-stream isochronous
  pump; FeatureUnit volume/mute surface as ALSA controls. Unbind
  unregisters the card and drops the registry entry.
- **CDC** (`cdc`): shared CDC functional-descriptor parser
  (Header / Union / Country / ACM / NCM / ECM subtypes), CDC-Comm
  + CDC-Data class-triple constants. Used by the per-subclass
  drivers below.
- **CDC-ACM** (`cdc_acm` + `cdc_acm_bridge`): Abstract Control Model
  (USB serial) codec and live tty surface. `LineCoding` builder/parser
  (baud + data bits + parity + stop bits), `SET_LINE_CODING` /
  `GET_LINE_CODING` / `SET_CONTROL_LINE_STATE` / `SEND_BREAK`
  setup-packet builders, `SerialState` notification decoder, ACM
  functional-descriptor capability bits. Interface pairing honours the
  Union functional descriptor when one names the Comm interface
  (failing closed on a dangling Union); the bind path configures and
  arms the Comm interface's interrupt-IN notification endpoint, and
  the supervisor pump routes bulk-IN bytes to both the console input
  ring and the device's ttyACM RX ring, drains the ttyACM TX ring
  onto bulk-OUT (peek/skip on completion), and folds SerialState
  reports into the node's modem state. Each bound function publishes
  `/dev/ttyACM<N>` (major 166) through `cdc_acm_bridge` with the tty
  ioctl surface — termios/termios2 (CBAUD table + `BOTHER`, `B0`
  hangup drops DTR/RTS), `TIOCMGET`/`SET`/`BIS`/`BIC` (inputs from
  SerialState: DCD/DSR/RI; PSTN has no CTS), break via native
  `SEND_BREAK` gated on the ACM descriptor's send-break capability,
  `TCFLSH`/`TCXONC`/`FIONREAD`, `TIOCGICOUNT`, winsize — actuating
  through the class requests and committing user-visible state only
  after the device accepts (a STALL surfaces as `EIO` with the
  committed state and the device's cached line coding untouched).
  The live driver retains each bound device's line coding +
  control-line state — the `CdcAcmPort` setters commit to the
  record only on transfer success and surface failures as
  `CdcError::Transfer` — and registers the `cdc-acm` async
  system-PM hook (`cdc_acm::register_pm`, #763): prepare quiesces
  the pump, resume replays `SET_LINE_CODING` →
  `SET_CONTROL_LINE_STATE` per bound device from the saved state
  (bind order) once xHCI is restored. Hub-attached bindings record
  their (hub, port) and join the supervisor's hub-port wake step
  (`resume_suspended_hub_ports`).
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
  NTB-32 is negotiated when the device offers it
  (`SET_NTB_FORMAT` 1; NTH32/NDP32 with 32-bit block lengths
  and datagram pointers, lowercase `ncm0`/`ncm1` NDP
  signatures) and used for TX and RX alike; otherwise the
  driver stays on NTB-16 (`SET_NTB_FORMAT` 0).
  `NCM_NTB_PARAMETERS_STRUCTURE` decoder for the device-reported
  size limits.
- **CDC-ECM** (`cdc_ecm`): Ethernet Control Model 1.2 live driver
  for USB-Ethernet. One raw Ethernet frame per bulk transfer, no
  framing — no NTB wrap, no sequence, no CRC, no
  `GET_NTB_PARAMETERS`, no `GET_NET_ADDRESS` (NCM-only). Bind:
  SET_CONFIGURATION, Data alt-setting activation, bulk-pair (+
  notification endpoint when present) configuration, station
  address from the iMACAddress string descriptor only,
  best-effort `SET_ETHERNET_PACKET_FILTER`, netdev publication
  as `usb-ecm{N}` with per-device TX routing, RX pump (one
  transfer = one frame) + notification pump
  (`NETWORK_CONNECTION` link state, `CONNECTION_SPEED_CHANGE`
  speeds). Detach tombstones the record and unregisters the
  iface, so TX cookies never retarget another device. Shares
  the NCM module's Ethernet Networking descriptor parser, MAC
  string parser, and packet-filter encode — the CDC-common
  layer — and nothing NTB-shaped.

### Out of scope (deferred)
- UAC3 (protocol byte 0x30; descriptor layouts differ again).
- Runtime clock-selector switching after bind (bind now selects the
  pin for the resolved source); mixer gain (MCN) programming at
  bind/prepare.
- Non-QCA Bluetooth vendor firmware protocols (Intel, Realtek, MediaTek,
  Broadcom).
