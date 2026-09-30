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
- `Xhci::address_device_with(..., Topology)` retains the topology for later
  Evaluate Context operations; marking a downstream device as a hub must not
  erase its route string or parent-TT fields.
- `EndpointConfig` retains raw USB `wMaxPacketSize` and `bInterval` values.
  `Xhci::configure_endpoints` translates USB 2.0 periodic endpoints into xHCI
  Max Packet, Max Burst, Interval, CErr, and Max ESIT Payload fields using the
  addressed slot's negotiated speed.
- `find_video_streaming_endpoints(config)` returns each UVC bulk/isochronous IN
  endpoint with its owning interface and alternate setting.
  `select_video_streaming_iso_endpoint(endpoints, payload)` chooses the smallest
  alternate that satisfies the PROBE-accepted payload, and
  `negotiate_and_activate_video_stream(xhci, device_index, desired)` runs the
  26-byte SET_CUR(PROBE) / GET_CUR(PROBE) / SET_CUR(COMMIT) sequence, configures
  the accepted endpoint, issues `SET_INTERFACE`, and starts an IRQ-driven
  packet/frame pump into the camera's registered `/dev/video<N>` queue.
- `try_bind_btusb_already_addressed(xhci, slot_id, vendor_id, product_id,
  config)` binds the standard Bluetooth USB interface. For a recognised
  WCN6855 ID it completes the Qualcomm USB firmware/status protocol before
  running the full mandatory HCI sequence, adopting the ready controller, and
  publishing `/sys/class/bluetooth/hci<N>`. Firmware is selected from the
  verified registry using the controller-reported ROM/RAM/board identity.

## Scope

### Target laptop USB profile (silicon validation pending)

| USB ID | Device | In-tree path | Remaining validation |
|---|---|---|---|
| `05e3:0610` | Genesys Logic USB 2.0 hub | Hub class enumeration, multiple-TT flag, TT think-time propagation, downstream route addressing | Boot on the target xHCI controller and enumerate every downstream port |
| `27c6:6594` | Goodix USB2.0 MISC fingerprint reader | Explicit Goodix match, vendor-class bulk-IN/bulk-OUT transport, `/dev/fp0` handoff | Userspace Goodix MOC enrol/match protocol |
| `10ab:9309` | USI/Qualcomm WCN6855 Bluetooth | Explicit WCN6855 quirk match, runtime version/status query, rampatch + board-NVM USB download, full mandatory HCI bring-up, ready-controller registration, and `hci<N>` sysfs publication | Stage the matching signed firmware and validate the full sequence on silicon |
| `30c9:00cd` | Luxvisions integrated camera | Generic UVC bind, `/dev/video<N>` registration, PROBE/COMMIT negotiation, streaming-alternate selection, USB 2.0 high-bandwidth xHCI programming, and frame delivery | Validate negotiation and end-to-end isochronous video capture on silicon |

The `1d6b:0002` and `1d6b:0003` entries are synthetic root hubs exposed by
the host controller and are not matched as downstream USB devices.

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
- **Hub** (`hub`): hub class enumeration, multiple-TT detection from the
  Device Descriptor protocol, TT think-time propagation, and downstream
  route addressing so low/full-speed devices behind high-speed hubs are
  visible.
- **UVC stream** (`uvc_stream`): clean-room payload-header
  encoder + decoder for the per-isoch-transaction UVC header
  (bHeaderLength + Bit Field Header), with optional PTS (LE u32)
  and SCR (LE u32 SOF tick + 11-bit clock counter) fields. A
  `FrameReassembler` turns FID toggles into "new frame started" /
  "end of frame" / "error" steps the host driver feeds into the
  buffer manager.
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
- **UAC1** (`uac`): USB Audio Class 1.0 descriptor parser. AC
  HEADER, INPUT_TERMINAL, OUTPUT_TERMINAL, FEATURE_UNIT (per-channel
  control bitmaps), AS_GENERAL, Type-I FORMAT_TYPE (discrete sample-
  rate list and continuous-range form). Class triple constants for
  bus probing. Pure descriptor decode — pairs with a future
  isochronous-endpoint scheduler in `xhci` to ship audio data.
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
- UAC2 / UAC3 (newer protocol byte; descriptor layouts differ).
- End-to-end UAC audio streaming; the xHCI periodic endpoint machinery now
  exists, but the audio sample pump is still pending.
- Non-QCA Bluetooth vendor firmware protocols (Intel, Realtek, MediaTek,
  Broadcom).
