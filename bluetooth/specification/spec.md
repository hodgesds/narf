# narf-bluetooth — Bluetooth HCI core

Clean-room implementation of the Bluetooth Host Controller Interface
(HCI) packet layer + USB and H4 UART transport bindings.

## Sources (public only)

Protocol codecs are derived from the public standards below. Since NARF's
2026-05-20 relicense to GPL-2.0-or-later, the hardware-facing transport and
vendor-quirk paths also consult explicitly cited upstream Linux GPL sources.

### HCI

- **Bluetooth Core Specification, version 5.3** — Bluetooth SIG.
  Free download: <https://www.bluetooth.com/specifications/specs/core-specification-5-3/>
  - **Vol 4 Part E** — HCI Functional Specification. §5.4 (packet
    types), §7 (commands & events), §3 (general operation).
  - **Vol 4 Part B** — USB Transport Layer. §2.1 (endpoint mapping),
    §2.2 (packet-type indicator bytes).
  - **Vol 4 Part A** — UART Transport Layer (H4). §2 (packet-type
    indicator + body framing). Used by `h4`.
  - **Vol 4 Part D** — Three-Wire UART Transport Layer (H5). §3
    (4-byte link header + payload), §4 (SLIP escape), §5 (link
    establishment), §6 (CRC-CCITT). Used by `h5` (codec) and
    `h5_transport` (link-establishment state machine, sliding
    window, retransmission — `H5Transport: HciTransport` over a
    byte port; issue #1555).

### L2CAP

- **Bluetooth Core Specification, version 5.3, Vol 3 Part A** —
  Logical Link Control and Adaptation Protocol. §2.1 (CID
  assignments), §3.1 (B-frame layout), §4 (signalling commands),
  §6.6 (segmentation / reassembly).

### HID Profile (Classic BT, distinct from HOGP)

- **Bluetooth SIG, "Human Interface Device (HID) Profile
  Specification"**, Version 1.0, 22 May 2003.
  <https://www.bluetooth.com/specifications/specs/human-interface-device-profile-1-0/>
  - §5.2 — L2CAP fixed PSMs (Control 0x0011, Interrupt 0x0013).
  - §7.4 — HIDP transactions (HANDSHAKE, HID_CONTROL, GET/SET_REPORT,
    DATA, etc.).

### USB HCI transport

- **USB Class Definitions for Wireless Controllers**, v1.0,
  USB-IF, 2007. Class triple `0xE0 / 0x01 / 0x01`.
  <https://www.usb.org/document-library/usb-class-definitions-wireless-controllers-10>
- **Bluetooth Core 5.4 Vol 4 Part B** — endpoint roles + Setup
  packet shape for HCI Commands.

### ATT

- **Bluetooth Core Specification, version 5.3, Vol 3 Part F** —
  Attribute Protocol. §3.3 (PDU layout), §3.4 (opcodes), §3.4.1
  (error codes), §3.4.2 (Exchange MTU).

### GATT

- **Bluetooth Core Specification, version 5.3, Vol 3 Part G** —
  Generic Attribute Profile. §3 (Service / Characteristic /
  Descriptor model), §4.4 (discovery procedures), §3.3.1.1
  (Characteristic Properties bit definitions).
- **Bluetooth Assigned Numbers** — declaration UUIDs (0x2800
  Primary Service, 0x2803 Characteristic, 0x2902 CCC Descriptor)
  and well-known service UUIDs (0x180F Battery, 0x1812 HID, …).

### SMP

- **Bluetooth Core Specification, version 5.3, Vol 3 Part H** —
  Security Manager Protocol. §3.3 (PDU layout), §2.3.5 (LE Secure
  Connections pairing), §2.3.5.1 (pairing-method selection table 2.8),
  §2.3.5.6 (pairing phase 2), §2.2.5 (AES-CMAC), §2.2.6 (f4 confirm
  values, table 2.1), §2.2.7 (f5 MacKey / LTK derivation), §2.2.8
  (f6 DHKey checks, table 2.2), §2.2.9 (g2), §3.6.1 (key
  distribution, Peripheral first), §3.6.4–§3.6.6 (distribution only
  on an encrypted link), §3.6.7 (Security Request), Appendix D (sample
  data pinning the f4/f5/f6 helpers byte-for-byte).

### HFP (Hands-Free Profile)

- **Hands-Free Profile, Version 1.8** — Bluetooth SIG. Public adopted
  profile. §4.2 (service-level connection establishment), §4.34 (BRSF
  feature bit table), §4.4 (CIND / CMER indicator negotiation),
  §4.6 (in-band ringtone), §4.13 (call list / CLCC), table 5.1 (HF +
  AG feature bit columns).
- **ITU-T Recommendation V.250** — public AT command syntax baseline
  (lexer + line termination + basic / extended formats).
- **3GPP TS 27.007** — public AT command set; HFP reuses CIND, CIEV,
  CHUP and the +CME ERROR response shape verbatim.

### AVDTP / A2DP

- **Audio/Video Distribution Transport Protocol Specification,
  Version 1.3** — Bluetooth SIG. Public adopted document.
  §8.4 (Signalling Message format), §8.5 (Signal Identifiers,
  table 8.4), §8.6 (Service Capabilities), §8.20.1 (SEP TSEP
  encoding), §8.20.6 (error codes table 8.27).
- **Advanced Audio Distribution Profile (A2DP), Version 1.4** —
  Bluetooth SIG. Public. §4.3 SBC media-codec capability layout
  (sampling-frequency / channel-mode / block-length / subbands /
  allocation-method bitmasks + 1-byte min/max bitpool).
- **Bluetooth Assigned Numbers** — AVDTP signalling PSM 0x0019,
  Audio/Video Distribution media-type and codec-type registry.

### RFCOMM

- **Bluetooth Core Specification 5.3, Vol 3 Part B (RFCOMM)** —
  Bluetooth SIG. §1 framing model, §2 multiplexer control, §5.1.1
  address byte, §5.1.2 control byte (SABM/UA/DM/DISC/UIH + P/F),
  §5.1.3 EA-coded length indicator, §5.1.4 FCS coverage, §5.4 DLCI
  ↔ server-channel mapping.
- **ETSI TS 07.10** — the underlying multiplexed-serial protocol that
  RFCOMM adapts. Public ETSI document; only the byte layout is
  consumed.

### HOGP (HID over GATT)

- **HID over GATT Profile Specification, version 1.0** — Bluetooth SIG.
  Adopted profile; defines the HID Service (0x1812) shape: HID
  Information (0x2A4A), Report Map (0x2A4B), HID Control Point
  (0x2A4C), Report (0x2A4D) + Report Reference descriptor (0x2908),
  Protocol Mode (0x2A4E), Boot Keyboard Input/Output Report (0x2A22 /
  0x2A32), Boot Mouse Input Report (0x2A33).
- **HID Service Specification, version 1.0** — Bluetooth SIG.
  §3.1 HID Information field layout, §3.4 Protocol Mode values,
  §3.6 Control Point command bytes, §3.7.1 Report Reference fields.
- **USB-IF Device Class Definition for Human Interface Devices (HID),
  v1.11** — referenced for the boot-protocol report layouts (§B.1
  keyboard, §B.2 mouse) reused on BLE.

### GAP advertising data

- **Bluetooth Core Specification Supplement, Part A — Data Types
  Specification, Version 11** — Bluetooth SIG. Public adopted
  document. §1.3 (advertising data record format: length /
  AD type / payload).
- **Bluetooth Assigned Numbers — Generic Access Profile** —
  Bluetooth SIG. Public registry of AD type codes (Flags = 0x01,
  Service UUID lists 16/32/128 bit, Local Name, Tx Power,
  Manufacturer Specific Data = 0xFF, Service Data, Appearance,
  URI, …).

### Bluetooth Mesh

- **Bluetooth Mesh Profile Specification, Version 1.1** (Sep 2023)
  — Bluetooth SIG. Public adopted document. §3.4.2 Network PDU
  layout (IVI/NID + obfuscated CTL/TTL/SEQ/SRC + encrypted
  DST + Transport PDU). §3.5.2 Lower Transport: unsegmented
  vs segmented Access PDU (SegN/SegO/SeqZero/SZMIC packing).
  §3.7.3 Access-layer Opcode encoding (1 / 2 / 3-byte forms).
- **Bluetooth Mesh Model Specification, Version 1.1** —
  Bluetooth SIG. Public. §4.2.1.1 Composition Data Page 0
  layout (CID/PID/VID/CRPL/Features bitmap + per-element list).

### SDP (Service Discovery Protocol)

- **Bluetooth Core Specification 5.3, Vol 3 Part B (SDP)** —
  Bluetooth SIG. §3 service-record / attribute model, §4 PDU
  formats (PDU Header, ServiceSearchRequest, ServiceAttributeRequest,
  ServiceSearchAttributeRequest), §5.1 DataElement TLV encoding
  (Type Descriptor in high 5 bits, Size Index in low 3).
- **Bluetooth Assigned Numbers** — SDP Service-Class UUIDs and
  Universal Attribute IDs (ServiceClassIDList = 0x0001,
  ProtocolDescriptorList = 0x0004, BluetoothProfileDescriptorList
  = 0x0009, ServiceName = 0x0100). PSM = 0x0001.

### USB transport class

- **USB Class Definitions for Wireless Controllers, Revision 1.0** —
  USB-IF, August 2002.
  Class 0xE0 (Wireless Controller), Subclass 0x01 (RF Controller),
  Protocol 0x01 (Bluetooth Programming Interface).
- **Linux `drivers/bluetooth/btusb.c` and `btqca.c`** — GPL-2.0-only;
  endpoint binding, vendor-family identification, and firmware-name/protocol
  metadata. Consulted under NARF's GPL-2.0-or-later license.

## Public interface

- `controller::bring_up_all(cap)` runs the mandatory synchronous HCI sequence
  for transports registered before the Stage::Late bring-up initcall.
- `h5_transport::H5Transport` implements `HciTransport` over a
  `transport::BytePort`: SYNC / CONFIG link establishment (Vol 4
  Part D §5), sequence numbers + sliding window + retransmission
  (§6, §12 timing). `H5Transport::from_uart_info` rebuilds the
  byte-port handle from a serial registry entry, dispatching on the
  entry's `UartFamily` (PL011 entries get a `Pl011BytePort`, 8250
  entries a `Uart8250BytePort`); `bind_named(name)` establishes the
  link and registers the transport for `bring_up_all`. Boot bind is
  opt-in only: the Stage::Late `bluetooth-h5-boot` initcall binds
  `bt-h5=<uart-name>` (absent, bare, or empty binds nothing) and
  runs before `bluetooth-bringup`. The QEMU virt PL011 is published
  in the serial registry as `PL011-0` so H5 works on ARM boards; a
  PL011 data tty is still a follow-up. H4 landed with its own
  `H4BytePort` trait (#1557); H4 should adopt the shared `BytePort`
  trait and the two transports should share one 8250 adapter.
- `h4_transport::H4Transport` — `HciTransport` over a UART byte port
  (`H4BytePort`: `write_byte` / `read_byte`, implemented for the
  8250/16550 `Uart8250` in `narf-drivers-serial`). H4 framing is the
  existing `h4` codec (Vol 4 Part A §2); the transport demultiplexes
  the single RX byte stream into event / ACL / SCO queues.
  `h4_transport::bind_uart(name, baud)` looks a port up in the serial
  registry, programs it, and registers the transport, so the Stage::Late
  `bluetooth-bringup` initcall picks it up via `bring_up_all`. No
  auto-bind: nothing in the tree says which UART (if any) has a Bluetooth
  module attached, and binding the console port (`COM1`) is refused.
- `controller::register_ready_transport(transport, info)` adopts a controller
  whose late-discovered driver completed that same sequence on a native async
  transport path. Registration is idempotent by transport identity and returns
  the stable `hci<N>` ordinal.
- Detach composition (issue #890): `controller::unregister_controller(index)`
  tears a controller down in full — tombstone the registry slot first
  (the linearization point: from there the controller is invisible to
  every live-only lookup, so an event arriving mid-teardown cannot
  resurrect it), stop + remove the pump (`pump::stop_pump` /
  `pump::remove_pump`, dropping the core with its connection table),
  unregister the transport (`transport::unregister`, by pointer
  identity, so a later `bring_up_all` cannot re-bring-up the dead
  transport), remove the sysfs node
  (`sysfs_bridge::unregister_hci_controller`), forget the mgmt
  settings (`mgmt::forget_settings`), and publish mgmt
  `INDEX_REMOVED` last. Idempotent: a second detach returns `false`.
  Ordinals are index-stable — detaching never shifts a live
  controller's ordinal; a later registration reuses the first
  tombstoned slot. `controller::controller_count()` counts live
  controllers only; `controller::is_live` / `get_live` /
  `live_indices` are the live-only views mgmt (`READ_INDEX_LIST`
  lists live ordinals), hci_sock, and the pump use, so a detached
  ordinal disappears instead of shifting later ones.
- `sysfs_bridge::register_hci_controller(index, info, connections)` publishes
  a ready controller under `/sys/class/bluetooth/hci<N>` and records its
  kobject for the pump's connection mirroring. `sysfs_bridge::add_connection`
  / `remove_connection` add/drop the `hci<N>:<handle>` per-connection child
  (Linux `hci_conn_add_sysfs` / `hci_conn_del_sysfs`, child name `%s:%d`);
  the index-keyed `add_connection_for` / `remove_connection_for` helpers
  are the pump's entry points and no-op when nothing is published at that
  ordinal.
- `pump` — the HCI event/ACL driver task. `pump::notify_controller_ready(index)`
  (called by both registration paths above) registers a per-controller
  `PumpCore`; `pump::enable_spawning()` (Stage::Late `bluetooth-pump`
  initcall) starts a stackful pump task per controller. `pump::pump_once(index)`
  is the fixture-drivable step: events are dispatched (connection tracking,
  LTK-request answering from the in-progress AuthComplete session or
  the bond store, else negative reply, flow control) and fanned out to the raw-HCI socket
  queue (`hci_sock::drain_event` reads it once a pump is active), ACL frames
  are reassembled per connection and routed by CID — ATT to the
  per-controller `GattServer`, SMP to a per-connection SMP session
  (`smp::Responder` for peer-initiated pairings, `smp::Initiator`
  when the peer sends a Security Request or the application calls
  `pump::smp_initiate_pairing`) driven by the production
  `pump::NarfSmpCrypto` (narf-crypto P-256 /
  AES-CMAC / hardware RNG), signalling channels answered per §L2CAP.
  Connection tracking also mirrors into sysfs: connect gains the
  `hci<N>:<handle>` child, disconnect removes it (issue #891).
  `pump::stop_pump(index)` quiesces a controller's task ahead of detach;
  `pump::remove_pump(index)` drops the pump slot outright (the detach
  half — see the detach-composition bullet above).
  GAP central initiation (issue #1312): `pump::central_start_scan(index,
  params)` issues LE Set Scan Parameters (§7.8.10) with LE Set Scan
  Enable(1) (§7.8.11) following on the parameters' Command Complete;
  LE Advertising Reports received while scanning feed the
  `gap::Central` peer table (`pump::central_peers`); `pump::central_connect`
  disables the scan first and issues LE Create Connection (§7.8.12) on
  the disable completion (or directly from Idle), and LE Connection
  Complete lands the connection like any other pump connection.
  `pump::central_phase` exposes the initiator phase. GAP extended
  advertising / scanning (issue #823): `pump::ext_central_start_scan(index,
  params)` issues LE Set Extended Scan Parameters (§7.8.64) with LE
  Set Extended Scan Enable(1) (§7.8.65) following on completion; LE
  Extended Advertising Reports (§7.7.65.13) received while scanning
  feed the `gap::ExtendedScanner` peer table (`pump::ext_central_peers`)
  with fragment reassembly per (address, SID), and LE Scan Timeout
  (§7.7.65.17) ends the scan on its own. `pump::ext_adv_start(index,
  params, data, scan_response)` drives one advertising set through
  Set Extended Advertising Parameters (§7.8.53) → Set Extended
  Advertising Data (§7.8.54) → optional Set Extended Scan Response
  Data (§7.8.55) → Set Extended Advertising Enable(1) (§7.8.56),
  each step only on the previous step's Command Complete; the
  controller-selected Tx power lands on the set
  (`pump::ext_adv_selected_tx_power`), LE Advertising Set Terminated
  (§7.7.65.18) and LE Scan Request Received (§7.7.65.19) land on the
  set's host-side state, and `pump::ext_adv_stop` disables a set.
  `gap::supports_extended_advertising` is the §7.8.3 bit-12 capability
  gate (LE Read Local Supported Features, octet 1 bit 4) the host must
  check before issuing extended commands. Out of scope here: periodic
  advertising (§7.8.61..63) and LE Extended Create Connection (§7.8.66)
  — follow-ups to #823 — and any mgmt/userspace trigger for these
  calls (future lane).
  Pairing initiation (issue #888, MITM methods #818) is
  `pump::smp_initiate_pairing` (LE initiator + bond store, IO
  capability from mgmt); host-initiated disconnect is
  `pump::disconnect` (issue #1527: HCI_Disconnect by handle, reason
  0x13, resolved by the Disconnection Complete event).
- `mgmt` — the Linux Bluetooth Management API
  (`HCI_CHANNEL_CONTROL`, issue #815). Set-mode ops issue real
  HCI through the controller transport and record the setting
  only once the controller accepts it: power on/off (HCI_Reset +
  event mask + identity refresh + re-apply of every recorded
  HCI-backed setting), discoverable/connectable
  (HCI_Write_Scan_Enable, with the Linux couplings —
  discoverable-on while connectable-off is REJECTED,
  connectable-off also switches discoverable off),
  fast-connectable (Write_Page_Scan_Type), link-security
  (Write_Authentication_Enable), SSP (Write_Simple_Pairing_Mode),
  LE (Write_LE_Host_Support), secure-conn
  (Write_Secure_Connections_Host_Support; SC-Only is
  NOT_SUPPORTED), bondable (host policy, no HCI command exists).
  While unpowered a setting is recorded and applied on the next
  power-on (the Linux model); power-on re-writes a userspace-set
  name/class and otherwise re-reads the controller's. READ_INFO
  reports the real dev_class / local name / short name (the
  bring-up reads them from the controller; the short name stays
  empty until SET_LOCAL_NAME sets one). START/STOP_DISCOVERY
  drive the GAP central initiator above (LE public only; BR/EDR
  and LE random are NOT_SUPPORTED pending #1315 / a random-address
  backend) and publish DISCOVERING / DEVICE_FOUND per report;
  SET_SCAN_PARAMS stores the LE scan parameters (HCI §7.8.10
  bounds). PAIR_DEVICE (LE, existing connection required,
  per-pairing IO capability — any of the five §3.5.1 values, so
  MITM methods are reachable) returns Command Status now and
  Command Complete when the initiator session ends (SUCCESS /
  AUTH_FAILED / DISCONNECTED / CANCELLED);
  CANCEL_PAIR_DEVICE (issue #1528)
  aborts an in-flight mgmt-started pairing via
  `pump::smp_cancel_pairing` (Pairing Failed, Unspecified Reason,
  Vol 3 Part H §3.5.5) and completes the pending PAIR_DEVICE
  with CANCELLED — a cancel with no pending pairing for that
  peer is INVALID_PARAMS, as in the kernel.
  SET_IO_CAPABILITY stores the
  controller-wide IO capability used by responder pairings and
  Security-Request-triggered initiations. The MITM user flows run
  through mgmt: USER_CONFIRM_REQUEST / USER_PASSKEY_REQUEST /
  PASSKEY_NOTIFY events and USER_CONFIRM_REPLY / NEG_REPLY,
  USER_PASSKEY_REPLY / NEG_REPLY commands; ADD/REMOVE_REMOTE_OOB_DATA
  hold the peer's P-256 OOB data for the pump (LE: 71-byte form,
  P-192 fields zero). PIN_CODE_REPLY / NEG_REPLY are recognised
  and refused as NOT_SUPPORTED (BR/EDR-only, no legacy pairing
  backend); READ_LOCAL_OOB_DATA is NOT_SUPPORTED (no stable local
  SC keypair yet). DISCONNECT (issue #1527, powered-only) is async
  like PAIR_DEVICE — no immediate reply, Command Complete echoing
  the address when the Disconnection Complete lands (or FAILED
  when the controller refuses the HCI command). UNPAIR_DEVICE
  forgets the bond (idempotent) and disconnects a live connection
  first when disconnect=1.
  SET_ADVERTISING drives the legacy advertising HCI sequence
  (Set Advertising Parameters / Data / Scan Response Data /
  Advertise Enable; mode 0x02 connectable, 0x01 non-connectable
  with a fresh non-resolvable random address when connectable
  is off) and is re-applied on power-on; SET_BREDR toggles the
  BR/EDR bit with the Linux couplings (unpowered disable also
  clears discoverable/SSP/link-security/fast-connectable,
  powered disable is REJECTED, powered re-enable is REJECTED
  while a static address is set or secure-connections is on).
  SET_STATIC_ADDRESS records a static-random identity address
  (powered is REJECTED, non-ANY needs the static bits) and
  SET_PRIVACY records mode + local IRK (powered is REJECTED);
  power-on programs the random address — an RPA generated from
  HCI LE Rand + LE Encrypt (`ah`) when privacy is on, else the
  static address — and the controller resolving list from the
  loaded IRKs (Clear + Add per entry + Address Resolution
  Enable). LOAD_LONG_TERM_KEYS stores accepted LTKs as real
  bonds (invalid entries skipped, debug key type skipped);
  LOAD_IRKS replaces the host IRK list (one invalid entry
  fails the whole command) and mirrors peer IRKs into existing
  bonds. LOAD_LINK_KEYS is not dispatched (no BR/EDR link-key
  store or consumer exists).
  Known limits: mgmt issues its HCI synchronously, so while the
  pump task is draining the same transport a completion can be
  consumed by the pump instead (a single command path via the
  pump/CmdQueue is the follow-up); the discoverable timeout is
  accepted but never enforced (no mgmt timer); the RPA is
  generated once per power epoch and never rotated (no mgmt
  timer); LOAD_LONG_TERM_KEYS merges into the bond store
  instead of the kernel's clear-first, so live pairings keep
  their bonds; power-off does not drop live pump connections.
  GATT client (issue #1313): `pump::gatt_client_discover_services` /
  `discover_characteristics` / `discover_descriptors` / `read` /
  `write` / `subscribe` issue ATT requests over a central-role
  connection's outbound ACL path, and `pump::gatt_client_services` /
  `characteristics` / `descriptors` / `subscribed` / `last_read` /
  `last_error` / `take_notifications` expose the discovered state.
  Inbound ATT on a central-role connection is demultiplexed to the
  per-connection `gatt_client::Client` (never to the GATT server);
  ATT lock-step holds one outstanding request per connection, and
  discovery loops from the last returned handle until the range end
  or an Attribute Not Found terminator. Out of scope here: MTU
  exchange (default ATT MTU 23 governs), Read Blob / long reads,
  Prepare / Execute writes, and ATT over BR/EDR.
  HOGP wiring (issue #1314): the pump's GATT server mounts the HID
  service (0x1812) as a boot keyboard on every controller —
  `services::mount_hid_service` publishes HID Information
  (bcdHID 1.11, country 0, NORMALLY_CONNECTABLE only, no remote
  wake claim), the HID 1.11 Appendix B.1 boot keyboard Report Map,
  HID Control Point, Protocol Mode (default Report), and boot
  keyboard input/output characteristics — always-mounted like
  GAP/GATT/DIS/Battery, but mount alone does not advertise, and
  the server cannot emit notifications yet, so a central can read
  the map and flip Protocol Mode but receives no input reports
  from this mount. The central half is `hogp_client::HogpClient`,
  built by `pump::hogp_attach` from GATT discovery records:
  `pump::hogp_note_last_read` feeds HID Information / Report Map /
  Report Reference reads, `pump::hogp_protocol_mode_write` (+
  `hogp_note_boot_mode`) selects boot protocol when Protocol Mode
  exists, `pump::hogp_subscribe_targets` yields the CCCD targets
  (NOTIFY wins over INDICATE), and `pump::hogp_route_drained`
  drains the client notification queue into the `narf_input`
  global rings — boot keyboard reports diffed (modifier byte, then
  six-keycode array, rollover suppressed, usages 0x00–0x03 and
  0xE0–0xE7 filtered) via `push_key`, boot mouse reports via
  PointerEvent + ButtonEvent. Report-protocol input Reports are
  staged undecoded (`pump::hogp_take_undecoded`); the Report Map is
  not parsed, evdev DeviceNode registration is not done, and HID
  Control Point / boot output reports are not driven — all
  follow-up.
  AF_BLUETOOTH channel sockets (issue #814): the server side of
  L2CAP/RFCOMM sockets is wired to the pump's existing channel
  servers through the filesystem broker
  (`narf_filesystem::bluetooth`, installed by the `bluetooth-mgmt`
  initcall). `pump::register_psm` / `unregister_psm` register a
  listening PSM as a Generic staging server (LE CoC or BR/EDR);
  service PSMs (SDP 0x0001, RFCOMM 0x0003) refuse with InUse.
  `pump::take_pending_channel` / `pending_channel` claim/peek the
  oldest unclaimed peer-opened channel for a listener's PSM;
  `pump::send_channel` sends one SDU (LE CoC: K-frame segmentation
  against the peer's MPS and credit budget, all-or-nothing;
  BR/EDR generic: one B-frame) and `pump::drain_channel_rx` /
  `channel_rx_pending` drain/peek staged inbound SDUs;
  `pump::disconnect_channel` removes the channel and sends the
  peer a Disconnection Request. RFCOMM: `pump::take_pending_rfcomm`
  / `pending_rfcomm` claim/peek the oldest unclaimed DLC for a
  server channel (DLCI `2*channel+1` per TS 07.10 §5.4, matched
  leniently on the direction bit), `pump::send_rfcomm` /
  `drain_rfcomm_rx` / `rfcomm_rx_pending` move UIH frames on the
  open DLC (C/R follows the DLC side: 1 for an initiator-opened
  DLC, 0 for a responder-opened one), and `pump::close_rfcomm_dlc`
  sends DISC and forgets the DLC (the mux survives). Claims are
  (handle, local CID, DLCI) and are released at every
  channel-removal site, so a reused CID is never shadowed. The
  pump publishes `narf_filesystem::bluetooth::publish_bt_channel_event`
  when a Generic channel opens or data lands on a
  socket-claimable channel, so parked poll/accept waiters re-run
  their readiness scan. Outbound opens (#1532):
  `pump::connect` / `connect_ready` / `cancel_connect` (registered
  as the filesystem broker's `bt_connect` / `bt_connect_ready` /
  `bt_cancel_connect`) start-or-poll an outbound LE CoC, BR/EDR
  Connection Request, or RFCOMM SABM/DLC open: the first call
  starts the open and reports Pending, a later call completes it
  (Open / OpenRfcomm) or reports the terminal Refused / Failed
  outcome; cancelling drops the record and tears down any
  half-opened channel. Out of scope here: fixed-CID
  sockets (ATT/SMP/signalling stay routed to the pump's own
  server/responder), and SDP-channel sockets (service-owned).
  SCO sockets (issue #814) ride the #817 SCO transport
  (`HciTransport::send_sco` / `recv_sco`, isoch endpoints on USB).
  `pump::sco_connect` starts an outbound setup — over a live ACL
  it issues Setup Synchronous Connection at once (8 kHz TX/RX,
  0xFFFF max latency, the socket's BT_VOICE setting, retransmission
  effort 0x02, all eSCO packet types), otherwise it pages first
  (the peer must be discovered; NARF never pages blind) — and
  `pump::sco_connect_status` polls the outcome: Pending while in
  flight, Connected once the Synchronous Connection Complete
  lands the link (MTU = the controller's SCO MTU, else 60),
  Refused(status) for a controller refusal (0x04 Page Timeout
  surfaces as ETIMEDOUT at the socket layer), Aborted when no
  setup is in flight. At most one pending setup per controller;
  a second connect to a live link is AlreadyConnected, and an
  unmatched Synchronous Connection Complete records an unclaimed
  link a later connect claims. `pump::send_sco` sends one frame
  (oversize → TooBig; an isoch-less transport → Unsupported,
  fail-closed), `pump::drain_sco_rx` / `sco_rx_pending` drain/peek
  staged inbound frames (the packet-status flag is dropped at the
  pump — Linux delivers it as `BT_SCM_PKT_STATUS` ancillary data,
  which NARF has no BT cmsg path for yet), `pump::disconnect_sco`
  issues HCI_Disconnect (reason 0x13), and
  `pump::cancel_sco_connect` drops a pending setup (a page already
  in flight still lands a plain ACL). `pump_once` drains
  `recv_sco` each step; Disconnection Complete drops SCO links
  riding the dead ACL (and the SCO handle itself). Raw HCI
  sockets forward 0x03 SCO data packets to `send_sco`. The socket
  layer (`userspace/src/socket.rs`) is two-phase: the first
  `connect()` returns EINPROGRESS and the syscall parks on
  POLLOUT|ERR|HUP, re-executing into a status poll; SOL_SCO
  SCO_OPTIONS reports the link MTU and SCO_CONNINFO the handle +
  peer class once connected (ENOTCONN before). Inbound SCO accept
  is out of scope — accept still returns WouldBlock.
- `pm` — per-controller power-management state (issue #820). Three
  independent park causes — mgmt power-off, system suspend,
  USB autosuspend — OR into `pm::is_parked`, which gates
  `pump::pump_once` (a parked step never polls the transport but
  still flushes queued outbound ACL, so a queued packet can wake
  the port through the transport's TX-demand resume).
  `pm::suspend_controller` / `pm::resume_controller` are the
  device-PM suspend/resume pair (registered per USB controller by
  the btusb bind as `btusb-hci<N>`, and per PCIe controller by the
  btintel-pcie firmware load as `btintel-pcie`, which resolves the
  HCI index lazily by transport identity — the index only exists
  once `bring_up_all` has run the mandatory HCI bring-up over the
  transport); `pm::park_autosuspend` /
  `pm::unpark_autosuspend` are the hub idle-suspend park and the
  wake-watch / TX-demand unpark. `mgmt::is_powered` is truthful:
  the `POWERED` setting bit AND NOT parked-for-power (mgmt off or
  system suspend); a runtime (autosuspend) park leaves `HCI_UP`
  alone, as on Linux. `pm::idle_timeout_ms` is the live idle
  policy sysfs `idle_timeout` reports — default 30 000 ms (the USB
  hub autosuspend window), 0 meaning "never autosuspend" — and the
  btusb suspend hook vetoes gating for a 0-timeout controller.
  Reloading PCIe firmware after a power cut across suspend is
  covered since #1660: resume detects the loss (`BOOT_STAGE`
  without `OPFW`), records `firmware_lost`, and stays parked, and
  a supervisor task spawned at firmware-load time observes the
  flag from task context, re-runs `enable_bt` (re-publish CI,
  `MAC_INIT`, wait for ROM) + `fw::setup`, and unparks the pump —
  the transport survives, so the HCI index is kept and
  `register_ready_transport` is not re-run.
  The `idle_timeout` sysfs attribute is writable (#1577): a store
  parses milliseconds (0 = never autosuspend) and calls
  `pm::set_idle_timeout_ms`, rejecting negative / non-numeric /
  out-of-range input with `EINVAL`.
  Out of scope here: PCIe controllers (`btintel_pcie` never enters
  the HCI controller registry, so it has no index to key this
  state off) — follow-up.

## Scope

### Landed today
- **HCI** (`hci` / `opcode` / `event` / `transport` / `controller`):
  packet codec, Mandatory + LE-basics opcodes, Command Complete /
  Command Status decoders, transport trait + USB class triple, full
  bring-up state machine (Reset → Read Local Version → Read BD_ADDR
  → Read Buffer Size → Set Event Mask). Periodic advertising
  opcodes (§7.8.61..63, §7.8.67..69, §7.8.89..92 sender-side sync
  transfer) + LE Meta subevent parsers
  for Sync Established / Report / Sync Lost (§7.7.65.14..16,
  subevents 0x0E..0x10) and Sync Transfer Received [v1]
  (§7.7.65.21, subevent 0x18, #1575) — a transferred sync adopts
  into `PeriodicSync` with no pending Create Sync.
- **HCI pump** (`pump`): supervised per-controller event/ACL pump task
  composing the layers below into a running system — connection table,
  ACL flow control, raw-socket event fan-out, per-connection L2CAP
  dispatch (ATT → GATT server with default GAP/GATT/DIS/Battery/HID
  services, SMP → Just-Works responder + initiator with bonding
  (§3.6.1 Phase 3 distribution, bond store, re-encryption), LE +
  BR/EDR signalling answers, dynamic CIDs → open channel servers).
  Production `SmpCrypto` via narf-crypto (`NarfSmpCrypto`).
  Periodic advertising (`periodic_adv_*` API, #1560): broadcaster
  parameters / data / enable (§7.8.61..63) and receiver sync
  Create / Cancel / Terminate (§7.8.67..69) with the
  `PeriodicSync` receiver machine (Creating → Synced → Idle on
  Sync Lost / Terminate, fragmented-report reassembly bounded at
  251 bytes) driven by the §7.7.65.14..16 subevents, plus
  transfer adoption from Idle on Sync Transfer Received
  (§7.7.65.21, #1575). Sender-side sync transfer (#1654): Sync
  Transfer (§7.8.89, only for the sync currently held, to a live
  connection), Set Info Transfer (§7.8.90, only while our train is
  Enabled), per-connection (§7.8.91) and default (§7.8.92)
  transfer parameters; all four return Command Complete and the
  outcome is recorded as the pump's last sync-transfer outcome —
  the transfers change no phase.
- **L2CAP** (`l2cap`): CID constants, B-frame codec, ACL fragment
  reassembler that handles the PB-flag rules from Vol 4 Part E §5.4.2,
  signalling-command codec + iterator, dynamic CID allocator, LE
  credit-based connection request/response + flow-control builders
  with §4.23 result codes.
- **L2CAP channel servers** (`l2cap_server`): PSM → server registry
  (SDP + RFCOMM pre-registered on BR/EDR, LE services register
  explicitly), per-connection LE credit-based channels (credit
  accounting with top-up grants, K-frame → SDU reassembly with the
  2-byte length prefix, oversize/over-MPS/overrun → channel drop)
  and BR/EDR channels (SDP / RFCOMM session / generic staging).
  Staged payloads drain via `pump::drain_channel_rx` /
  `pump::drain_rfcomm_rx`; socket/devfs consumer wiring is
  follow-up work, not part of this surface.
- **ATT** (`att`): full opcode constant set + error-code constants
  + PDU codec + builders/decoders for Exchange MTU, Read, Write,
  Handle Value Notification/Indication/Confirmation, Error Response.
- **GATT** (`gatt`): Service / Characteristic / Descriptor record
  types + well-known UUIDs + discovery-request builders and
  response parsers (Read By Group Type for Primary Services, Read
  By Type for Characteristics, Find Information for Descriptors).
  GATT client (`gatt_client` + `pump` wiring, #1313): discovery /
  read / write / CCCD subscription over central-role connections,
  with ATT lock-step, response demultiplexing away from the GATT
  server, and notification/indication intake.
- **SMP** (`smp`): Pairing PDU codec, IO-Capability + AuthReq
  bitfields, pairing-method selector (table 2.8 — OOB when one or
  both sides hold OOB data, table 2.7), LE Secure Connections
  initiator + responder state machines running the full §2.3.5.6
  sequence for **Just Works, Numeric Comparison, Passkey Entry,
  and Out of Band**: f4 Pairing Confirm values generated and
  verified on both roles (§2.2.6, table 2.1), f5 MacKey + LTK
  derivation (§2.2.7), and f6 DHKey Check values generated and
  verified on both roles (§2.2.8, table 2.2); confirm / DHKey
  mismatches abort the exchange (Pairing Failed 0x04 / 0x0B via
  the pump). Numeric Comparison (§2.3.5.6.2) parks after the f5
  derivation with the g2 value (§2.2.9) and resumes only on the
  user's confirm (rejection aborts with Pairing Failed 0x0C);
  Passkey Entry (§2.3.5.6.3) runs 20 Confirm/Random rounds, one
  per passkey bit (Z = 0x80 | bit), ending with Na = Na20 /
  Nb = Nb20 for stage 2; Out of Band (§2.3.5.6.4) commits each
  side's own key to its OOB random, verifies the peer's OOB hash
  against its public key, and uses the OOB randoms as the f6 R
  values. The IO capability (and its MITM bit) is configurable
  per session via `with_io_capability`, not hardcoded. Crypto
  primitives injected through `SmpCrypto` trait (P-256 keygen +
  DH, AES-CMAC, RNG).
- **Bonding** (`bond_store` + pump SMP session): both roles negotiate
  bonding (both Bonding_Flags == 01) and Phase 3 key distribution
  (§3.6.1: IdKey + Sign, negotiated as the intersection of the two
  sides' distribution bytes; EncKey ignored for LE Secure
  Connections, LinkKey out of scope). After authentication the
  session parks at AuthComplete until the link is encrypted —
  distribution PDUs are only legal on an encrypted link
  (§3.6.4–§3.6.6) — then the Peripheral distributes first, then the
  Central, in IRK / identity-address / CSRK order. A completed
  bonded pairing persists in the per-controller `BondStore`
  (peer address + LTK + EDIV/Rand, both zero for SC, + peer IRK /
  identity address / CSRK); LE LTK Requests are answered from the
  in-progress AuthComplete session first, then from the store on
  exact peer + EDIV/Rand match, else negative-replied. The pump
  exposes `smp_initiate_pairing` (application trigger, IO
  capability from mgmt's SET_IO_CAPABILITY store),
  `smp_initiate_pairing_with_io` (per-pairing IO capability, as
  PAIR_DEVICE carries), `smp_user_confirm` / `smp_user_passkey` /
  `smp_user_passkey_cancel` (mgmt user replies), `smp_start_encryption`
  (re-encrypt from a bond), `forget_bond`, `bond_count`, and
  `bond_authenticated`. No ATT-triggered pairing yet (no auth-gated
  attribute exists). The store encodes to a versioned image
  (`BondStore::encode` / `decode`, strict fail-closed) and seals it
  with ChaCha20-Poly1305 (`BondStore::seal` / `unseal`, AAD bound
  to the controller + format version) under an explicitly
  provisioned key (`set_bond_sealing_key`); the pump exposes the
  latest sealed image (`sealed_bonds_image`) and restores from one
  (`restore_sealed_bonds`). Sealing is disabled until a key is
  provisioned, and no driver-domain file-write path exists yet to
  carry the sealed image to disk — those two hookups, plus key
  provisioning, are remainders.
- **GATT server** (`gatt_server`): in-memory attribute database
  with handle assignment + permission flags, request handler that
  answers Read / Write / Read By Type / Read By Group Type / Find
  Information / Exchange MTU per ATT §3.4. Convenience builders
  `add_primary_service` / `add_characteristic` emit the canonical
  Vol 3 Part G declaration shape.
- **GAP** (`gap`): clean-room advertising-data record codec.
  AdIter walks the standard length+type+payload layout (with
  zero-length-as-terminator handling), append_record + builders for
  Flags / Complete Local Name / Tx Power / Manufacturer Specific
  Data / 16-bit Service UUID list / Service Data, decoders for the
  same plus convenience helpers (find by AD type, local_name,
  flags, tx_power, manufacturer_data, service_uuids_16). AD type +
  flags-byte constants per Assigned Numbers. Periodic advertising
  encoders (`PeriodicAdvertisingParameters` / Data / Enable /
  CreateSync, §7.8.61..63, §7.8.67) + the transport-free
  `PeriodicAdvertiser` / `PeriodicSync` state machines.
- **Mesh** (`mesh`): clean-room Bluetooth Mesh codec. Network PDU
  header (9 bytes — IVI/NID + CTL/TTL + 24-bit BE SEQ + SRC + DST),
  Lower Transport segmented Access PDU header (4 bytes — SEG/AKF/AID
  + SZMIC + 13-bit SeqZero + SegO + SegN packing), Access-layer
  Opcode encoder/decoder for all three forms (1-byte 0x01..0x7E /
  2-byte 0x80..0xBF / 3-byte vendor with LE Company ID), Composition
  Data Page 0 header with feature-bit constants (Relay / Proxy /
  Friend / Low Power).
- **SDP** (`sdp`): clean-room Service Discovery Protocol codec.
  PDU header (5 bytes), DataElement TLV encoder/decoder (NIL,
  Unsigned Integer, UUID, Text, Boolean, Sequence with all three
  variable-size-index forms), Universal Attribute ID constants
  (ServiceClassIDList, ProtocolDescriptorList, ServiceName, etc.),
  Service Search Request + Service Attribute Request builders.
  PSM 0x0001 surfaced as a constant.
- **SDP server** (`sdp_server`): request handler against a one-record
  database (Serial Port Profile record on RFCOMM server channel 1):
  Service Search / Service Attribute / Service Search Attribute
  with UUID normalisation through the Bluetooth Base UUID, browse-root
  matching, attribute ranges, and fail-closed errors (unknown handle,
  bad syntax, non-empty continuation, oversize attribute list).
  Never issues continuation state.
- **HFP** (`hfp`): clean-room AT command codec for HFP 1.8. AT line
  tokenizer (basic / write `=` / read `?` / test `=?` forms), HF
  command builders (BRSF, CIND test/read, CMER, CHLD test, CLCC,
  ATA, AT+CHUP), AG response builders (BRSF response, OK, ERROR,
  +CIEV unsolicited indicator, +BSIR, RING). HF + AG feature
  bitmasks (codec negotiation, eSCO S4, enhanced VR, etc.). CSV
  numeric parser for +CIND / +CIEV payloads.
- **AVDTP / A2DP** (`avdtp`): clean-room AVDTP signalling codec.
  Header packing (transaction label, packet type, message type,
  signal id), Stream End Point encode/decode (SEID + In-Use bit +
  media type + TSEP), SBC Media Codec Capability blob (frequency /
  channel-mode / block-length / subbands / allocation-method
  bitmasks + bitpool range), and command builders for Discover /
  Get Capabilities / Set Configuration / Open / Start / Suspend /
  Close. PSM 0x0019 surfaced as a constant.
- **RFCOMM** (`rfcomm`): wire-frame codec for SABM/UA/DM/DISC/UIH
  with both 1-byte and 2-byte EA-coded length indicators, FCS-8 over
  the spec-mandated coverage (header for control frames, address+
  control only for UIH), and a single-DLC initiator state machine
  (Closed → Connecting → Open → Disconnecting). Server-channel ↔ DLCI
  mapping kept as plain const values.
- **RFCOMM responder session** (`rfcomm_session`): one L2CAP
  channel's multiplexer — mux SABM/DISC, per-DLCI open/data/close
  with mirrored DLCIs (no server-channel → DLCI mapping computed),
  C/R flipped on responses, UIH staging per DLC, DM for data on
  closed DLCs. Multiplexer-control UIH commands (MSC/PN/RPN/RLS/NSC)
  are unanswered (peer proceeds with defaults).
- **HOGP** (`hogp`): HID-over-GATT profile builder. Composes the
  mandatory HID Service layout (HID Information, Report Map, HID
  Control Point + N Reports each with a Report Reference descriptor
  and CCCD when notify is requested), plus the optional Protocol
  Mode + Boot Keyboard / Boot Mouse Reports for hosts that fall back
  to boot protocol. Boot-report encoders for the canonical 8-byte
  keyboard and 3-byte mouse layouts.
- **USB transport + quirks** (`usb_transport` / `btusb_quirks`): standard
  Wireless Controller class matching, HCI USB framing, vendor-family lookup,
  firmware candidates, and WCN6855 target identity `10ab:9309`. The concrete
  endpoint/DFU implementation lives in `narf-drivers-usb`; late USB discovery
  adopts its completed async bring-up through `register_ready_transport`.

### Out of scope (deliberate)
- Realtek / Broadcom USB vendor firmware protocols (Intel, MediaTek and
  Qualcomm loaders live in `narf-drivers-usb::btusb`) and Bluetooth
  policy daemons.
- Pairing initiation from the kernel on application policy trigger
  (no upper-layer trigger API yet), and SCO/eSCO isochronous USB
  transport. Staged channel payloads have no socket/devfs consumer
  yet (drain APIs exist; wiring is follow-up).

## Cap surface

`Cap<Bluetooth, Grant>` — TCB-only mint, authorises transport
registration + admin-class HCI commands (Reset, Set Event Mask).
Per-channel data ops are gated separately once L2CAP lands.
