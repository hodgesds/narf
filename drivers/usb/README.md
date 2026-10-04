# drivers/usb — USB Host Stack and Class Drivers

This crate is NARF's USB stack: the host-controller drivers that put
transactions on the wire, the enumeration and transfer plumbing that
sits above them, and a broad set of class drivers that turn enumerated
devices into usable subsystems. USB is a host-driven, tiered bus — a
root hub on the controller, optional external hubs beneath it, and
devices addressed through the resulting tree — carrying four transfer
types (control, bulk, interrupt, isochronous) across endpoints described
by device, configuration, interface, and endpoint descriptors. The crate
covers that whole span, from MMIO register programming up to feeding the
kernel's input, block, network, audio, video, and Bluetooth subsystems.

## Host controllers

The primary host-controller driver targets xHCI (the eXtensible Host
Controller Interface, USB 3.x), implemented across its command,
transfer, and event rings, device-context arrays, scratchpad buffers,
slot/endpoint management, and port enumeration. The legacy controllers —
EHCI (USB 2.0), OHCI and UHCI (USB 1.1) — are present as structural
probe paths: they are discovered and logged but defer live operation,
since the bring-up target hardware is xHCI-only, while the registrations
keep expansion cards and future SoCs from showing up as unbound devices.

## Enumeration and transfers

Above the controller sit the shared mechanisms every class driver uses:
a device-attach dispatcher that resets and enumerates a port, reads
descriptors, and recurses through hubs; control, bulk, interrupt, and
isochronous transfer helpers; a hub class driver; a USB-device handle
that class drivers hold; a VID/PID-keyed class-driver registry; and
firmware-upload and DFU (Device Firmware Upgrade) helpers for chips that
load runtime firmware over the bus. Enumeration is coordinated by a
long-running supervisor task that retries attach on each connected root
and downstream port until it binds, drains interrupt-IN endpoints into
the input ring, handles hot-plug via port link-state transitions, and
performs idle suspend — all with per-port time budgets so a stuck port
cannot starve the rest of the bus.

## Class drivers

The crate implements a wide range of device classes. Human Interface
Devices (HID) have the largest footprint: boot and report-descriptor
parsing, keyboard, mouse, touchpad, and consumer-control decoders, plus
vendor quirk tables for Apple, Microsoft, Logitech (Unifying/DJ
receivers and HID++), and Wacom. Communications Device Class support
covers CDC descriptor parsing, ACM (USB serial modems, feeding the
`/dev/ttyUSB*` nodes through a devfs bridge) and NCM (USB networking),
alongside dedicated USB-Ethernet drivers for the Realtek RTL8152/8153
family. Mass Storage uses Bulk-Only Transport with an embedded SCSI
command set to present USB drives to the block layer. USB Audio (UAC)
and USB Video (UVC, with a streaming path) feed the audio and video
subsystems. Bluetooth-over-USB provides the HCI transport, including a
Qualcomm (QCA) variant. Further class drivers cover CCID smart-card
readers (with T=0 and T=1 protocol handling), fingerprint-reader
transports and the WBDI biometric wrapper, Xbox gamepads (xpad), and
USB-to-serial bridge chips (FTDI, CP210x, PL2303, CH341) exposed as TTYs.

Host-controller and class code is written from the public USB
specifications; since NARF's relicense to GPL-2.0-or-later, explicitly
identified paths also draw on the corresponding upstream Linux drivers.
Initcalls register the host controllers and class subsystems and arm the
enumeration supervisor; the supervisor early-returns when no xHCI
controller is present so no idle task is spawned on USB-less systems. The
crate is `no_std` and async.

- Spec: [`specification/spec.md`](./specification/spec.md)
