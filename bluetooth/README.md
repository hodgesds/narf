# bluetooth — Bluetooth Host Stack

`narf-bluetooth` is NARF's Bluetooth host stack, implemented clean-room
from the public Bluetooth SIG Core Specification. It spans the full host
side of a Bluetooth system: the Host Controller Interface (HCI) that
talks to a controller chip, the transports that carry HCI, the core
protocol layers (L2CAP, ATT/GATT, RFCOMM, SDP), the security manager,
and a range of upper-layer profiles. The scope is the host — the
controller's link-layer radio work stays in silicon and firmware.

At the base is the HCI packet layer: a codec for Command, ACL,
Synchronous (SCO) Data, and Event packets, the HCI opcode and
event-code vocabulary, and a controller bring-up state machine that
walks a transport through the mandatory init dance (Reset, Read Local
Version, Read BD_ADDR, Set Event Mask). A command queue tracks
controller credit flow. HCI reaches hardware through a transport trait
with concrete bindings: USB (per the Wireless Controllers class),
UART H4 and three-wire H5 framing, plus vendor paths — a USB quirk table
and an Intel PCIe-attached controller driver (Lunar Lake onward, x86_64
only) with its own firmware download.

Above HCI sit the standard protocol and profile layers. L2CAP (with
enhanced retransmission mode) multiplexes logical channels; ATT and GATT
with a GATT server provide the attribute protocol behind Bluetooth Low
Energy; GAP governs discovery and connection; SMP handles LE pairing and
key management; RFCOMM and SDP provide the classic serial/ service-
discovery substrate; and BR/EDR classic command builders cover inquiry,
connection setup, secure simple pairing, and SCO. Profiles include
A2DP/AVDTP and AVRCP for audio, HFP for hands-free, the classic HID
profile and HOGP for input devices, and a Bluetooth mesh layer. Audio
profiles connect to the SBC/mSBC codecs in `narf-audio`.

The control surface is capability-gated by a dedicated Bluetooth cap
type minted only from the trusted computing base. Devices surface to
userspace through devfs (`/dev/rfcomm<N>`) and a sysfs
`/sys/class/bluetooth/` class via init calls; a probed USB controller is
bound by the USB host supervisor's per-port attach pass rather than by a
static initcall. The crate depends on capabilities, bus, I/O, firmware,
EFI, console, the driver framework, filesystem, scheduler, time, and
audio, and is `no_std`.

- Spec: [`specification/spec.md`](./specification/spec.md)
