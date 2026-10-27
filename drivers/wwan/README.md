# drivers/wwan — Cellular Modem (WWAN)

`narf-drivers-wwan` is NARF's Wireless Wide Area Network subsystem —
support for M.2/USB cellular modems. WWAN modems attach over USB,
PCIe/MHI, or shared memory, and each physical device typically
exposes several logical ports at once (an AT command channel, a
control protocol channel, and one or more raw IP data bearers). This
crate defines the abstract notion of such a port and the protocol
layers that ride on top of it.

At its center is a port abstraction that classifies a channel by the
protocol it carries — AT commands, MBIM, QMI, or raw data — and
offers a simple send/receive surface over the underlying transport.
Two control protocols are modeled: MBIM (USB-IF Mobile Broadband
Interface Model, MBIM 1.0) and QMI (Qualcomm's Modem Interface)
control-message framing and service IDs. A third module describes
Intel's IOSM (IPC Over Shared Memory) protocol used by XMM 7360/7560
ePCIe modems, carrying the PCI device-ID table for those parts;
IOSM's ring/doorbell state machine resembles Qualcomm's MHI, which
NARF already scaffolds for ath11k.

## USB CDC-MBIM (live path)

USB-first, per the small-drivers wave (issue #1032): a CDC-MBIM
class driver registered with the USB class registry binds MBIM
functions (CDC-Comm subclass 0x0E plus the MBIM functional
descriptor; NCM/NCM-MBIM-in-NCM-mode functions stay with `cdc_ncm`).
Bring-up runs the MBIM control conversation — OPEN, DEVICE_CAPS,
SUBSCRIBER_READY_STATUS, RADIO_STATE — over an async transport
abstraction (`MbimTransport`), with full COMMAND fragmentation
reassembly and unsolicited INDICATE_STATUS capture. Sessions are
activated through the public `usb_mbim::connect` API: PACKET_SERVICE
attach, CID_CONNECT, IP_CONFIGURATION_INFO, and publication of a
raw-IP netdev per session into `narf-net`'s registry (`wwan<N>` for
session 0, `wwan<N>s<id>` for the rest), addressed and carriered
from the modem-reported configuration. Data moves as NTB-16 frames
whose NDP16 signatures carry the session id (the Linux `cdc_mbim`
demux discipline); each session netdev's transmit cookie pins its
(bearer, session) pair, so frames cannot cross between sessions.
A refused connect surfaces as a typed `WwanError::ModemStatus` and
publishes nothing; a disconnect keeps the netdev registered with
carrier down.

The crate registers exactly one initcall, `wwan-usb-mbim` at
Stage::Subsys.

## Deferred

IOSM/PCIe activation (the ID tables are in place; there is still no
IOSM transport, and no `wwan-iosm` initcall is registered), QMI
device binding, DSS (Device Service Stream) channels — including
verification of the DSS NDP16 signature base against MBIM 1.0 §6 —
SIM management, USSD/STK/SMS, the Radio Interface Layer, modem
firmware loading, and MHI ring bring-up. There is deliberately no
auto-connect at probe: session activation waits for an APN policy
above this crate, so a bound modem idles with its radio state
reported and no bearer up.
