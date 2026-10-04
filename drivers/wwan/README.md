# drivers/wwan — Cellular Modem (WWAN) Scaffold

`narf-drivers-wwan` is NARF's Wireless Wide Area Network subsystem —
the beginnings of support for M.2 cellular modems. WWAN modems attach
over USB, PCIe/MHI, or shared memory, and each physical device typically
exposes several logical ports at once (an AT command channel, a control
protocol channel, and one or more raw IP data bearers). This crate
defines the abstract notion of such a port and the protocol codecs that
ride on top of it.

At its center is a port abstraction that classifies a channel by the
protocol it carries — AT commands, MBIM, QMI, or raw data — and offers a
simple send/receive surface over the underlying transport. Two control
protocols are modeled as codec layers: MBIM (Microsoft's Mobile
Broadband Interface Model, MBIM 1.0), with message-header encode/decode,
and QMI (Qualcomm's Modem Interface) control-message framing and service
IDs. A third module describes Intel's IOSM (IPC Over Shared Memory)
protocol used by XMM 7360/7560 ePCIe modems, carrying the PCI device-ID
table for those parts; IOSM's ring/doorbell state machine resembles
Qualcomm's MHI, which NARF already scaffolds for ath11k.

Scope is Stage 0/1: protocol codecs and static device tables only. SIM
management, USSD/STK/SMS, the Radio Interface Layer, actual modem
firmware loading, USB CDC-MBIM endpoint plumbing, and MHI ring bring-up
for IOSM are all deferred to later stages, and there are no initcalls to
register yet because there is no live hardware path. The port trait is
synchronous for now; an async wrapper is planned once the scheduler's
waker integration is ready. The crate is `no_std` and depends only on
`narf-lib`.
