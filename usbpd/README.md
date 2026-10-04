# usbpd — USB Power Delivery and Type-C Port Manager Core

This crate is the protocol core for USB Power Delivery (USB-PD) and the
Type-C Port Manager (TCPM). It is the hardware-independent half of the
USB-C power and alternate-mode subsystem: the wire-format codecs and the
policy state machine that negotiates power contracts and alternate
modes, with no silicon of its own. The matching controller drivers live
in `drivers/usbpd`; this crate is what they drive against, and it is also
consumed by `drivers/extcon` for its shared PD/Type-C data types.

USB-PD is the protocol that lets two devices across a USB-C cable
negotiate how much power flows and in which direction, carried as BMC-
encoded messages over the cable's CC (configuration channel) wires. The
crate provides the message layer — PD message header encode/decode and
the Power Data Object and Request Data Object codecs that describe what a
source can supply and what a sink asks for. On top of that sits the
Type-C Port Manager: a policy-engine state machine that drives a port
from unattached through attach, capability discovery, capability
selection, and the sink/source power transition to a settled contract,
yielding the negotiated voltage and current.

Between the state machine and the hardware is the TCPC (Type-C Port
Controller) interface — a register-level abstraction for sensing the CC
pins, programming port role and termination, and transmitting and
receiving PD frames. Vendor TCPC chip drivers implement this interface,
which is how the hardware-independent policy engine stays independent.

The crate also carries the Vendor Defined Message layer, including the
DisplayPort Alt Mode discovery and configuration codecs (per the VESA DP
Alt Mode standard), so a port can be walked through alt-mode discovery
and configured for DisplayPort over USB-C. A separate SOP'/SOP'' codec
handles cable-plug VDMs — the messages addressed to the electronically
marked cable itself rather than the port partner — decoding cable
identity and passive/active cable capability objects.

Access to the PD control surface is gated by the kernel capability
system through a dedicated PD capability type. The crate is a clean-room
implementation derived strictly from the public USB-IF USB-PD, Type-C,
and TCPCI specifications and the VESA DP Alt Mode standard, with no GPL
or Linux source consulted. It is `no_std` and runs on x86_64 and
aarch64.

- Spec: [`specification/spec.md`](./specification/spec.md)
