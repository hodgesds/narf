# narf-usbpd — USB Power Delivery + Type-C Port Manager

Clean-room implementation of USB-PD message framing and the
Type-C Port Manager (TCPM) sink-role state machine.

## Sources (public only)

- **USB Power Delivery Specification, Revision 3.1, v1.8** (USB-IF)
  — message framing, Power Data Object encoding, state-machine
  prescriptions for source/sink/port partner negotiation.
- **USB Type-C Cable and Connector Specification, Revision 2.2**
  (USB-IF) — port roles, CC pin signalling, attach/detach detection.
- **Universal Serial Bus Type-C Port Controller Interface Specification
  (TCPCI), Revision 2.0** (USB-IF) — register-level interface a host
  TCPM uses to talk to a TCPC chip (FUSB302, TPS6598x, et al).

No GPL / Linux `drivers/usb/typec/` source consulted.

## Scope

Stage-1 (this crate's first cut):
- PD message header (USB-PD §6.2.1) + extended header (§6.2.1.2).
- Power Data Object (PDO) encoding — Fixed / Variable / Battery /
  Augmented (§6.4.1).
- Request Data Object (RDO) builder (§6.4.2).
- TCPC interface trait — `set_role`, `cc_status`, `transmit`, `receive`.
- TCPM sink-role state machine: Unattached → AttachWait → Attached →
  SinkStartup → SinkDiscovery → SinkWaitCaps → SinkEvaluateCaps →
  SinkSelectCapability → SinkTransitionSink → SinkReady (§8.3).

Out of scope for Stage 1:
- Power Role Swap, Data Role Swap, VCONN Swap.
- Alt-Mode (DisplayPort, Thunderbolt) discovery / configuration.
- A real TCPC driver (FUSB302 / TPS6598x). The `Tcpc` trait is the
  insertion point; an in-tree driver lands separately.

## Cap surface

`Cap<UsbPd, Grant>` — TCB-only mint, authorises TCPC registration
+ admin operations (port-role swap, request a power contract).
Per-port telemetry reads need only a `Read` cap.
