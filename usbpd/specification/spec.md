# narf-usbpd — USB Power Delivery + Type-C Port Manager

Clean-room implementation of USB-PD message framing and the
Type-C Port Manager (TCPM) sink-role state machine.

## Sources (public only)

All code is derived strictly from the references below. **No GPL
or Linux `drivers/usb/typec/` source material was consulted at any
point.**

### USB-IF specs (download from <https://www.usb.org/document-library>)

- **USB Power Delivery Specification, Revision 3.1, Version 1.8**
  (USB-IF). §6.2.1 (message header), §6.4.1 (Power Data Objects),
  §6.4.2 (Request Data Object), §6.4.4 (Vendor Defined Messages),
  §8.3.3 (sink Policy Engine state machine).
- **USB Type-C Cable and Connector Specification, Revision 2.2**
  (USB-IF). §4 (CC pin meanings, Rd/Rp termination), §4.5 (port
  attach/detach behaviour).
- **USB Type-C Port Controller Interface Specification (TCPCI),
  Revision 2.0** (USB-IF). §4 (TCPC register interface), §4.4
  (CC sense + role programming).

### VESA specs

- **DisplayPort Alt Mode on USB Type-C Standard, Version 2.0**
  (VESA). §4 (mode discovery sequence, SVID 0xFF01), §6.2
  (DP_Status VDO), §6.3 (DP_Configure VDO), §6.5 (pin assignments
  A..F).

## Scope

### Landed today
- **`message`** — Header encode/decode + CtrlMsg/DataMsg enums, Power
  Data Object codec (Fixed/Variable/Battery/Augmented per §6.4.1)
  and Request Data Object codec (§6.4.2).
- **`tcpc`** — `Tcpc` trait: `set_role`, `cc_status`, `transmit`,
  `receive`, `hard_reset`. CcState/PortRole enums.
- **`tcpm`** — Sink-role policy-engine state machine
  (Unattached → AttachWait → Attached → Startup → Discovery →
  WaitCaps → EvaluateCaps → SelectCapability → TransitionSink →
  Ready). Lands a `Contract { object_position, voltage_mv,
  op_current_ma }` on PS_RDY.
- **`vdm`** — VDM header codec (USB-PD §6.4.4), DiscoverIdentity /
  DiscoverSVIDs / DiscoverModes / EnterMode / Attention builders.
  DP_Capabilities / DP_Status / DP_Configure VDO codecs (VESA DP
  Alt 2.0). `DpAltModeDriver` walks the full alt-mode discovery
  sequence end-to-end and lands a working DP configuration.

### Out of scope (deliberate)
- Power Role Swap, Data Role Swap, VCONN Swap.
- Thunderbolt Alt Mode (Intel-specific spec, not in this crate's
  scope).
- Concrete TCPC drivers — see `narf-drivers-usbpd` for FUSB302.

## Cap surface

`Cap<UsbPd, Grant>` — TCB-only mint, authorises TCPC registration
+ admin operations (port-role swap, request a power contract).
Per-port telemetry reads need only a `Read` cap.
