# WWAN — Specification

> Status: **v0.1** (Stage 4 compatibility; USB CDC-MBIM control path).

## 1. Purpose & scope

`narf-drivers-wwan` models cellular modem control ports, MBIM and QMI
protocols, USB CDC-MBIM binding, and raw-IP bearer publication. IOSM/MHI
transport activation and user-facing modem policy remain out of scope.

## 2. Assumptions

- USB device operations are provided by `drivers/usb` and remain valid
  for the lifetime of their `Arc<USBDevice>` handles.
- Port registration is global and callable from multiple CPUs.
- A modem does not auto-connect; APN and session policy belong above
  the transport binding.

## 3. Public interface

- `WwanPort` exposes `name`, `kind`, `send`, and `recv`. It requires
  `Send + Sync` because registered `Arc` ports are stored in one
  cross-CPU registry and may be called through shared references.
  Implementations synchronize mutable transport state internally.
- `register_port` publishes an owned port. `ports`, `port_count`, and
  `port_by_name` provide registry snapshots and lookup.
- `bearer::register_dss_stream` publishes a DSS stream port
  (`WwanPortKind::Dss`, name `wwan{bearer}dss{session}`) for one
  DSS session of one bearer; `bearer::ndp_signature_stream` decodes
  an NDP16 signature into `NdpStream::Ips` / `NdpStream::Dss`
  (Linux `USB_CDC_MBIM_NDP16_IPS_SIGN` / `_DSS_SIGN` from
  `include/uapi/linux/usb/cdc.h`, session in byte 3).
  MBIM_CID_DSS_CONNECT is NOT part of this interface: its service
  UUID, CID, and payload layout did not ground from any source
  reachable for #1143, so no connect command is built.
- `MbimTransport` is the asynchronous transport seam used by the MBIM
  session state machine. `usb_mbim::connect` is the USB activation API.
- `SubscriberReadyInfo::parse` decodes the 28-byte MBIM fixed header:
  ready state, subscriber ID string, SIM ICCID string, and ready-info
  flags; the telephone-number array remains ignored.

## 4. Invariants

- Registry synchronization protects only registry metadata; port
  callbacks and USB operations run without the registry lock held.
- The MBIM descriptor parser returns a function only when the control
  descriptor, notification endpoint, data interface, and bulk pair
  form one complete function.
- A refused MBIM connection publishes no bearer; disconnect retains
  the netdev with carrier down.
- IPS and DSS are separate delivery namespaces: a DSS datagram is
  delivered only to its session's registered DSS stream port, an
  IPS datagram only to its session's netdev, and neither is ever
  cross-delivered — including at the same numeric session id. An
  NCM-signed NTB is not an MBIM NDP and is rejected whole.

## 5. Architecture notes (x86_64, aarch64)

The codec and registry are architecture-neutral. USB transport support
depends on the USB controller implementation available on each target;
the parser and session state machine do not assume x86 register access.

## 6. Dependencies

The crate depends on the USB device/class registry, scheduler async
bridge, network-device registry, and the shared driver framework.

## 7. Stage assignment

Stage 4: Linux-compatible USB CDC-MBIM control and data paths. IOSM/MHI
transport and QMI device binding are follow-on work.

## 8. Open questions

- What supported modem API should initiate session activation and
  supply APN policy?
- Which supported xHCI targets need device-specific MBIM quirks?
