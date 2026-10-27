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
