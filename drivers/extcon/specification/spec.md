# External connectors — specification

## 1. Purpose & scope

Represent connector orientation, roles, cables and alternate modes; notify
consumers independently of whether PD policy belongs to firmware or the host.

## 2. Assumptions

The registering driver owns the connector. A connector's name is a stable
identity, not a GPU PHY index or NHI function number.

## 3. Public interface

`class::register` publishes an `Arc<dyn ExtconDevice>`. Consumers use lookup,
cable-state reads and `ExtconEventSink` subscriptions. `TypecConnector`
retains the host-controlled TCPC/mux interfaces and adds
`update_firmware(FirmwareState)` for UCSI-owned connectors. That update
publishes USB host/device, DP, USB4 dock and audio-adapter state and clears
entered modes on disconnect. It does not invoke the host mux or synthesize
DP pin assignments from firmware state.

## 4. Invariants

State updates release the connector lock before subscriber callbacks.
Callbacks are non-blocking. Disconnected firmware state cannot assert a cable.
Host PD/mux operations must not compete with firmware for one connector.

## 5. Architecture notes

Architecture-independent state and notification model.

## 6. Dependencies

`usbpd`, `lib`, allocation. UCSI is a consumer of this crate, not a dependency.

## 7. Stage assignment

Stage 5 firmware Type-C integration alongside existing host PD paths.

## 8. Open work

Board-specific connector-to-GPU wiring and hotplug integration must be
provided by platform discovery; enumeration order is not a wiring map.
