# drivers/extcon — External Connector Framework and Type-C Class

This crate is NARF's external-connector (extcon) framework together with
the USB Type-C connector class that builds on it. A modern USB-C port is
a single physical receptacle that can simultaneously carry USB data,
Thunderbolt/USB4, DisplayPort, analog audio, and power delivered over
USB-PD, and whose orientation and roles are negotiated rather than fixed.
This crate gives the kernel one place to track what is actually plugged
into each connector and to notify the subsystems that need to react.

The framework layer models a connector as a device that reports the
state of a set of named cables (USB, headphone, DisplayPort, and so on)
and that consumers can look up and subscribe to for change
notifications. State updates release the connector's lock before
invoking subscriber callbacks, and callbacks are required to be
non-blocking, so notification never serializes behind connector work.

The Type-C layer specializes this for USB-C receptacles. It tracks cable
orientation and the data and power roles, retains the host-controlled
interfaces to the port's TCPC (Type-C Port Controller) and its
signal mux/retimer, and carries the Alternate Mode negotiation helpers
for DisplayPort and Thunderbolt Alt Modes. Crucially it accommodates two
ownership models for the same hardware: on ACPI laptops a firmware policy
manager (UCSI) owns PD policy and the mux, so the connector also accepts
a firmware-state update that publishes USB host/device, DP, USB4-dock,
and audio-adapter state and clears entered modes on disconnect — without
the connector itself programming a host mux or synthesizing DP pin
assignments. On host-owned ports the TCPC/mux interfaces drive the
connector directly. A sysfs bridge surfaces connector and cable state to
userspace in the familiar extcon layout.

The crate depends on the `usbpd` protocol core for PD/Type-C data types
only. Its own driver, `drivers/usbpd`, drives this crate — registering
connectors and pushing CC, role, and alt-mode updates as PD events land
— so to avoid a dependency cycle this crate must not import that driver.
The design is architecture-independent. The crate is `no_std`.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Stage: 5 (firmware Type-C integration alongside host PD paths)
