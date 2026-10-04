# drivers/usbpd — USB-C Port Controller Drivers

This crate holds the USB-C Power Delivery controller drivers that realize
the `usbpd` protocol core on real silicon. Where `usbpd` defines the PD
message codecs, the TCPM policy-engine state machine, and the abstract
TCPC (Type-C Port Controller) interface, this crate provides concrete
chip drivers and the glue that connects a detected port controller to the
policy engine, the extcon connector class, and — for DisplayPort Alt
Mode — the GPU.

Two ownership models coexist, because real laptops split PD duties
differently. On firmware-owned platforms a PD policy manager lives behind
ACPI UCSI (USB Type-C Connector System Interface, hardware ID PNP0CA0):
here firmware owns PD policy and the connector mux, and the crate's UCSI
driver speaks the UCSI command protocol over its ACPI shared-memory
transport to read connector state and publish it to the Type-C connector
class, without running a second policy engine or programming the mux. On
host-owned platforms the crate instead drives the TCPC chip directly.
Because the two must never compete for the same controller, raw TCPC
probing is suppressed whenever a UCSI PNP0CA0 device is present.

The host-owned path provides drivers for the ON Semiconductor FUSB302B —
a low-level BMC-PHY TCPC where the policy engine does all the protocol
work — and the TI TPS65987DDH, a firmware-driven PD controller. Both
reach their chip over I2C: a bridge wraps the kernel's async I2C
controllers behind the synchronous bus interface the chip drivers expect,
so detection walks every registered I2C bus and probes each known chip at
its datasheet address. A detected TCPC is parked in a port registry, and
the crate spawns a per-port async task that drives the core's TCPM state
machine — sink or source, chosen from CC orientation at attach — to a
Ready contract and keeps it alive across detach and re-attach, at a
wall-clock cadence calibrated from the PD timing requirements. A
companion task performs DisplayPort Alt Mode discovery once the port is
ready and bridges a configured DP tunnel to the GPU via a stable
connector identifier. A policy module supplies the default sink and
source policies the state machine evaluates against.

The chip drivers are clean-room implementations from public silicon
datasheets. Probing is initcall-driven at Late stage, after I2C and ACPI
are up, and is quiet on platforms with no matching controller. The crate
is `no_std` and async.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Stage: 5 (laptop connector integration)
