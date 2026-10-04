# drivers/i3c — I3C Controller Drivers

This crate holds the I3C controller (master) hardware drivers that
realize the abstract bus interface defined by the `i3c` protocol core.
Where `i3c` describes what an I3C bus does — transfers, Common Command
Codes, Dynamic Address Assignment, HDR-DDR, and In-Band Interrupts —
this crate drives the silicon that actually puts those transactions on
the wire, implementing the core's bus trait and registering each live
controller so client drivers can find it.

Two controller backends are provided. The first is a driver for the MIPI
I3C Host Controller Interface (HCI), the vendor-neutral MMIO register
map that several implementations share; it supports both PIO operation,
where command and response words are pushed and popped through the
controller's queue ports under software control, and a DMA ring mode in
which the controller streams commands and responses through host-memory
rings for higher throughput. The second backend targets NXP's I3C master
IP as found in the i.MX and MCX families, a distinct non-HCI register
layout with its own request-encoding and DAA sequencing. Both are
clean-room implementations following publicly documented register maps.

Each driver translates the core's high-level operations into its
controller's native command format: DAA runs the ENTDAA handshake and
returns the enumerated targets, CCCs are encoded as broadcast or
directed commands, and IBIs surface through the controller's in-band
interrupt path to wake the async handlers registered against the core.

Probing is initcall-driven: the crate's registration hook installs the
controller probes so the kernel's driver/runtime discovery machinery can
bring up whatever I3C master a given platform carries, with no-match on a
platform lacking an I3C controller being a quiet, non-fatal outcome.

The crate is `no_std` and async, matching the protocol core, and builds
for the kernel's supported architectures.
