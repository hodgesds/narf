# drivers/gpio — GPIO Controller Trait and Drivers

This crate is NARF's GPIO (General-Purpose Input/Output) subsystem: the
abstract controller contract plus the host GPIO-block drivers that
implement it. GPIO controllers expose banks of individually configurable
pins that can be driven as outputs, read as inputs, or configured as
interrupt sources with a pull resistor and a trigger/polarity setting.
On a PC platform these pins are how discrete peripherals signal the host
— most importantly the interrupt line of an I2C-attached HID device,
which ACPI describes through a `_CRS::GpioInt` resource that names a
parent GPIO block and a pin within it.

The crate models a controller as a set of pins addressed by index, with
operations to read and drive a pin and to register or unregister an
interrupt handler for a pin. The configuration vocabulary mirrors ACPI
directly: pin direction, pull configuration (default / up / down /
none), and an interrupt configuration carrying level-vs-edge and active
polarity, all decoded from the same `_CRS::GpioInt` fields. Interrupt
handlers run in IRQ context when a pin fires; the controller owns its
own MMIO and handler table behind an internal lock. A name-keyed,
process-global registry lets a client — the i2c-hid binder being the
sole consumer today — resolve the `GpioInt::resource_source` ACPI path
to the GPIO controller that owns the interrupt pin.

Two controller backends are provided. The AMD FCH driver covers the
GPIO block on Zen-generation AMD laptops, where each pin is a single
32-bit register carrying its status, enable, level, and polarity bits
and the whole block shares one interrupt line that the ISR demultiplexes
by scanning pin status. The Intel PCH driver targets the GPIO
communities on Tiger Lake through Meteor Lake; it currently performs
discovery and registration — decoding the per-community MMIO regions
from `_CRS` and publishing the controller so i2c-hid can resolve its
interrupt source — with live pin programming staged for later.

Probing is initcall-driven, with the two backends registered as
independent initcalls so a no-match in one does not gate the other;
absence of any GPIO block (as on most virtual platforms) is handled
gracefully. The crate is `no_std`.
