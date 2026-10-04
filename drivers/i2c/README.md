# drivers/i2c — I2C Bus Trait and Controller Drivers

This crate is NARF's I2C (Inter-Integrated Circuit) subsystem: the
abstract bus contract together with the host-controller drivers that
implement it. I2C is the ubiquitous two-wire, multi-drop, addressed
serial bus used across PC platforms for sensors, embedded controllers,
touchpads, USB-C port controllers, and HID-over-I2C peripherals. The
crate defines what an I2C transfer is — a sequence of read/write
operations issued to a 7-bit target address with a single
(repeated-)START between operations and a STOP after the last — and
surfaces a narrow, controller-agnostic error set (device NACK,
arbitration loss, controller-reported abort, timeout, bad hardware) so
client drivers can make retry/abandon/log decisions without learning
each controller's quirks. The bus interface is async: implementors own
the controller MMIO and any IRQ vector and serialize concurrent callers
internally, so a client simply awaits a transfer.

A process-global registry keys buses by name — typically the ACPI path
of the controller — so that client drivers decoded from AML (HID-over-I2C
being the primary consumer today) can locate their parent bus without a
handle being plumbed through every initcall.

Several controller backends are included. The AMD FCH driver covers the
I2C blocks on Zen-era AMD laptops; because the FCH IP is a relabelled
Synopsys DesignWare core, the same register map serves the Intel PCH
LPSS controllers on Tiger Lake / Alder Lake / Raptor Lake and earlier,
which the crate handles as a second ACPI-discovered backend. Discovery
in both cases walks the AML namespace for the relevant hardware IDs and
decodes `_CRS` for the MMIO base and interrupt. The i801 driver handles
Intel ICH/PCH SMBus controllers and the piix4 driver the AMD/legacy
PIIX4 SMBus controller, both bound as PCI drivers. A GenericSerialBus
module bridges the gap to ACPI: it installs a dispatcher so that AML
`OperationRegion(..., GenericSerialBus, ...)` field accesses route
through the I2C registry, an inverted-dependency hook that avoids a cycle
between the ACPI interpreter and this crate.

Probing is initcall-driven; the per-controller probes run as independent
initcalls so a no-match or failure in one backend never gates the
others, and a platform with no matching controller reports absence
quietly rather than failing. The crate is `no_std`.
