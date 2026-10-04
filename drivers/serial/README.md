# drivers/serial — 8250/16550 UART and Serial Drivers

`narf-drivers-serial` provides NARF's serial-port drivers: the
8250/16550 UART family that underpins the PC COM ports, along with the
enumeration paths that find serial hardware on modern platforms. Serial
ports remain essential kernel infrastructure — they carry the early boot
console and debug output long before richer I/O is available — so this
crate is both a device driver and a dependency of the kernel's console
bring-up.

The centerpiece is the 8250/16550 driver, which handles the classic
legacy ports (COM1-COM4 at the fixed I/O addresses 0x3F8/0x2F8/0x3E8/
0x2E8) with FIFO and baud-rate programming and byte-level I/O, plus an
early-console path that probes COM1 and programs it for 115200 baud
before full interrupt setup so the earlycon can print during boot.
Beyond the fixed legacy ports, the crate enumerates non-legacy UARTs
several ways: ACPI PNP0501 device enumeration, PCI class-match probing
for PCI-attached 8250/16550 ports (x86_64), and an Intel LPSS path for
the low-power subsystem UARTs found on recent Intel SoCs. An ARM PL011
module provides the aarch64 UART. A small registry tracks discovered
ports.

Each enumeration path registers an init call at Stage `Subsys` so the
driver framework and bus/ACPI layers can wire ports up during startup.
The crate depends on arch, bus, capabilities, the driver framework,
ACPI/AML, memory, interrupts, console, and init, and is `no_std`,
spanning both x86_64 (8250/PCI/LPSS) and aarch64 (PL011) targets.
