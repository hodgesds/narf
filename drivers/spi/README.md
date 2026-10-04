# drivers/spi — SPI Bus Trait and Controller Drivers

This crate is NARF's SPI (Serial Peripheral Interface) subsystem: the
abstract bus contract together with the host-controller drivers that
implement it. SPI is the four-wire, full-duplex, master-driven serial
bus used for flash memories, sensors, trackpads, and other board
peripherals. The crate defines what an SPI transfer is — bytes clocked
out of the transmit buffer while bytes are simultaneously clocked into
the receive buffer, with the shorter slice setting the length — and the
surrounding configuration: chip-select selection, SCK frequency, and the
clock polarity/phase mode. SPI mode is the (CPOL, CPHA) pair numbered
0–3; the crate's encoding places CPOL at bit 1 and CPHA at bit 0 to
match the conventional `SPI_MODE_*` layout and the AMD FCH mode field.
A narrow error surface (timeout, bad hardware, frequency out of range,
invalid chip-select, buffer-too-large-for-FIFO, generic hardware error)
lets client drivers make policy decisions without controller-specific
knowledge. Controllers own their MMIO and serialize concurrent callers
with an internal lock; a name-keyed, process-global registry (keyed by
ACPI path or PCI BDF) lets client drivers locate a bus, with duplicate
controller paths collapsed on registration.

Several controller backends are included. The AMD FCH SPI driver covers
the controller on AMD platforms (its V1/V2/HID2 variants). The Intel
LPSS driver covers the PXA-derived SSP SPI masters on Skylake through
Alder Lake and later. A distinct Intel PCH SPI *flash* driver handles
the BIOS-flash hardware sequencer — physically separate silicon from the
LPSS SSP masters — and is read-only by design. Two Arm-oriented backends
round out the set: a Cadence SPI driver (Xilinx Zynq and other Arm SoCs)
and an Arm PrimeCell PL022 SSP driver, both commonly needed on aarch64
boards. Register maps are drawn from the corresponding upstream Linux
drivers under the kernel's GPL-compatible license.

Probing is initcall-driven: each backend registers an independent
initcall so a no-match or failure in one does not gate the others, and a
platform without a given controller reports absence quietly. The crate
is `no_std`.
