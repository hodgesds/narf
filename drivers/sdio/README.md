# drivers/sdio — SDHCI Host Controller and SDIO Protocol

This crate is NARF's SDIO stack: an SD Host Controller (SDHCI) driver
paired with the SDIO protocol layer that runs on top of it. SDIO carries
the SD card command/data protocol to non-storage peripherals — most
notably the Wi-Fi/Bluetooth combo chips found on many laptops and
embedded boards — exposing them as addressable functions on an SD bus
rather than as plain memory cards. The crate's job is to bring up the
host controller, speak enough of the SD/SDIO command set to enumerate
and configure a card, and present a per-function interface that a chip
driver (for example a cyw43439 bridge) can build on.

The SDHCI side provides PCI discovery (matching the SD host-controller
class and extracting the controller's MMIO base), the full SDHCI
register map with its bit definitions, encoders for the relevant bus
commands — card reset and identification, function addressing, and the
CMD52/CMD53 single-register and block I/O commands that are the heart of
SDIO — and the 1.8 V signalling-switch helpers needed for the UHS-I
voltage transition. Host state decodes the controller's capabilities,
computes clock dividers, and tracks the card's relative address and
operating-conditions registers.

The SDIO protocol side provides the CCCR (Card Common Control Registers)
and FBR (Function Basic Registers) address definitions and the CIS tuple
decoders (manufacturer, function, and function-extension tuples) used to
identify a card and its functions during enumeration, plus a per-function
abstraction over CMD52/CMD53 that chip drivers consume to read and write
their function's register space.

The command encoders and protocol decoders are pure computation,
unit-testable without hardware; live MMIO register I/O, the DMA/ADMA2
descriptor rings, UHS-II, and eMMC HS400 are deferred. Register layouts
and protocol detail follow the SD Association's SDHCI and SDIO simplified
specifications, adapted from the corresponding upstream Linux MMC drivers
under the kernel's GPL-compatible license. Probing is driven through the
kernel's PCI driver/runtime machinery. The crate is `no_std`.
