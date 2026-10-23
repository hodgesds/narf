# drivers/sdio

Owned standard SDHCI PIO command execution, SDIO card enumeration and
function access, with PCI class 08:05:00/01 dispatch to exact SDIO chip
consumers. The initial profile is 3.3 V, one-bit legacy timing, at most
25 MHz and no DMA. CYW43439 uses the resulting card for firmware boot,
F2 packet service and station attachment. Platform-specific clock/power
binding and physical controller acceptance remain open. Public contracts
and remaining software are in [the specification](specification/spec.md).
