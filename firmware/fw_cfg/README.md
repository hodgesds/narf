# firmware/fw_cfg — QEMU fw_cfg Interface Driver

`narf-firmware-fw-cfg` is a clean-room driver for QEMU's `fw_cfg`
paravirtual firmware-configuration device, implemented from QEMU's
published `docs/specs/fw_cfg.rst`. `fw_cfg` is an indexed key/value store
through which QEMU hands the guest a range of boot-time data: the kernel
command line, the boot order, ACPI and SMBIOS tables, and arbitrary
operator-supplied blobs passed via `-fw_cfg name=opt/foo,file=...`. The
kernel uses it as a simple, early-available channel to pull configuration
and firmware tables before richer discovery mechanisms exist.

Access is a two-step protocol: write a 16-bit selector key to name an
entry, then read the entry's bytes off the data register. A well-known
file-directory entry maps human-readable names like `bootorder`,
`cmdline`, and `etc/*` to their numeric selector keys, so callers look up
blobs by name. The driver validates the `QEMU` signature before trusting
any entry, so it can cleanly report absence on non-QEMU platforms.

The transport differs by architecture. On x86_64 the driver uses the
legacy port-I/O interface — a selector port and a data port — reading the
entry as a byte stream; the DMA-channel interface is not implemented
because streaming reads cover every entry the kernel needs. On aarch64 it
uses the MMIO interface exposed by the `qemu,fw-cfg-mmio` device, whose
window on `qemu-system-aarch64 -M virt` sits at a fixed physical base.
A subtle but load-bearing detail the driver gets right: the MMIO selector
register is written big-endian even though the x86 port selector is host
little-endian. The devicetree walk that supplies the MMIO base in
production lives in `init/`; bring-up code sets the base explicitly.

This crate is `no_std`. It depends on `narf-arch` for the architecture
port-I/O and MMIO primitives, and on `narf-init` for boot wiring. The
driver is implemented clean-room from QEMU's published `fw_cfg.rst`
device specification.
