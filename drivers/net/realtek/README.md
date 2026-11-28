# drivers/net/realtek — Realtek r8169/RTL8125/RTL8126/RTL8127 NIC family

One crate for the whole Realtek PCIe family, because the drivers form
a dependency chain (`rtl8127` → `rtl8126` → `rtl8125` → `r8169`)
sharing the `rtl_phy` helpers — in-crate references instead of four
separate crates. Each driver still registers its own PCI matches and
implements `HwNic`: `r8169.rs` (RTL8168/RTL8111, the most complete
cut, with TX checksum/TSO, VLAN insertion, RX checksum decode, jumbo
rings, WoL, and EEE), `rtl8125.rs` (2.5 GbE), `rtl8126.rs` (5 GbE),
and `rtl8127.rs` (10 GbE, including the RSS register model). Shared
code lives in `features.rs` (one feature model for the family),
`phy_access.rs`, and `rtl8168.rs` (per-revision PHY init tables).
The parent README's `r8169` and `rtl8125` rows both describe drivers
in this crate.

Dual-build: the built-in build includes all four drivers. The module build
runs the shared RTL8125 hardware engine through device-scoped KABI grants,
with TX callbacks and a receive/link poller. Its bring-up profile supports
RTL8125B XID `0x641` (including host PCI `10ec:8125` revision 05); other
XIDs fail explicitly. It does not claim module support for the other families.
`register() -> i32` propagates registration failures to the module loader.

Build with `cargo xtask build-module --package narf-drivers-net-realtek
--no-default-features --features module --out target/rtl8125-bringup.ko`
(on one command line). Add `--arch=aarch64` for the other target. A kernel
that will load it must select `narf-drivers-net/rtl8125-module-only`, which
suppresses the built-in RTL8125 PCI registration.

The module waits up to 60 seconds for `rtl_nic/rtl8125b-2.fw` to appear in
the firmware registry. Carrier and TX stay disabled until parsing, PHY
patching and autonegotiation setup succeed. Firmware reads use 64 KiB
chunks with a fallible allocation of the reported total size. Interpreter
execution has a 30-second deadline and an instruction budget, including
backward jumps. Errors retain DMA mappings; device reset/drain and reusable
hot-unload/rebind are not implemented.

Host validation: `cargo test -p narf-drivers-net-realtek
--no-default-features --features module --lib` executes the compiled module
against a KABI/register model, including >1 MiB firmware, delayed firmware
availability, TX/RX, bad RX, short reads, reset timeout and a firmware loop.
This is not a physical link or throughput qualification.

To compose an x86_64 development EFI image with both RTL8125B and ConnectX-3
modules, stage the Realtek firmware outside git and build:

```sh
cargo xtask pack-firmware --name rtl_nic/rtl8125b-2.fw \
  --payload /lib/firmware/rtl_nic/rtl8125b-2.fw \
  --out target/firmware/rtl_nic/rtl8125b-2.fw
cargo xtask efi-image \
  --features narf-drivers-net/rtl8125-module-only,narf-drivers-net/mlx4-module-only \
  --module-crate drivers/net/realtek/Cargo.toml \
  --module-crate drivers/net/mlx4/Cargo.toml \
  --allow-unsigned-modules \
  --initramfs-firmware rtl_nic/rtl8125b-2.fw \
  --cmdline 'narf.disks=boot-only console=ttyS0 console=tty0' \
  --output target/narf-wired-bringup.efi
```

This embeds modules stamped for the composed kernel and their autoload
arguments. The development image allows unsigned modules and firmware;
it does not install itself or access persistent root filesystems. ConnectX-3
uses onboard firmware and needs no firmware file in the archive. Qualification
still requires a cold boot on the target, carrier checks and bidirectional
traffic through each interface independently. Unload/rebind is not qualified.

- Spec: [drivers/net specification](../specification/spec.md)
