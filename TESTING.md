# Testing NARF

This document covers all the ways to exercise NARF — from a 30-second
QEMU boot to a full real-hardware install on a Renoir-class laptop.

## Quick reference

| Goal | Command |
|------|---------|
| Boot under QEMU, async demo | `cargo xtask run --arch=x86_64` |
| Boot under QEMU, graphical | `cargo xtask run --arch=x86_64 --display=gtk` |
| Run the full kernel-test suite | `cargo xtask test --arch=x86_64` |
| Run the real-init boot-smoke | `cargo xtask boot-smoke --arch=x86_64` |
| Build a bootable ISO | `cargo xtask image --arch=x86_64` |
| ISO + boot under OVMF UEFI | `cargo xtask iso-boot --arch=x86_64` |
| Demo with user-mode testbin + shell | `cargo xtask demo --arch=x86_64 --display=gtk` |
| Burn ISO to USB stick | `sudo cargo xtask disk-write --device /dev/sdX` |
| Lay down GPT + ESP + ext4 install | `sudo cargo xtask disk-write-partitioned --device /dev/sdX --yes` |

Every command takes `--arch=aarch64` instead of `--arch=x86_64` if you
want to exercise the ARM path.

## Prerequisites

- **Rust nightly** — pinned in `rust-toolchain.toml`. `rustup` picks up
  the pin automatically on first `cargo` invocation; no manual
  `+nightly` needed.
- **QEMU** — `qemu-system-x86_64` and/or `qemu-system-aarch64`.
  - Debian / Ubuntu: `apt install qemu-system-x86 qemu-system-arm`
  - Arch: `pacman -S qemu-full`
  - macOS: `brew install qemu`
- **OVMF** UEFI firmware for `iso-boot`.
  - Debian / Ubuntu: `apt install ovmf`
  - Arch: `pacman -S edk2-ovmf`
- **ISO build chain** — only the `image` / `iso-boot` / `disk-write`
  subcommands need these.
  - Debian / Ubuntu: `apt install xorriso mtools`
  - Arch: `pacman -S libisoburn mtools`

xtask cross-builds against `x86_64-unknown-none` / `aarch64-unknown-none`
with `-Z build-std=core,compiler_builtins,alloc`. NVMe disk images and
the QEMU virt DTB are generated lazily into `target/`.

---

## QEMU testing

### Async-demo boot (the simplest path)

```sh
cargo xtask run --arch=x86_64
```

Boots a kernel build that runs the cooperative async executor for five
timer ticks, prints diagnostics, then exits cleanly via `isa-debug-exit`.
Default display mode is `none` (serial on stdio only) — fast, scriptable,
no graphical window.

### Graphical display

```sh
# host UI determined automatically:
cargo xtask run --arch=x86_64 --display=gtk      # GTK (Linux)
cargo xtask run --arch=x86_64 --display=sdl      # SDL (cross-platform)
cargo xtask run --arch=x86_64 --display=cocoa    # macOS native
```

The kernel's framebuffer driver paints on the QEMU VGA / virtio-gpu
output. Useful for working on the FB console, splash screen, or the
shell at the `narf>` prompt.

### Remote display via VNC

When you want to run the kernel on a remote host (CI, a beefy GPU
build server, a Raspberry Pi running aarch64-host QEMU) but interact
with the framebuffer from your laptop:

```sh
# Server-side (the host running QEMU):
cargo xtask run --arch=x86_64 --display=vnc:127.0.0.1:5

# Client-side, on your laptop:
vncviewer <server-ip>:5905
# or
xtigervncviewer <server-ip>:5905
```

The `:5` suffix is the VNC display number (port = 5900 + N). Bind to
`0.0.0.0` instead of `127.0.0.1` if your client isn't on the same host
— but understand the framebuffer is unauthenticated by default. For
real CI use, prefer an SSH tunnel:

```sh
# Server-side:
cargo xtask run --arch=x86_64 --display=vnc:127.0.0.1:5

# Client-side, via SSH tunnel:
ssh -L 5905:127.0.0.1:5905 <server>
vncviewer 127.0.0.1:5905
```

### Hardware profiles

Default is `full` — all supported emulated devices enabled. Useful for
isolating driver paths when one is misbehaving:

```sh
cargo xtask run --arch=x86_64 --hw-profile=minimal      # serial only
cargo xtask run --arch=x86_64 --hw-profile=virtio-only  # VirtIO + serial
cargo xtask run --arch=x86_64 --hw-profile=legacy-only  # non-VirtIO + serial
```

`minimal` is the right profile when you're debugging the boot path or
the scheduler and don't want noisy driver init. `virtio-only` is the
fast-path profile for production-style tests (virtio-blk + virtio-net).
`legacy-only` exercises the e1000 / AHCI / SDHCI / xHCI surface
without the VirtIO shortcuts.

---

## Running the kernel-test suite

```sh
cargo xtask test --arch=x86_64
cargo xtask test --arch=aarch64
```

This:

1. Builds a kernel with the `kernel-test` feature on, which links in
   every `kernel_test_in!`-registered smoke and replaces the demo /
   shell entry point with `narf_verification::run_all_and_exit`.
2. Launches QEMU with the kernel binary.
3. The in-kernel runner iterates every test, prints
   `[ OK ] / [FAIL] / [skip]` per test, and exits via `isa-debug-exit`
   with the pass/fail aggregate code.
4. After the kernel-test phase completes, the xtask also runs a
   **boot-smoke** phase — a separate boot without `kernel-test` that
   exercises the real init flow and verifies the kernel reaches the
   "boot ready" milestone before exiting cleanly. This catches
   regressions that smokes miss because smokes test modules in
   isolation, not the full init flow.

The runner prints `── summary: <pass> pass, <fail> fail, <skip> skip ──`
on the way out. Skips are tests that need a device QEMU doesn't
emulate (e.g. Intel 82599); they exit cleanly without failing the run.

### Just the boot-smoke phase

```sh
cargo xtask boot-smoke --arch=x86_64
```

Boots the kernel **without** the `kernel-test` feature — i.e. the real
init flow — and watches stdout for panic markers + the success
milestone. The kernel triggers a clean ACPI/isa-debug-exit shutdown
after a ~2-second async-task drain. The xtask treats QEMU exit code 1
(= isa-debug-exit success) as Pass and anything else as Fail.

Useful for catching regressions like the PCR-0 self-measure UB that
kernel-test couldn't see (because it only ran in isolation, not in the
late-boot async task path).

### Running a single subsystem's tests

There isn't a per-subsystem filter at the xtask level, but the inner
runner accepts a regex via the test harness:

```sh
# Run only USB tests:
cargo xtask test --arch=x86_64 -- --filter usb

# Run only the wireless 4-way handshake:
cargo xtask test --arch=x86_64 -- --filter four_way
```

(The post-`--` flags are forwarded to the in-kernel runner.)

### Re-running on flake

Tests CAN flake — especially the ones that touch real-time or that
race the QEMU NVMe image's write lock under high parallelism. The
convention is to re-run twice before declaring a regression:

```sh
for i in 1 2 3; do cargo xtask test --arch=x86_64 ; done
```

---

## Building bootable images

### Limine ISO + boot under OVMF

```sh
cargo xtask iso-boot --arch=x86_64
```

Builds the Limine ISO (lands at `target/narf-x86_64.iso`) and boots it
under QEMU + OVMF UEFI in one step.

To just produce the ISO without booting:

```sh
cargo xtask image --arch=x86_64
```

To boot the ISO with a graphical display + the user-mode testbin
running (you'll get an interactive shell at the `narf>` prompt):

```sh
cargo xtask demo --arch=x86_64 --display=gtk
```

The ISO uses Limine as the bootloader on x86_64. On aarch64 `xtask
image` produces a kernel + DTB image bootable via QEMU `-kernel`; no
ISO is built since the aarch64 boot path is direct-kernel today.

### What's in the ISO

The Limine ISO contains:

```
/EFI/BOOT/BOOTX64.EFI    # Limine
/limine/limine.cfg       # Boot menu
/narf-x86_64             # The kernel
/initramfs.cpio          # Initial RAM filesystem
/firmware/*              # Firmware blobs (wrapped with NARF trailer)
```

The kernel cmdline (set in `limine.cfg`) typically reads:

```
quiet root=PARTLABEL=NARF_ROOT
```

When booted from the ISO (vs from a partitioned install), the root
walker falls through to the initramfs shell since there's no
`PARTLABEL=NARF_ROOT` on the boot device.

---

## Real-hardware boot

### Burning the ISO to a USB stick

```sh
# Auto-detect the first USB-attached disk:
sudo cargo xtask disk-write

# Or pin a specific device:
sudo cargo xtask disk-write --device /dev/sdX

# Skip the slow full-device wipe if you know the USB has no leftover
# bootable signatures past the ISO size:
sudo cargo xtask disk-write --device /dev/sdX --no-wipe

# Fast wipe: zero the MBR / GPT / EFI / El Torito regions only
# (first 100 MiB + last 4 MiB), skip the middle-of-disk zero-fill.
# Same boot-correctness as a full wipe when the USB is larger than
# the ISO.
sudo cargo xtask disk-write --device /dev/sdX --fast-wipe

# Burn a custom ISO path:
sudo cargo xtask disk-write --device /dev/sdX --iso path/to/narf.iso
```

> **Safety**: writes are destructive. xtask refuses to write to a
> device that isn't USB-attached (no `/dev/sda` that's actually your
> system disk by accident). Always double-check the device path via
> `lsblk` first.

After the `dd` finishes, xtask does a logical detach + re-probe +
read-back verification so the burn is guaranteed to land on the USB
stick's flash NAND, not the USB controller's write cache. The check
catches the failure mode where a successful `dd` exit code paired
with a still-default boot sector means the firmware has the writes
buffered but they never reached the device.

### Partitioned disk install (ESP + ext4 root)

The raw-ISO burn above produces a hybrid-MBR Limine image where the
kernel reads everything from the El Torito boot catalog. For a real
install layout — GPT with an EFI System Partition holding Limine +
kernel + initramfs, plus a labelled ext4 root partition that the
kernel auto-mounts on `/` via `root=PARTLABEL=NARF_ROOT` — use
`disk-write-partitioned`:

```sh
# Stage kernel + initramfs + Limine first (builds only, no QEMU):
cargo xtask image --arch=x86_64

# Then lay down the partitioned disk:
sudo cargo xtask disk-write-partitioned --device /dev/sdX --yes

# Tunables:
sudo cargo xtask disk-write-partitioned --device /dev/sdX \
     --esp-size-mib 512 \
     --root-fs ext4 \
     --root-label NARF_ROOT \
     --yes
```

Host-tool requirements (xtask preflights them and names the missing
package up front):

| Tool | Arch package | Debian/Ubuntu |
| --- | --- | --- |
| `sgdisk` | `gptfdisk` | `gdisk` |
| `partprobe` | `parted` | `parted` |
| `mkfs.vfat` | `dosfstools` | `dosfstools` |
| `mkfs.ext4` / `mkfs.ext2` | `e2fsprogs` | `e2fsprogs` |
| `lsblk` / `mount` / `umount` | `util-linux` | `util-linux` |

The resulting disk boots Limine from the ESP, which loads the kernel
with `kernel_cmdline: quiet root=PARTLABEL=<label>`. At mount time,
the root-mount walker matches that selector against GPT metadata the
partition scanner attached at registration — typo the label and the
kernel falls through to the initramfs shell instead of mounting the
wrong volume.

### Tested target laptops

The bring-up arc targets two AMD laptops as the reference hardware:

- **AMD Renoir 4700U** (Family 0x17 model 0x60, Zen2 + Vega8 / DCN 2.0)
- **AMD Phoenix HawkPoint1** (Family 0x19 model 0x74, Zen4 + RDNA3.5 /
  DCN 3.5)

Most driver work covers both. Boot logs and on-screen diagnostics
target a fixed FB status-panel slot so issues are observable without
a serial console.

### Real-hardware boot tips

- **First boot will not have hardware your QEMU profile lacks**. Expect
  the boot log to surface fresh "probe failed" / "probe skipped" lines
  for laptop-specific peripherals (touchpad, fingerprint, NFC, camera
  ISP) — those are points of interest, not failures.
- **AMD FCH xHCI port-power quirk**: this is now wired in `xhci.rs`,
  but if your platform has an even-more-obscure port-power scheme,
  you'll see `xhci: N of M root-hub port(s) connected after PP=1` with
  N=0 — that's the diagnostic to grep for.
- **SDHCI on AMD Renoir / Phoenix**: needs the D3hot pre-reset cycle.
  Wired in `sdhci.rs`. If it fails, the log shows `sdhci: AMD pre-reset
  PM cycle ok` followed by `sdhci: bring_up failed: ResetTimeout` —
  that's the chipset variant we don't yet match.
- **Touchpad won't enumerate**: this was the load-bearing bug; the
  slot-lifecycle fix in `attach.rs::dispatch_after_address` is the
  cure. If you see `usb-hid: kbd attached on port N` but no touchpad,
  the bug is in the dispatcher's slot ownership — file an issue.

---

## Debugging

### Reading dmesg

The kernel exposes the in-kernel ring buffer at `/dev/kmsg` (Linux-
compatible). Read it from the userspace shell:

```
narf> dmesg | head -50
narf> grep "AMD" /dev/kmsg
narf> dmesg | grep usb-hid
```

The shell's grep supports `-i` (ignore case), `-v` (invert), `-m N`
(max matches), `-u` (dedupe), and `"quoted patterns"` for multi-word
matches.

### GDB stub

NARF ships a serial RSP stub on COM1. Connect from host gdb:

```sh
# In one terminal, boot the kernel with a TCP serial passthrough:
qemu-system-x86_64 ... -serial tcp::1234,server,nowait

# In another:
gdb target/x86_64-unknown-none/debug/narf-frame
(gdb) target remote :1234
(gdb) info registers
(gdb) x/16i $rip
(gdb) continue
```

The stub supports `+`/`-` ACK framing, `qSupported`, `g` register
dump, `m`/`M` memory peek/poke, `s`/`c` step/continue. Hardware
breakpoints via DR0-3 and software breakpoints via INT3 are both
wired.

### Single-step boot diagnostics

When the kernel hangs early, the easiest tool is the FB status-panel
slot — it's painted at a fixed location and updates synchronously
during boot. The user can read it even when the rest of the system
is wedged.

If you can't see the FB (e.g. headless boot, broken display), serial
is the next stop:

```sh
cargo xtask run --arch=x86_64 --display=none 2>&1 | tee boot.log
grep -E "panic|fault|init:" boot.log
```

For real-hardware, the same diagnostics paint to the laptop's
display via the framebuffer.

### Wedged QEMU NVMe image

The `cargo xtask test` runner uses a shared NVMe image
(`target/narf-nvme.img`) for storage-driver smokes. If a previous run
crashed without cleanup, QEMU's write lock will block the next run:

```
qemu-system-x86_64: -device nvme,drive=nvm0,serial=narf: Failed to get
"write" lock
```

Resolution:

```sh
lsof target/narf-nvme.img         # Find the wedged QEMU
kill <pid>                         # Or wait for it to exit
# Then retry.
```

The xtask doesn't currently auto-detect this; it's on the cleanup
list.

---

## Performance measurement

NARF ships a PMU-sampling surface in `arch/src/x86_64/pmu.rs` (Intel
architectural perfmon) and `arch/src/aarch64/pmu.rs` (where exposed).
Allocate a counter:

```rust
use narf_arch::pmu::{alloc_counter, read, release, PmuEvent};

let cyc = alloc_counter(PmuEvent::Cycles)?;
let ins = alloc_counter(PmuEvent::Instructions)?;
let start_c = read(&cyc);
let start_i = read(&ins);
work();
let elapsed_c = read(&cyc) - start_c;
let elapsed_i = read(&ins) - start_i;
release(cyc);
release(ins);
```

For wall-clock measurements use `narf_time::now_cycles()` (RDTSC on
x86_64) or `narf_time::Deadline::after_ms(N)` for deadline-style
timing.

---

## CI integration

Every PR must pass:

```sh
cargo xtask test --arch=x86_64
cargo xtask test --arch=aarch64
cargo xtask boot-smoke --arch=x86_64
cargo xtask boot-smoke --arch=aarch64
```

The boot-smoke phase is the load-bearing check — it catches the
class of regression that smokes can't see because they exercise
modules in isolation rather than the full init flow.
