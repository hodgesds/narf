# Booting NARF from CachyOS

This guide covers testing NARF on an x86_64 machine that normally runs
CachyOS. Keep the CachyOS kernel installed and selected by default. NARF is an
additional boot target, not currently a drop-in replacement for
`linux-cachyos`.

## What works today

| Goal | Status |
| --- | --- |
| Build and boot NARF under QEMU on a CachyOS host | Supported |
| Boot the NARF ISO or a NARF USB image on a spare machine | Supported, hardware coverage varies |
| Install the native Arch package on a legacy-BIOS GRUB system | Implemented; GRUB searches for the kernel on either common `/boot` layout |
| Install the native Arch package on a UEFI GRUB system | Implemented through a package-owned Limine EFI payload |
| Boot the installed CachyOS root to a console login under NARF | Experimental: `narf.disks=root-ro` (see [Booting the installed CachyOS root](#booting-the-installed-cachyos-root)); KDE not yet |
| Boot an encrypted CachyOS root | Not yet supported by the native-package workflow |
| Use CachyOS Limine, systemd-boot, or rEFInd | Implemented through native registration, BLS, or EFI discovery |
| Boot a signed native package with Secure Boot enabled | Implemented; the enforced chain and tamper rejection are OVMF-gated, while physical firmware still needs validation |

The distinction matters. NARF can run unmodified musl and glibc programs and
has booted a generated Fedora image with systemd as PID 1 in QEMU. The native
package currently boots NARF's built-in userspace, however; it does not reuse
the CachyOS initramfs, Linux modules, or installed root filesystem.

CachyOS currently offers GRUB, Limine, systemd-boot, and rEFInd. NARF's native
package installs an isolated Limine application, kernel, and configuration
under `/EFI/NARF` on the ESP. UEFI GRUB chainloads it, systemd-boot uses its
Boot Loader Specification entry, rEFInd discovers it, and CachyOS Limine is
registered through `limine-entry-tool`. Legacy-BIOS GRUB continues to load the
Multiboot2 kernel directly. See the CachyOS
[boot-manager overview](https://wiki.cachyos.org/installation/boot_managers/)
before changing an installed machine.

In this guide, **supported** means the exact workflow has a repeatable
end-to-end acceptance test. **Implemented** means the relevant code exists and
has narrower tests; it does not imply that a particular physical machine has
passed. **Experimental** means the path is useful for development but still
has an important integration or hardware-validation gap.

## Safety checklist

Before a bare-metal test:

1. Keep `linux-cachyos` installed and configured as the default entry.
2. Have a CachyOS live USB or another known-good recovery path.
3. Back up important data. Do not use an experimental kernel boot as a backup
   test.
4. For unsigned release media, disable Secure Boot for the NARF attempt. For a
   native package, either do that or sign its bound loader with the machine's
   existing enrolled `sbctl` policy as described below.
5. Start with QEMU, then a dedicated NARF USB, and only then add a native boot
   entry.

Confirm the machine and boot layout without changing anything:

```sh
uname -m
if test -d /sys/firmware/efi; then echo UEFI; else echo "legacy BIOS"; fi
findmnt /boot /boot/efi
test -f /boot/grub/grub.cfg && echo "GRUB configuration found"
sbctl status 2>/dev/null || true
```

The CachyOS native package path uses `x86_64`. It supports the boot
managers above but does not change UEFI NVRAM, replace the active manager, or
make NARF the default. The cross-distribution packager also emits native
aarch64 UEFI packages, but CachyOS itself is an x86_64 distribution.

## Recommended first test: QEMU

Install the build and virtualization prerequisites listed in
[Running on Linux](RUNNING_ON_LINUX.md). On CachyOS these are available through
`pacman`; package names can change, but the required tools include the base
build toolchain, Rustup, QEMU x86_64, `libisoburn`/`xorriso`, `mtools`, OVMF,
and GRUB utilities.

From a NARF checkout:

```sh
cargo xtask host-test
cargo xtask run --arch=x86_64
cargo xtask boot-smoke --arch=x86_64
cargo xtask test --arch=x86_64
```

The first Rust command installs the repository-pinned toolchain through
Rustup when it is not already present. `/dev/kvm` is used automatically when
the current user can access it; otherwise QEMU falls back to slower software
emulation.

Exercise the same x86_64 UEFI/Limine image layout used for release media:

```sh
cargo xtask iso-boot --arch=x86_64
```

This is the most useful first compatibility report because failure leaves the
host boot configuration untouched. When reporting a problem, include the
QEMU command, serial log, CPU model, and the final test summary.

Before testing networking on hardware, run both end-to-end virtual paths:

```sh
cargo xtask net-smoke --arch=x86_64
cargo xtask e1000-module-net-smoke --arch=x86_64
```

Both require successful host-to-guest TCP and UDP exchanges plus a guest DNS
lookup. The second additionally proves that the e1000 driver was built,
ABI-stamped, loaded before PCI probing, and used as the exclusive owner of the
emulated NIC.

## Standalone ISO or USB test

Build the release image:

```sh
cargo xtask image --arch=x86_64
sha256sum target/narf-x86_64.iso
```

The ISO boots through Limine's removable-media UEFI path and requires Secure
Boot to be disabled. It is independent of the boot manager installed by
CachyOS.

For a dedicated USB device, first identify the exact target:

```sh
lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINTS
```

Then write it with the guarded xtask command:

```sh
sudo cargo xtask disk-write --device=/dev/sdX
sync
sudo eject /dev/sdX
```

`disk-write` is destructive to the selected device and refuses a target that
is not USB-attached. Replace `/dev/sdX` only after checking its model and size.
Do not select the CachyOS system disk.

On first real-hardware attempts, capture the serial console if the platform
exposes one and record the exact CPU, motherboard/laptop, storage controller,
GPU, network adapter, and boot result. Stage 5 silicon validation remains in
progress, so a successful QEMU boot does not imply every physical driver is
ready.

### Disposable partitioned ext4 USB

After the live ISO boots, the next storage test is a dedicated partitioned
USB. This exercises GPT discovery, a FAT32 ESP, root-device selection, and an
ext4 root without touching the CachyOS disk:

```sh
cargo xtask image --arch=x86_64
cargo xtask disk-write-partitioned \
  --device=/dev/sdX \
  --root-fs=ext4 \
  --root-label=NARF_ROOT
```

The second command displays the target and asks for confirmation before using
`sudo` to repartition it. It destroys every existing partition and byte of
data on the selected USB device. Check its transport, model, and size with
`lsblk` immediately before answering the prompt.

This creates a NARF development root containing the in-tree init and shell; it
does not copy or convert the installed CachyOS system. ext4 is the default
because it is the most exercised persistent-root path. Use this only after the
non-partitioned ISO has established that the machine reaches NARF at all.

## RX 6750 XT bring-up boot

Recipe for the Navi22 (RX 6750 XT, `03:00.0`) bring-up on the Gigabyte B650I
AORUS ULTRA (BIOS F41). The console lives on the Raphael iGPU (`12:00.0`); the
6750 XT is a secondary GPU whose cold boot cannot take the screen away. The
stick saves the NARF kernel log to itself, so a failed boot can be read back
under CachyOS. The stick boots with `narf.disks=boot-only`, which keeps the
internal disks read-only; see
[Internal-disk safety](#internal-disk-safety-narfdisksboot-only) for exactly
what that guarantees.

**Build** (no device access; the importer copies only the Navi22 blobs):

```sh
cargo xtask import-firmware --source /usr/lib/firmware \
  --vendor amdgpu/navy_flounder --skip-existing
cargo xtask usb-image --initramfs-firmware "amdgpu/navy_flounder*"
```

This writes `target/narf-x86_64-usb.img`: an MBR disk with one FAT32 ESP
(label `NARFBOOT`) holding Limine, the kernel, an initramfs with the
`navy_flounder` firmware (the Navi22 initcall runs before any root mount) and
`/NARFLOG.ID`. The kernel command line gets `narf.disks=boot-only
narf.bootlog=<random token> log_buf_len=8M` and no `quiet`. Add arguments with `--cmdline <arg>`
(repeatable); build without the log with `--no-bootlog`. Adding `--qemu` also
boots a copy of the image under OVMF as QEMU USB storage and prints the logs
it wrote; those boots also attach decoy internal disks (an NVMe with a GPT
ESP, an ext4 marked `needs_recovery` and a btrfs, plus a whole-disk ext4 on
SATA) and fail unless their SHA-256 is unchanged afterwards.

**BIOS settings:**

- *Settings → IO Ports → Initial Display Output*: **IGD Video**, so the UEFI
  GOP, Limine and the NARF console are on the motherboard HDMI.
- *Settings → IO Ports → Integrated Graphics*: **Enabled** (Auto can disable
  the iGPU while a discrete card is installed).
- *Boot → CSM Support*: **Disabled** (the stick is UEFI-only).
- *Boot → Secure Boot*: **disabled** for this test, because the stick is
  unsigned (see [UEFI Secure Boot](SECURE_BOOT.md)). This host currently
  reports it disabled: `od -An -t u1
  /sys/firmware/efi/efivars/SecureBoot-*` ends in `0`.
- Choose the stick once from the boot menu (F12) instead of changing the boot
  order, so CachyOS stays the default.

**Cabling:** connect the monitor to the **motherboard HDMI**. A second cable
from the monitor to the 6750 XT's HDMI is optional and matters only once
native modeset lands. Attach a USB keyboard for the NARF shell.

If Limine reports `Could not find viable load address for executable` before
NARF starts, check the ELF's full `PT_LOAD` memory spans with `readelf -lW`.
This board reserves physical `[0x099ff000, 0x0a000000)`. The production image
outgrew its former 32 MiB load placement and its final segment, including
`.bss`, overlapped that reservation. The x86_64 linker now starts the image
at 256 MiB. Rebuild old kernels when testing this board; changing a menu's
file path alone does not change an executable's load addresses.

For a KDE boot, a successful PCI probe and the presence of `/dev/dri/card0`
do not establish acceleration readiness. Check the later
`amdgpu: navi22 preflight refused:` line before diagnosing KWin or Qt plugin
errors. This MSI RX 6750 XT's VBIOS `113-MSITV398MH.310` supplies a version-6
PowerPlay payload; the generic Navy Flounder firmware SKU supplies version 1.
Both use the same 2470-byte table and 1668-byte SMC layout. NARF accepts both
versions while retaining board-source selection and power/thermal checks.
Native graphics initialization and the graphical login still require a
successful hardware boot; a VM smoke does not exercise those paths.

On this board, discovery reports two distinct engines as `SDMA0:0` and
`SDMA1:0`. Queue preparation normalizes the hardware ID and its local instance
before checking for duplicate engines. The connector GPIO LUT also identifies
DDC pairs through DATA bit 8; that selects the same AUX/I2C channel as CLOCK
bit 0. Rejecting either valid encoding previously stopped queue preparation
with `Queues(Unsupported)` and display routing with `Inventory(Unsupported)`.

The subsequent hardware boot completed nine of the 31 cold-boot checkpoints,
then stopped at `Graphics`: PSP returned DMCUB type 51 entry `0x82fee00100`,
outside the newly allocated TMR `[0x8002300000, 0x8002d00000)`. Linux preserves
PSP's separate secure CW0/CW1 windows. NARF now carries their pre-allocation
inventory through boot and recovery: DMCUB may use the exact reserved CW0,
and startup validates each complete secure window against its corresponding
reservation or TMR without changing those registers. VCN still requires TMR.
This correction requires another native hardware test before claiming progress
beyond `Graphics` or a working graphical login.

After synchronizing the kernel selected by the host's Limine entry, the
2026-10-22 boot passed `Graphics`, `RlcBoot`, GFX/SDMA queues and IB tests:
26 of 28 reported checkpoints completed. `DmubStart` degraded with `Invalid`,
then `Media(DeviceGone)` stopped startup and quarantined the framebuffer.
The DMCUB and VCN payloads in that boot's firmware initramfs match the host
Linux Navy Flounder files byte for byte. The next corrections retain the
PSP-reported executable extent, reserve complete freshly programmed secure
windows, and power VCN tiles before reading their gated status register.
Their register-model tests do not establish a working hardware display.

In the same boot, root mounting took 4314 ms and GPU startup took 52899 ms.
At uptime 54 s the capture still showed journal flush, Plymouth's writable-root
notification and userdb credential loading running, with `sysinit.target`,
`basic.target` and PlasmaLogin waiting. That snapshot does not establish
Btrfs as the cause of the later userspace wait; no graphical-login success
has been recorded.

The next capture (`plasma-8aeb8863-b279-479e-b112-feca3ff5cc50`) confirms
that the new diagnostic kernel ran but still stopped at 26/28 checkpoints.
DMCUB CW0 read as entirely zero. VCN's first all-ones read was at BAR5 byte
offset `0x1fd58`: discovery base `0x7e00` plus `UVD_VCPU_CNTL` dword `0x156`,
not UVD_STATUS. Linux uses a masked read/modify/write for this control word
without rejecting that value. NARF now preserves the unselected bits and
checks independent GC/NBIO presence before accepting an all-ones VCPU control
read; status and wait registers still reject all ones. Regression cases cover
both control updates on a live GPU and disappearance before the write.
This correction still requires hardware validation. The DMCUB zero-window
failure remains unresolved; its diagnostic now includes the PSP image extent
and inherited secure reservations, without changing secure window registers.

That capture also shows journal flush completing around uptime 62.7 s,
system tmpfiles completing around 69.5 s, and the journal catalog completing
around 75 s. The linker-cache rebuild was still running at the end of the
readable kernel capture; it contains no PlasmaLogin start. The earlier
journal/userdb/Plymouth snapshot therefore does not establish a permanent
sysinit deadlock.

The working-Linux comparison after that boot found DMCUB enabled, out of reset,
and ready (`DMCUB_SCRATCH0 = 3`) while all eight CW0/CW1 registers also read
zero. `UVD_VCPU_CNTL` and the gated GC `GB_ADDR_CONFIG` both read all ones.
NARF therefore cannot use either observation alone as evidence of failure.
The corrected DMUB path accepts wholly zero secure readback only with this
PSP session's authenticated full image, matching upload size and retained
memory ownership, then still requires a fresh ready publication and mailbox
proof. Readable and partially readable windows retain their bounds checks.
VCN presence uses NBIO's memory-size and aperture registers instead of GC.
The captured root was `btrfs / ... rw`, and diagnostic files were persisted;
the service snapshot still had PlasmaLogin waiting. These corrections have
not yet established a working hardware graphical login.

The next capture (`plasma-cbd60c86-9b79-479e-a512-fe4a80eb0ea2`)
completed `DmubStart`, including firmware version and feature-capability
mailbox replies. Startup reached 30/31 checkpoints, exposed the framebuffer,
and read a 256-byte HDMI EDID with a preferred 3840x2160 mode. VCN degraded
with `BootFailed(0)` but no longer quarantined display startup. Native HDMI
then failed at `Clocks` with `Block(Rejected(255))`; a working native mode
and graphical login are still unverified.

The DAL clock preparation now follows Linux's `dcn3_update_clocks`: it omits
the separate SOC/FCLK floors and unused DF C-state command, retains strict
DCF/UCLK/PIX/DISP floor validation, and tolerates firmware rejection of the
optional display-count and deep-sleep hints. Transport failures still abort.
Each rejected command logs its message, argument and response so another
clock failure identifies the exact request rather than only `Rejected(255)`.
The captured error predates that diagnostic and does not identify which
of the old requests was refused. Register-model tests cover the corrected
request sequence and refused optional notifications; they do not establish
native hardware modesetting success.

The subsequent clock-request audit covers the Navi22 DAL and GFX PPSMC
mailboxes plus the native display's PLL, DPP/DP and audio DTO paths against
Linux `ecd997b0189a`. It does not cover other GPU families. The checks include
message/register IDs, clock IDs, units and packing, request ordering, board
bounds, response handling and cancellation ownership:

| Request or path | Linux comparison and result |
| --- | --- |
| DAL startup `0x2/0x3/0x4/0xb` | `dcn3_init_clocks`: versions and scalar MHz levels; header/interface and level-query refusals are tolerated; usable ranges remain required for admission. NARF does not query unused DTBCLK. |
| DAL display floors `0x9`, hints `0xd/0xe` | `dcn3_update_clocks`: DCF/UCLK/PIX/DISP, ceil(kHz/1000), clock ID shifted by 16. Required floors remain strict; notifications tolerate refusal. Joint setup now reports all admitted streams instead of always one. |
| DP PHYCLK floor | `dcn30_notify_link_rate_change`: link code × 27000 kHz, no lower than the board minimum, covering all links. NARF conservatively retains the highest successful link request until GPU restart. Requests above the board maximum now fail before writing. |
| Runtime clock operations | PHY and optional memory floors, watermark messages and audio PME now retain in-flight ownership across cancellation, including when firmware replies after the future is dropped. |
| GFX PPSMC range/control | `smu_v11_0`: GFXCLK ID 0, UCLK ID 2; min/max queries in MHz; SoftMax then SoftMin, `0xffff/0` for automatic mode. Separate GFX and DAL mailbox registers/message spaces match Linux. |
| Display DPM and power saving | `sienna_cichlid` feature IDs and board masks match; required protections stay enabled. Current display admission refuses FCLK switching, deep sleep and hub power gating. Their optional paths are not evidence of hardware readiness. |
| HDMI PHY PLL | `dcn3_program_pix_clk` → `dce112_program_pix_clk` → `set_pixel_clock_v7`: target in 100 Hz, combo PLL/CRTC/encoder IDs, XTALIN 0 and deep-colour ratio 0 match. DCN's resource builder leaves `SUPPORT_YCBCR420` unset; the generic helper's YUV420 flag is therefore not added. |
| DENTIST and DPP DTO | `dcn20_update_clocks_update_dentist` / `dccg2_update_dpp_dto`: divider IDs, completion bits, bounded waits, phase = ceil(255 × requested/reference), modulo 255. NARF retires consumers before changing dividers. |
| DP pixel DTO | `dcn3_program_pix_clk`: 730 MHz DPREFCLK, optimized-rate entries, otherwise pixel Hz/reference Hz; no VBIOS PLL request for DP. |
| HDMI/DP audio DTO | `dce110_populate_audio_dto_parameters` / `dce_aud_wall_dto_setup`: HDMI's lowest active OTG drives DTO0; DP uses DPREFCLK/DTO1. HDMI audio now uses the 4:2:0-halved requested clock without deep-colour PLL scaling. |
| PMFW watermarks and audio wake | DAL `0x5/0x6/0x8` carries the retained watermark address/table 1; `0x11` is optional audio PME. Watermark failure refuses dependent power-saving admission; it does not prove a display-clock failure. |

`bash drivers/gpu/tests/navi22_clock/check.sh ~/git/linux` checks the wire
constants and register fields against Linux's headers; the harness is also
included by the revision-pinned `cargo xtask gpu-reference` gate. The kernel
regressions cover every required display-floor rejection, frequencies outside
board bounds before writes, stream counts, interrupted runtime operations and
HDMI audio clock selection. Hardware acceptance of these requests, native
modesetting and the KDE login remain unverified by this source audit.

The discrete GPU handoff also establishes the x86_64 TSC duration scale before
firmware startup. Its Late initcall precedes the normal HPET/timer-IRQ setup;
using the identity scale there shortens hardware waits and inflates reported
milliseconds on a >1 GHz TSC. A missing calibration source now refuses the
handoff with `Clock` before GPU writes. For older captures, retain the raw
`cyc` total and the later calibrated Hz when interpreting elapsed time: the
79,755,617,363-cycle RX 6750 XT capture at 4.7 GHz represents about 17 seconds,
although its pre-calibration warning says 79,755 ms. That capture continued
into systemd but does not establish a working physical display or KDE login.

The modeset-to-power-saving audit checks the RX 6750 XT's live Linux discovery
bases against the HDP, MMHUB, ATHUB, OSSSYS, SMUIO and GC addressing, and the
register fields against Linux's headers. Its sequence follows Linux's IP order
(common, GMC, IH, GFX, SDMA), with RLC safe mode around GC gating. The native
modeset's one-frame settling delay and two-frame underflow watch also require
the calibrated scale; the old waits ended within a fraction of one frame on
this host. An immediate SCDC read is diagnostic, not proof of a physical image.

A gating failure can leave earlier IP writes applied; the owner then refuses
further gating transitions. It returns before the subsequent GFXOFF/deep-sleep
feature enables and memory/fabric floor reductions. The new all-ones diagnostic
includes the BAR5 address and preceding register-write count, distinguishing
failure before any gating writes from a partial transition. The older
`Gating(DeviceGone)` capture lacks that information, so its exact failure and
the physical black screen remain unresolved by this source audit.

The October 23 `plasma-25ea18c1-b779-479e-b312-fe4af7f58481` capture confirms
early 4.7 GHz calibration and a reported native HDMI mode. It gets past the
journal/Plymouth read-write jobs and attempts `kwin_wayland` at 172 seconds.
The gating failure is `RLC_CGTT_MGCG_OVERRIDE`, BAR5 byte offset `0x3b120`,
after ten writes; that register address matches the Linux GC 10.3 header.
These observations do not establish a visible image or successful greeter.

For that boot, the useful additional artifact was `/var/lib/plasmalogin/core`;
there were no greeter text logs under its home. Its executable mappings match
`/usr/lib/plasma-login-greeter`. The 46,096-byte file ends after 822 of 853
program headers, before its notes, so it contains no saved fault registers or
process-identity note. The core writer now places notes immediately after the
ELF header, batches metadata into one sequential write, and emits a
`coredump: fatal ...` kernel record before file I/O. This improves the next
capture; it does not fix or identify the underlying greeter fault. Preserve
the core's timestamp and collect the new record before planning another fix.

The next capture, `plasma-3d4989b5-b779-479e-b312-fe4a7b24ccbb`, fails earlier:
the journal records eight `SIGBUS` page faults in `timeout` and
`systemd-executor`. Their instruction bytes match the installed dynamic
loader at offset `0x1d778`, reading the first bytes of `/etc/ld.so.cache`.
The mapping is readable/private, starts at `0x409000002000`, and covers
`0x2e000` bytes; the loader's file-size operand is 187,287 bytes. `/core`
now retains its notes and identifies another `systemd-executor` instance
at that same loader offset. D-Bus startup times out; no Plasma start was
saved for this boot. This is a file-backed demand-page refusal, not an
unsupported instruction. The capture does not retain the backing filesystem
error or inode, so its precise cause must not be inferred from SIGBUS alone.

Two local checks expose relevant replacement defects. First, the VFS dentry
table has 2,048 buckets but the old mutation guard records only 64 bits:
high-bucket shifts panic in checked builds and miss the correct active-writer
counter/generation in release builds. A lookup started before replacement
can therefore publish a stale inode afterwards. Mutation tracking must span
the full table. Second, the Btrfs retained-handle experiment reads a fresh
replacement successfully but gets `NotFound` reading the replaced file
through an existing handle, both before and after `syncfs`. At audit time,
last-link replacement reclaimed the old inode immediately. Linux retains an
unlinked inode and its data until its final open/mapping reference is gone.
Correcting the dentry mask does not implement that missing Btrfs lifetime.
The subsequent upstream Btrfs cache-generation change invalidates retained
generic shared-cache pages; it does not preserve an unlinked inode. The
failing loader mapping is private and enters the private demand-read branch,
so that upstream change alone does not establish a fix for this refusal.

The production Limine VM smoke validates built-in login/shell startup. It
does not boot this installed KDE root or race `ldconfig` against process
startup. The recent full CachyOS fixture attempts instead stop at a PID 1
invalid-opcode fault because its loader uses AVX-512 absent from the TCG CPU.
Neither result establishes working cache replacement. A representative gate
must cover open/map/close, replacement before first touch, old and new
contents through their respective handles, concurrent lookup publication,
and a real dynamic executable after cache rebuild on writable Btrfs.
The root smoke's `ldconfig | head | sed` command is a diagnostic report:
it does not assert `ldconfig`'s exit status or concurrent loader correctness.

The Btrfs file-loading fix retains shared inode metadata and a lifetime anchor
for every node, including nodes held only by mappings. A separate open sees
size changes immediately; async stat refreshes attributes from the tree.
Replacement and unlink persist `nlink=0` with an `ORPHAN_ITEM`, leaving old
handles and unfaulted mapping pages attached to their original data. Explicit
sync, later operations and the commit timer reclaim an orphan after its final
reference; a writable mount recovers persisted orphan items after a crash.
Drop flushes accepted changes without starting an additional cleanup transaction.

The regression tests cover old/new contents, writes through an unlinked open
file, cross-open size changes, ordinary loader-style symlinks, and crash
recovery on the CachyOS-shaped Btrfs fixture. The syscall-level QEMU case uses
a small writable Btrfs fixture and exercises private mmap, fd close,
replacement, first touch, new-file mapping and final-unmap reclamation. These
checks address the file-loading defects; physical HDMI output and a completed
KDE session still require native verification.

**Write the stick.** Identify it first. It must show `TRAN usb`:

```sh
lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINTS
cargo xtask disk-write --iso target/narf-x86_64-usb.img \
  --device /dev/sdX --fast-wipe
```

`disk-write` refuses non-USB targets, asks for confirmation, and verifies the
written bytes after a replug. On this host the internal disks are the two
NVMe drives (the Sabrent data disk at `04:00.0` and the WD SN770 CachyOS disk
at `07:00.0`; Linux names them `nvme0n1` / `nvme1n1` in either order, varying
per boot) and the SATA disk `sda`. None of them is ever a valid `--device`.

**What to expect on screen.** While the card boots, every Navi22 stage prints
`start`, then `complete` or `failed <error>`. The cold boot ends with
`amdgpu: navi22 stage summary (N/M ok):` followed by one line per
stage, then the connector (EDID/HPD), media and thermal notes. If the screen stops changing, photograph it; the last `start` line
names the stage that hung. Shortly after the shell appears, the console shows
`bootlog: saving the kernel log to usb-msc0p1:/narf-boot-<n>.log`. To finish,
log in (`root` / `narf`) and type `reboot` (or `poweroff`) in the NARF
shell, which flushes the log one last time.
Otherwise wait at least five seconds after the last line before powering off.

**Retrieve the log** after booting back into CachyOS:

```sh
lsblk -o NAME,SIZE,TRAN,LABEL      # the NARFBOOT partition, e.g. sdX1
udisksctl mount -b /dev/sdX1
cp /run/media/$USER/NARFBOOT/narf-boot-*.log .
udisksctl unmount -b /dev/sdX1
```

Each boot creates the next `narf-boot-<n>.log`, up to 32 files of at most
4 MiB each; delete old ones to continue. Each line is prefixed with seconds
since boot, as in `dmesg`. The kernel writes only to a USB FAT volume whose
`/NARFLOG.ID` matches the token on its command line. To keep the stick
read-only for one boot, press `e` in the Limine menu and change the argument
to `narf.bootlog=off`.

An unexpected power-off during bring-up is most likely the Navi22 thermal
protection (SMU CTF or software-shutdown temperature), which calls the ACPI S5
power-off on purpose. That path runs the same final flush as `reboot`, so the
log should end with the `amdgpu: navi22 thermal ...` or `EMERGENCY` line that
caused it, followed by `[bootlog: final flush before reboot/power-off]`.

Limits: the stick becomes writable only once the USB stack runs, which is
after the last boot initcall, including the 6750 XT cold boot. Lines logged
before then are saved retroactively, but a hang *before* that point leaves
only the screen. A kernel panic is appended in a final flush bounded at 3 s.
A fatal CPU exception is not saved.

### Internal-disk safety (`narf.disks=boot-only`)

`cargo xtask usb-image` puts `narf.disks=boot-only` on the command line
(`--allow-all-disks` leaves it off; never use that on this machine). With it:

- **Every block device is read-only until it is identified as the stick.**
  The block registry wraps each disk and partition (NVMe, SATA, USB, SD) in a
  guard that passes reads and refuses writes with an error. The first refusal
  per device is logged as `disks: refused write to <dev> ...`. The console
  states the policy at boot:
  `disks: narf.disks=boot-only: every disk is read-only until identified as
  the boot medium`.
- **Only the stick becomes writable.** A USB mass-storage FAT volume whose
  `/NARFLOG.ID` matches the `narf.bootlog=` token is identified
  (`disks: usb-msc0p1: identified as the boot medium`). From then on, that
  stick's partitions are writable, and nothing else is. A device that later
  appears under the same name starts read-only again. With
  `narf.bootlog=off`, or a `--no-bootlog` image, nothing is ever identified,
  so every disk stays read-only, the stick included.
- **No automatic mount of anything else.** These boot steps skip every
  unidentified disk and log the skip:
  - `root-mount-auto`, including an explicit `root=`, which is refused with
    `BootOnly` (`/` comes from the initramfs);
  - `efi-system-partition-mount`, which therefore never mounts the CachyOS ESP
    at `/boot`;
  - `mnt-mount-ext2`, which never mounts an internal ext4 (such as the
    Sabrent `nvme0n1p2`) at `/mnt`.

  The btrfs member discovery skips unidentified disks too. The btrfs disk
  smokes additionally need `narf.btrfs_smoke`, which only xtask's own test
  run passes.
- **Read-only mounts do not write.** An ext2/3/4 or btrfs volume on a
  read-only device is mounted read-only without a single write:
  - **ext:** the stale `needs_recovery` superblock repair is skipped. A dirty
    journal is replayed into memory only.
  - **btrfs:** a pending fsync log tree refuses the mount instead of being
    replayed. No commit timer starts.
  - **FAT:** a mount never writes (there is no dirty-bit or FSInfo update at
    mount). Writes happen only through file operations, which the guard
    refuses.
- **The NVMe passthrough is closed.** On every controller node `/dev/nvme<C>`,
  admin and I/O passthrough ioctls (Format, Sanitize, firmware commit, raw
  writes) and writes are refused unless every namespace of that controller is
  the stick. Only the namespace-id query is answered.

Limits. Exactly what this does and does not cover:

- **Scope.** The guarantee covers what NARF does after the kernel starts.
  - The UEFI firmware and Limine run first, and they are outside it. Limine
    only reads.
  - Under QEMU, OVMF without a writable variable store writes `\NvVars` to
    the first ESP it finds. `--qemu` gives it one, so the check measures
    NARF alone.
- **Which writes are guarded.** The guard sees every write that goes through
  the block registry: all filesystems, the `/dev/<disk>` block nodes, the
  boot log and the partition/LUKS layers. A driver writing through a private
  controller handle would bypass it. An audit of the in-tree storage drivers
  found no such write on a non-test boot.
  - NVMe, AHCI, virtio-blk and USB MSC probes only read: IDENTIFY and the
    partition table. Controller setup (queue creation, feature negotiation,
    HBA and link resets) does not change media.
  - Format/Sanitize/firmware/security commands have no in-kernel caller.
  - Test-only writes exist only in `kernel-test` builds, which usb-image does
    not use.
- **Command-line errors.** A misspelled `narf.disks=` value fails closed to
  `boot-only`. Removing the argument (Limine `e` editor) removes the
  guarantee.
- **Reads stay allowed.** The internal disks can still be enumerated,
  partition-scanned and read, including from the root shell.
- **Explicit `ro` on the stick.** A userspace `mount -o ro` of the
  identified stick sets only the VFS read-only flag. ext's mount-time
  superblock repair would still run there. On every other disk the device
  itself is read-only, so this does not arise.
- **Current hardware coverage on this host.**
  - NVMe: NARF drives every NVMe controller, numbered in PCI order: on this
    host `nvme0` is `04:00.0` (Sabrent data disk) and `nvme1` is `07:00.0`
    (WD SN770, the CachyOS disk). Every active namespace is registered as
    `nvme<C>n<N>` and partition-scanned, so `nvme0n1p1`, `nvme0n1p2` (ext4
    data), `nvme1n1p1` (the ESP) and `nvme1n1p2` (btrfs root) are all
    registered, read-only.
  - **Names are not identity.** A controller that fails to probe, a moved
    drive or a firmware that enumerates differently shifts every later name.
    Identify disks by filesystem UUID or PARTUUID (`/dev/disk/by-uuid`,
    `/dev/disk/by-partuuid`) or by hardware identity (`/dev/disk/by-id/
    nvme-<model>_<serial>`, `nvme-<wwid>`, `/dev/disk/by-path/
    pci-0000:07:00.0-nvme-1`); the boot log prints each namespace's PCI
    address, model, serial and WWID (`nvme: nvme1 (0000:07:00.0, ...)`).
  - SATA: the AHCI driver binds any AHCI-class controller (`01:06:01`), as
    Linux does, so the AMD 600-series controller (`1022:43f6`) and `sda`
    are driven as `sata0`, with any partitions as `sata0p<n>`, all
    read-only. The AMD controller has not been tested: QEMU emulates only
    Intel ICH9.
  - Probing these disks only reads. Controller setup (NVMe queue creation,
    the AHCI HBA reset and SATA link reset) does not change media.
  - On reboot and power-off NARF sends every NVMe controller a Flush (when
    it has a volatile write cache) and then the CC.SHN normal-shutdown
    notification, as Linux does (`nvme: nvme<C>: flushed ... CC.SHN normal
    shutdown: Complete`). Neither carries data or changes media contents.
- **Testing.** This is validated in QEMU (block-layer model tests, a
  two-controller NVMe model and a two-controller QEMU run, ext and btrfs
  read-only mount tests, and the `usb-image --qemu` decoy hashes with two
  NVMe decoys and a SATA decoy). It has
  not been validated on hardware.

### Booting the installed root (`narf.disks=root-ro` / `root-rw`)

Two more policies boot the host's own CachyOS root (systemd as PID 1)
instead of NARF's userspace. Both name the root only by filesystem UUID, never
by a device name:

```sh
# Read-only root, writable tmpfs overlay (nothing on any disk is written):
cargo xtask grub-image --arch=x86_64 \
  --initramfs-firmware "amdgpu/navy_flounder*" \
  --root-policy root-ro --root-uuid 653602c3-cd42-420e-95ef-4c4033d17b56 \
  --rootflags subvol=/@ --bootlog-token <token> \
  --cmdline-extra "systemd.unit=multi-user.target fsck.mode=skip"
# Real read-write to the btrfs root ONLY: the same, with --root-policy root-rw.
```

Each command emits `narf.disks=<mode> root=UUID=<uuid> rootflags=subvol=/@
systemd_pid1 systemd.zram=0` (`--rootflags` changes the subvolume;
`systemd.zram=0` keeps zram-generator from creating swap units for a zram
device NARF does not have), then
`narf.bootlog=<token>` and the `--cmdline-extra` arguments. Without
`--root-policy`, grub-image still writes `boot-only`.

- `--root-policy` builds the systemd PID 1 kernel by itself: it adds the
  features `boot-init` (honours `systemd_pid1`), `cgroup-all` (a real
  cgroup2 `/sys/fs/cgroup`, which systemd requires), `container` (namespaces
  for unit sandboxing) and `firmware-allow-unsigned`, the same set
  `systemd-pid1`, `cachyos-root-smoke` and `cachyos-gate` use. A bundle built
  without them boots NARF's own userspace and ignores `systemd_pid1`. Passing
  them explicitly with `--features boot-init,cgroup-all,container,firmware-allow-unsigned`
  is equivalent.
- `--initramfs-firmware "amdgpu/navy_flounder*"` puts the RX 6700 XT's
  firmware in the initramfs, so the display comes up before the root mounts.
- `--bootlog-token <token>` adds `narf.bootlog=<token>` (8-64 characters of
  `[A-Za-z0-9_-]`) for the persistent boot log described below.
- `--cmdline-extra` (repeatable) appends arguments. For the first trials use
  `systemd.unit=multi-user.target` (the host defaults to `graphical.target`)
  and `fsck.mode=skip`. Arguments that grub-image has its own option for
  (`narf.disks=`, `root=`, `rootflags=`, `narf.bootlog=`) are refused there.

- **Nothing is writable until the root is designated.** Root mounting
  matches `root=UUID=` and calls `designate_root` before the filesystem is
  built. The designation re-reads the UUID from the partition's own
  superblock and requires exactly one `root=` on the command line. It is
  refused for a UUID carried by two devices (a cloned disk, a multi-device
  btrfs), a whole disk, an ESP or vfat partition and, under `root-rw`,
  anything that is not btrfs. It can happen once per boot. If the root device
  is removed or re-registered, or a second device with its UUID appears, the
  designation is revoked and every disk stays read-only for the rest of the
  boot.
- **Banners.** At policy resolution:
  `disks: POLICY narf.disks=root-rw: ONLY the partition whose filesystem UUID
  matches root=UUID=... will be WRITABLE; every other disk and partition (its
  ESP included) is read-only`. At designation:
  `disks: WRITABLE: <dev> (btrfs UUID ...) is the ONLY writable device`.
  Under `root-ro` the second banner says `designated READ-ONLY ... NOTHING is
  writable`.
- **`root-rw` writes exactly one partition.** Only the designated root
  partition's block-layer guard passes writes. Every other disk and
  partition is refused: the SN770's whole-disk device and its ESP
  (`6D89-28C5`, which may be mounted read-only), the Sabrent, `sda`, and the
  `/dev/nvme<C>` passthrough nodes. vfat filesystems also report themselves
  read-only to the VFS under both root policies, so they mount `ro`.
- **The boot-log stick is the one exception, under both policies.** With
  `narf.bootlog=<token>`, the USB mass-storage FAT partition whose
  `/NARFLOG.ID` first line is the token becomes writable, and nothing else on
  that stick or any other disk does. A stick on the root's own disk is never
  accepted. The console then prints `disks: WRITABLE (log stick):
  usb-msc0p1 ...`. A failed root-ro/root-rw boot still leaves its log. Under
  the root policies the log probes the stick only after root mounting has
  finished, so the stick's I/O never delays the root. Lines from before then
  are saved retroactively.
- **The boot stops visibly, never degrades.** A failed `root=` mount under
  either root policy prints `root-mount: narf.disks=... ROOT MOUNT FAILED:
  <reason>; NOT falling back` plus the btrfs refusal line. It does not fall
  back to the initramfs or another disk.
- **btrfs write-safety gate.** This mirrors Linux `open_ctree` /
  `btrfs_check_features`. Before anything can write (log replay included),
  a read-write btrfs mount is refused and logged as
  `btrfs <uuid>: REFUSING read-write mount: <reason>` when any of these hold:
  - an incompat or compat_ro bit outside what the writer maintains;
  - a free-space tree without its valid bit (or BGT without FST);
  - no free-space tree on non-mixed block groups;
  - `BTRFS_SUPER_FLAG_ERROR` or any superblock flag besides `WRITTEN`
    (seeding, metadump, fsid or csum change in progress);
  - generation 0;
  - a balance item, reloc roots, or a started or suspended device replace.

  Under `root-rw` the gate also requires one device, crc32c, 4 KiB sectors,
  a power-of-two nodesize of 4–64 KiB, a valid free-space tree and an empty
  log tree (`log_root == 0`; mount once on Linux to replay a dirty log). Its
  incompat set is limited to `MIXED_BACKREF DEFAULT_SUBVOL COMPRESS_LZO
  COMPRESS_ZSTD BIG_METADATA EXTENDED_IREF SKINNY_METADATA NO_HOLES` and its
  compat_ro set to `FREE_SPACE_TREE FREE_SPACE_TREE_VALID BLOCK_GROUP_TREE`.
- **One writer per filesystem.** Every btrfs mount of an fsid is a view of
  one shared core: one transaction, one allocator, one superblock commit. So
  under `root-rw` all seven fstab subvolumes (`/`, `/home`, `/root`, `/srv`,
  `/var/cache`, `/var/tmp`, `/var/log`) are writable together. The gate
  runs once per core. A read-write mount of a refused core fails with `EROFS`,
  which `mount(8)` retries read-only. Every other fsid and device stays
  read-only at the block layer.
- **Status on this host.** The CachyOS root has compat_ro `0xb`
  (`FREE_SPACE_TREE FREE_SPACE_TREE_VALID BLOCK_GROUP_TREE`) and incompat
  `0x371`, and the writer maintains all of it, block-group tree included, so
  `root-rw` writes it. The gate refuses only if the superblock read at boot
  shows a pending log tree (an unclean Linux shutdown), an error flag, or a
  running balance or replace. Compare with the real superblock using `sudo
  btrfs inspect-internal dump-super
  /dev/disk/by-uuid/653602c3-cd42-420e-95ef-4c4033d17b56`.
- **What the writer does to a CachyOS volume.**
  - New data is written uncompressed, which is valid under
    `compress=zstd:1`.
  - Touched zstd/LZO extents are rewritten uncompressed.
  - `chattr +C` journals (`NODATASUM`) get no checksums.
  - Freed extents' checksums are removed from Linux's merged csum items.
  - Data goes to DATA block groups and tree blocks to METADATA ones.
  - The free-space tree is maintained.
  - The v1 space cache is invalidated by the generation bump.
  - `discard=async` is accepted and ignored (NARF never discards).
  - Options that would change unmaintained state (`clear_cache`,
    `space_cache=v1`, `nodatasum`, `rescue=`, `degraded`, `device=`) are
    refused.
- **Interop test.** `cargo xtask btrfs-rootrw-interop` builds a CachyOS-shaped
  image unprivileged and boots it under `root-rw`. The image has GPT, an ESP,
  btrfs with nodesize 16K, crc32c, FST, no-holes, `--compress zstd:1`, the
  seven `@` subvolumes and `+C` journals. It is built twice, with the host's
  exact flags (block-group tree) and without them. Each image gets four
  boots:
  - `@`: pacman db add and remove, `/etc/hostname` replace, a zstd-file
    overwrite, an unlink;
  - `@home`;
  - `@log`: journal append, rotate and vacuum;
  - `fstab`: all six other subvolumes mounted rw through the shared core and
    written.

  After each boot the test requires host `btrfs check --readonly
  --check-data-csum` to be clean and the GPT and ESP to be byte-identical. At
  the end, `btrfs restore` content must match in all seven subvolumes.
  `--bgt=refused` checks the opposite case (a writer without BGT support).
  `cargo xtask btrfs-crash-smoke [--bgt]` checks fsync durability across a
  SIGKILL. A host `mount -o loop,ro` runs only with passwordless sudo.
- **Before a real `root-rw` boot**, take a read-only snapshot on CachyOS
  (`sudo btrfs subvolume snapshot -r / /.snapshots/pre-narf`) and keep a
  backup of `/home`. Shut NARF down cleanly (`sync`, then power off). Back on
  CachyOS, run `sudo btrfs scrub start -B /` and check `dmesg` for btrfs
  errors.

## Storage encryption and LUKS

NARF has a real encrypted-block implementation, but that does not yet make an
ordinary encrypted CachyOS installation bootable through the native package.

| Capability | Current status |
| --- | --- |
| Open common LUKS1 volumes | Implemented for AES-XTS/`plain64` with bounded PBKDF2 profiles |
| Open common LUKS2 volumes | Implemented for one normal AES-XTS/`plain64` crypt segment with bounded PBKDF2 or Argon2i/Argon2id keyslots |
| Read and write the unlocked payload | Implemented; LUKS metadata itself is opened read-only |
| Supply a key from a measured NARF initramfs | Implemented with `rd.luks.key=/path` and optional `rd.luks.uuid=<uuid>` |
| Prompt interactively for a passphrase during boot | Not implemented |
| Format LUKS, edit keyslots, repair metadata, use integrity profiles, or resume reencryption | Not implemented |
| Unlock an installed CachyOS root from the current Arch package entry | Not integrated or accepted as a supported workflow |

The keyfile path names a file *inside the staged NARF initramfs*, not a path on
the still-locked root filesystem. The current Arch package boots built-in
userspace and does not build or attach a CachyOS-specific NARF initramfs, add
the required kernel arguments, or offer an unlock prompt. A typical encrypted
CachyOS root therefore remains unavailable even when its particular LUKS
header and cipher profile are understood by the block layer.

For now, leave an encrypted production installation unchanged. Test storage
with a disposable unencrypted ext4 image or disk, or build a dedicated NARF
initramfs containing a test keyfile. Never copy a production passphrase into a
development image, and do not remove encryption from the CachyOS installation
just to test NARF.

The exact accepted profiles and work limits are documented in the
[encrypted-block specification](../block/specification/encrypted.md).

## Filesystem status

CachyOS offers Btrfs, XFS, ext4, F2FS, and ZFS. Its default Btrfs layout uses
multiple subvolumes and Zstd compression. NARF's most supported and recommended
root filesystem for current installation experiments is **ext4**.

| Filesystem | NARF status | CachyOS testing guidance |
| --- | --- | --- |
| ext4 | Read/write; the default and most exercised NARF partitioned-install path | Recommended for a disposable NARF root. Unsupported features, a dirty journal, or damaged metadata can still force read-only operation or rejection. |
| ext2/ext3 | Supported by the shared ext-family driver, with feature-dependent write limits | Useful for fixtures and simple images; prefer ext4 for a new test root. |
| Btrfs | Broad read/write, compression, subvolume, snapshot, multi-device, and checksum support exists | Do not point NARF at the production CachyOS root yet. The CachyOS `@` layout, fstab, boot orchestration, and distro-PID1 path lack an end-to-end acceptance gate. |
| FAT12/16/32 | Read/write | Suitable for EFI/removable-media data, not a CachyOS root filesystem. |
| exFAT | Mount, directory walk, and reads work; full VFS mutation is incomplete | Treat as read-mostly removable media, not a root filesystem. |
| SquashFS, ISO 9660, UDF, MINIX | Read-only implementations, with format-specific limits | Suitable only for supported image or media use cases. |
| XFS, F2FS, ZFS | No NARF filesystem driver | Unsupported. CachyOS's Linux ZFS module cannot be loaded by NARF. |

Filesystem support is not permission to experiment on the only copy of a
volume. Use a clone or a disposable image until the exact NARF driver, mount
options, userspace, and shutdown path have passed an end-to-end test.

## Driver readiness

A driver being present in the source tree does not mean every device ID,
firmware revision, interrupt topology, and laptop wiring has passed on real
hardware. Start from the proven QEMU devices and treat physical hardware as a
bring-up target.

| Area | Best-tested path | Current physical-hardware caveat |
| --- | --- | --- |
| Storage | QEMU virtio-blk and NVMe | NVMe, AHCI, USB mass-storage, and other transports are in-tree, but machine-specific silicon coverage varies. Do not continue toward a root mount if the controller or disk did not bind cleanly. |
| Wired networking | QEMU e1000; its live acceptance test covers TCP, UDP, and DNS, including the loadable-module path | e1000/e1000e, igc, Realtek, ixgbe, mlx5, and other drivers have different maturity levels. Match the exact PCI ID; use QEMU e1000 or a known supported wired adapter when the onboard NIC is not ready. |
| Wi-Fi | Software and protocol tests; ath11k has a PCI/power-up smoke for QCNFA765/WCN6855 (`17cb:1103`) | iwlwifi's AX210+/Sc/BE211 path still needs silicon validation and real-supplicant acceptance. For QCNFA765, run the normal-boot ath11k scan pass below to qualify MHI, firmware, and the radio; do not depend on Wi-Fi for the first boot. |
| Graphics | QEMU Bochs and virtio-gpu framebuffer/DRM paths | Native AMDGPU work targets specific Phoenix/HawkPoint and Navi22 hardware but has not completed the silicon gate. CachyOS NVIDIA modules are Linux modules and cannot be reused. Use serial or the boot framebuffer first. |
| Input and USB | QEMU input plus xHCI USB HID paths | xHCI, USB keyboard/mouse, i8042, and I2C-HID foundations exist, but laptop touchpads and platform wiring still need machine-specific validation. Keep a USB keyboard and serial fallback. |
| Audio, power, suspend, and thermal | QEMU or software tests for individual pieces | Not first-boot acceptance criteria. Avoid suspend/resume during initial hardware testing. |

Devices that require firmware must use firmware staged and authorized for
NARF. Installed Linux modules, DKMS output, and a Linux driver's private
firmware-loading path are not interchangeable with a NARF module or driver.
Distribution maintainers can package an out-of-tree NARF driver as a built-in
or runtime module without editing this repository; see
[external kernel composition](extending/composition.md) and the
[runtime-module guide](extending/modules.md).

### Firmware for a hardware-specific test image

CachyOS normally stores device firmware under `/usr/lib/firmware` (with
`/lib/firmware` resolving to the same hierarchy). NARF's importer can copy a
single vendor subtree into the ignored `target/firmware` staging area,
decompress Arch-style `.zst` entries, and wrap each blob in the NARF firmware
format:

```sh
cargo xtask import-firmware \
  --source /usr/lib/firmware \
  --vendor iwlwifi \
  --skip-existing
cargo xtask image --arch=x86_64
```

With a partitioned root, firmware not selected for the initramfs is staged at
`/lib/firmware` on that root. Firmware needed before the root can mount must be
selected explicitly, for example with `--initramfs-firmware "vendor/*"` on
the `image` command. Import only the vendor required for the test; a complete
host firmware tree can make the image unnecessarily large.

The normal development image enables the explicit unsigned-firmware bring-up
policy and logs each unsigned handout. A distribution build must instead sign
the wrapped payloads and embed the authorized public keys as described in the
[firmware specification](../firmware/specification/spec.md). Never treat a
blob's presence in CachyOS as proof that the matching NARF driver is complete.

#### QCNFA765 / WCN6855 (`17cb:1103`) first radio pass

The Qualcomm QCNFA765 enumerates as a WCN6855 HW2.1 PCI function. Import only
the ath11k firmware, include its HW2.1 subtree in the initramfs, and request a
scan during a normal boot (not a `kernel-test` boot):

```sh
cargo xtask import-firmware \
  --source /usr/lib/firmware \
  --vendor ath11k \
  --skip-existing
cargo xtask usb-image --arch=x86_64 \
  --initramfs-firmware "ath11k/WCN6855/hw2.1/*" \
  --cmdline "ath11k.scan=1"
```

The pass is successful only after the console shows the WCN6855 HW2.1 probe,
firmware/MHI bring-up, a registered `wlan*` data path, and scan results. The
kernel-test PCI smoke intentionally stops before those asynchronous stages; it
validates the bound device, revision, firmware directory, and MSI layout only.

## CPU and isolation status

NARF selects its x86_64 domain backend at boot. It uses PKS when exposed by
the CPU and otherwise attempts the PCID page-table backend used by current AMD
laptops and many older Intel machines. The selected backend is printed in the
boot log.

PKS has suitable QEMU fault coverage. The PCID policy has structural tests,
but the enforcement path has not yet executed on the project's available
hardware runners. If neither PKS nor PCID is available, boot can continue
without a domain enforcer. Such a boot may still help driver bring-up, but it
must not be reported as proving NARF's cross-domain security properties. See
[Domain backends](DOMAIN_BACKENDS.md) for the exact boundary.

## Native Arch package on UEFI or legacy BIOS

A release may provide an Arch package named like:

```text
narf-kernel-<version>-1-x86_64.pkg.tar.zst
```

Inspect it before installation:

```sh
pacman -Qip ./narf-kernel-<version>-1-x86_64.pkg.tar.zst
pacman -Qlp ./narf-kernel-<version>-1-x86_64.pkg.tar.zst
```

Install it as an additional kernel target:

```sh
sudo pacman -U ./narf-kernel-<version>-1-x86_64.pkg.tar.zst
```

Developers can build the same package locally:

```sh
cargo install --path build/cargo-narf
cargo narf detect
cargo narf install --version 0.5.0 \
  --limine-efi /usr/share/limine/BOOTX64.EFI \
  --dry-run
cargo narf install --version 0.5.0 \
  --limine-efi /usr/share/limine/BOOTX64.EFI
```

Use the path from CachyOS's `limine` package. If the machine does not use
Limine as its primary manager, installing that package supplies build input;
it does not by itself change the active boot manager or firmware default.

The package installs `/boot/narf-kernel-<version>`, the package-owned UEFI
source payload under `/usr/lib/narf/uefi`, the `narf-uefi` administrator tool,
and `/etc/grub.d/42_narf`. When a FAT ESP is mounted at `/efi`, `/boot`, or
`/boot/efi`, its package hook also installs:

```text
/EFI/NARF/narf.efi
/EFI/NARF/narf-frame
/EFI/NARF/limine.conf
/boot/limine/limine.conf
/loader/entries/narf.conf
```

These are ESP-relative paths. For example, when the ESP itself is mounted at
`/boot`, its ESP-relative `/boot/limine/limine.conf` appears on the host as
`/boot/boot/limine/limine.conf`.

The `/boot/limine/limine.conf` copy is a marked GRUB-chainload fallback. The
installer does not overwrite an unrelated file at that path. It also skips
that fallback when another Limine EFI application is already present, then
reports a warning so that installation's existing Limine policy can remain in
control.

It does not replace or remove any CachyOS kernel, write UEFI NVRAM variables,
or change the default entry.

Before rebooting, verify the package and ESP payload:

```sh
pacman -Ql narf-kernel
grub-file --is-x86-multiboot2 /boot/narf-kernel-<version>
sudo narf-uefi status
```

If CachyOS already manages an enrolled Secure Boot policy with `sbctl`, sign
the NARF loader after package installation. This explicit choice persists and
future package upgrades re-sign the replacement loader:

```sh
sudo sbctl status
sudo narf-uefi install --sign-with-sbctl
sudo narf-uefi status
sudo sbctl verify /boot/EFI/NARF/narf.efi
```

Adjust the final path to the actual ESP mount point. Do not create or enroll
keys solely for this test without first accounting for CachyOS, Windows,
firmware updates, and option ROM trust. NARF never changes PK, KEK, `db`, MOK,
or the firmware Secure Boot setting. See
[UEFI Secure Boot](SECURE_BOOT.md) for the trust-chain and recovery model.

If `status` says no ESP is mounted, identify and mount the actual ESP, then
install explicitly. Do not substitute the root or data partition:

```sh
findmnt -t vfat
sudo narf-uefi install --esp /boot
sudo narf-uefi status --esp /boot
```

Replace `/boot` with the mount point reported on the machine. On UEFI GRUB,
the generated entry searches for the recorded ESP filesystem UUID, so another
disk or USB with an older `/EFI/NARF/narf.efi` cannot take precedence.
Regenerate `/boot/grub/grub.cfg` after a manual install and verify that the
NARF entry contains `chainloader`:

```sh
sudo grub-mkconfig -o /boot/grub/grub.cfg
grep -n -A12 -B1 "NARF <version>" /boot/grub/grub.cfg
```

On legacy BIOS the same generator searches first for
`/narf-kernel-<version>` and then `/boot/narf-kernel-<version>`, selecting the
filesystem that actually owns the file before issuing `multiboot2`.

No manual menu edit is needed for systemd-boot: it reads
`/loader/entries/narf.conf`. rEFInd discovers `/EFI/NARF/narf.efi`. On a
CachyOS Limine installation, the hook asks `limine-entry-tool` to register the
same EFI application; if the tool reports a warning, reinstall it explicitly
with `narf-uefi install` after confirming the ESP and active manager.

For an existing hardware-test Limine menu that directly loads
`boot():/boot/narf-frame`, adopt that config so the package also updates the
kernel the menu actually selects:

```sh
sudo narf-uefi install --esp /boot/efi \
  --limine-config /boot/efi/boot/limine/limine.conf
sudo narf-uefi status --esp /boot/efi
```

Use the actual ESP and config path. The config must contain exactly one NARF
Multiboot2 entry. Its command line, writable-root policy, graphical target,
and firmware modules remain intact. The selected kernel must report
`host Limine kernel matches package: yes` before rebooting; checking only
`/EFI/NARF/narf-frame` does not verify the old `/boot/narf-frame` target.
The adopted config is remembered for future package upgrades.

When building a package for this installed-root Plasma test, first build the
production systemd kernel, then package that exact artifact with
`--skip-build`:

```sh
cargo xtask build --arch=x86_64 \
  --features boot-init,cgroup-all,container,firmware-allow-unsigned
cargo narf package --version 0.5.0 --skip-build \
  --limine-efi /usr/share/limine/BOOTX64.EFI
```

`boot-init` enables `systemd_pid1`; the cgroup and namespace features support
the distro's systemd services. Do not package the canonical artifact left
by a kernel-test run. The normal package build serves NARF's built-in
userspace and does not enable these installed-root features automatically.

Installing a newer `narf-kernel` package upgrades the same package name,
removes the previous package-owned NARF image, and regenerates GRUB. It does
not retain an automatic older-NARF rollback entry. The separately installed
`linux-cachyos` package remains the recovery path and should stay the default.

At the GRUB menu, leave CachyOS as the default and select the NARF entry only
for the test. The current entry boots NARF's built-in userspace and does not
need a CachyOS-generated initramfs.

To remove the package and regenerate GRUB entries:

```sh
sudo pacman -R narf-kernel
```

Package removal invokes `narf-uefi remove` and regenerates GRUB when present.
The ESP must be mounted during removal. If it is currently unmounted, mount it
and run `sudo narf-uefi remove --esp <mount-point>` *before* `pacman -R`; the
package cannot clean an unmounted filesystem after its helper has been removed.

## Pre-hardware validation gate

Run `cargo xtask cachyos-gate` before booting the installed CachyOS root
under NARF on the real machine, and again after every change to storage,
btrfs, the disk policy or the systemd path. It boots the same
`cargo xtask grub-image` bundle that goes on the host's ESP, against disk
images that have the host's shape, and prints one PASS/FAIL row per check.
It exits nonzero if any row fails. It never opens a host block device.
Everything it writes is a regular file under `target/cachyos-gate/` (or
`--work-dir`).

```sh
cargo xtask cachyos-gate                       # full matrix (Gates A/B)
cargo xtask cachyos-gate --cases ro,rw         # a subset, in matrix order
cargo xtask cachyos-gate --crash-runs 3 --cycles 3 --seed 42
cargo xtask cachyos-gate --skip-build --cases linux   # reuse the staged bundles
cargo xtask cachyos-gate --real-root /mnt/sabrent/narf-gatec/cachyos-root-copy.img \
  --work-dir /mnt/sabrent/narf-gatec/work      # Gate C (see below)
```

### What it boots

| Piece | Gate | Host |
| --- | --- | --- |
| Machine | QEMU q35, OVMF (split CODE + a private VARS copy, so OVMF never writes `\NvVars` to an ESP), 4 vCPUs, 4 GiB, KVM when `/dev/kvm` is usable | B650I, UEFI |
| NVMe controller 1 (`00:04.0`) | Decoy GPT disk: vfat p1 (1 MiB) + ext4 p2 (64 MiB, one file), like the Sabrent | Sabrent Rocket 4.0 (`04:00.0`) |
| NVMe controller 2 (`00:07.0`) | Root disk: GPT vfat ESP p1 + btrfs p2, `boot` device | WD SN770 (`07:00.0`) |
| USB stick | MBR FAT32 with `/NARFLOG.ID` for `narf.bootlog=` | The bring-up stick |
| Boot chain | OVMF -> GRUB -> the bundle's `grub.cfg` stanza -> Limine (`/EFI/NARF/BOOTX64.EFI`) -> NARF | CachyOS GRUB -> the same stanza |

The root disk is the `cachyos-root-smoke` image
(`verification/data/cachyos-root/REGEN_cachyos_root_image.sh`, built
unprivileged on first use): the real CachyOS `base` userspace, `mkfs.btrfs -O
block-group-tree,free-space-tree,no-holes`, crc32c, 16 KiB nodes, 4 KiB
sectors, zstd, the subvolumes `@ @home @root @srv @cache @tmp @log`, and the
host's fstab with the image's own UUIDs. Its superblock carries the host's
feature flags exactly (compat_ro 0xb, incompat 0x371). The gate works on a
reflinked copy, `target/cachyos-gate/root.img`.

GRUB is a `grub-mkstandalone` x86_64-efi image placed at
`\EFI\BOOT\BOOTX64.EFI` on the root disk's ESP. Its embedded `grub.cfg` is
`set timeout=0` plus the bundle's own `grub.cfg` stanza, unchanged, so the
`search --file /EFI/NARF/BOOTX64.EFI` + `chainloader` path that runs on the
host is the path tested. The bundle's `esp/` tree is copied onto the same
ESP, as on the host. The gate builds two bundles:

```sh
cargo xtask grub-image --features cgroup-all,container \
  --root-policy root-ro --root-uuid <image fsid>      # and --root-policy root-rw
```

`--root-policy` makes `grub-image` add the systemd PID 1 features
(`boot-init`, `cgroup-all`, `container`, `firmware-allow-unsigned`), the
configuration `systemd-pid1` uses; `--features cgroup-all,container` is
redundant but harmless. Build the hardware bundle the same way (the full
command is under
[Booting the installed root](#booting-the-installed-root-narfdisksroot-ro--root-rw)).
The gate passes `--bootlog-token <token>`. The resulting command line is
printed in the `topology` row, for example:

```
narf.disks=root-rw root=UUID=<fsid> rootflags=subvol=/@ systemd_pid1 systemd.zram=0 narf.bootlog=gate...
```

Each boot logs in on the serial console (`root` / `narf`, the image's test
credentials) and drives the guest from a shell. The write workload writes
under `/narf-gate` on `@`:

- 400 small files, 50 of them fsynced one at a time;
- 100 renames and 100 unlinks;
- a 100 MiB file written through a temporary name, fsynced, then renamed;
- a `TAG` file;
- a file in `/home` if `/home` is writable;
- a journald message, then `journalctl --flush`.

It reports `home=rw|ro`, `journal=persistent|volatile` and the mount options
of `/`, `/home` and `/var/log`. All content is deterministic, so the host can
verify it byte for byte.

### The rows

| Row | Passes when |
| --- | --- |
| `topology` | Both bundles built; the root image's fsid and ESP serial differ from every host disk (the constants above plus `findmnt -no UUID` of `/`, `/boot/efi` and `/home`); its `/etc/fstab` (read with `btrfs restore`) names only the image's own btrfs and ESP UUIDs; no log tree. |
| `1 root-ro` | The getty login prompt is reached and the workload runs on the tmpfs overlay. Afterwards the SHA-256 of the whole root disk and of the decoy is unchanged, and so is the btrfs superblock generation. |
| `2 root-rw` | Login is reached with `/` mounted `rw`, and the workload and a clean `systemctl poweroff` complete. On the host, `btrfs check --readonly` and `btrfs check --readonly --check-data-csum` are clean, and `btrfs restore -r <id of @>` (unprivileged, on the extracted partition file) yields exactly the expected files and content. `log_root` is 0. Every byte outside the btrfs partition (GPT, ESP, slack) and the whole decoy are unchanged. |
| `3 crash xN` | N times, QEMU is SIGKILLed at a uniformly random point (5-95%) of the workload, using the duration measured by row 2 (30 s if row 2 did not run). `btrfs check --readonly` must be clean after each kill. The next NARF root-rw boot must either mount `/` read-write (only allowed when `log_root` is 0), or refuse read-write with the `non-empty fsync log tree` reason while leaving the root partition's hash unchanged. A refusal is followed by one Linux boot, which replays the log, and the runs continue. A final boot judges the last kill. |
| `4 cycles xN` | N consecutive root-rw boot -> workload -> poweroff cycles, each followed by the row 2 host checks: check, check-data-csum, restore, outside-bytes and decoy unchanged, `log_root` 0. |
| `5 linux interop` | The host's own kernel (`/boot/vmlinuz-linux-cachyos`, copied) boots the post-NARF image with systemd, mounts `/` rw, reads the files of the last NARF round (SHA-256 of `big.dat`, a small file), and runs the workload. `btrfs scrub start -B /` must find no errors, and the host checks must then be clean. NARF then boots the image root-rw again, reads the Linux-written files, writes a new round and powers off, and the host checks are clean again (round trip). |
| `boot chain` | Summary of every boot. Each NARF boot must show GRUB's `Booting 'NARF'` within 120 s, NARF's first console line within 180 s more, and its `disks: POLICY` line within 240 s after that. A boot that hangs before the kernel runs (firmware, GRUB or Limine) is killed and retried once, and is listed here. A second hang fails the row that was booting. |

The Linux boot needs no initramfs. The CachyOS kernel has btrfs and
virtio-blk built in (NVMe is a module), so the gate attaches both images as
virtio-blk disks and boots `root=PARTUUID=<p2> rootflags=subvol=/@ rw
console=ttyS0`. vfat is a module too, so it adds `systemd.mask=boot-efi.mount`.
The image has no Linux modules, so the ESP cannot be mounted. Add arguments
with `CACHYOS_GATE_LINUX_APPEND`.

### Reading the output

The run ends with a table:

```
cachyos-gate results
row              result  detail
---------------  ------  ----------------------------------------
topology         PASS    q35+OVMF; OVMF -> GRUB (...) -> Limine -> NARF
                         ...
1 root-ro        PASS    login 41s; / rw (overlay); ...; root+decoy sha256 unchanged; gen 9 unchanged; ...
2 root-rw        FAIL    / is not mounted read-write under root-rw: btrfs ...: REFUSING read-write mount: ...
```

- A row's detail starts with the first failure. The last lines of the guest
  console follow, and then the serial log's path, so a FAIL can be read
  without rerunning.
- `target/cachyos-gate/logs/NN-<label>.serial.log` holds the full serial
  console of boot `NN`: firmware, GRUB, Limine, the NARF kernel log, systemd
  and the shell session.
- `target/cachyos-gate/check/<label>.check.log` and `.check-csum.log` hold the
  host `btrfs check` output. `<label>.restore.log` and `restore-<label>/` hold
  what `btrfs restore` extracted.
- `REFUSING read-write mount: <reason>` lines in a detail come from NARF's
  read-write safety gate. Under `root-rw`, the gate turns the volume
  read-only and names the reason, such as an unsupported feature bit or a log
  tree.
- `home=ro` or `journal=volatile` in a PASS row is information, not a
  failure. The workload writes to `@` only. Whether the other fstab
  subvolumes come up writable depends on the btrfs one-writer-per-fsid rule.
- The crash row prints its seed. Rerun it with the same `--seed` to repeat
  the same kill points.
- `bootlog saved|not saved` in row 1 shows whether the kernel log reached the
  USB stick under that policy.

Do not boot the installed root on hardware until every row passes on the
current tree, first against the generated image (Gates A/B) and then against
a real copy of the host root (Gate C).

### Gate C: a real copy of the host root

Gate C runs the same matrix against a byte-level copy of the host's own `@`
(and optionally `@home`). Build the copy once, on the Sabrent's ext4 data
partition (`/mnt/sabrent`, about 519 GB free). These are the only commands
in this workflow that need `sudo`. They read the live root through read-only
snapshots and write only the image file through a loop device. The copy gets
a new fsid, a new ESP serial and an fstab that names only those, so it can
never be confused with the host root.

```sh
set -eu
SAB=/mnt/sabrent
DIR=$SAB/narf-gatec
IMG=$DIR/cachyos-root-copy.img
HOST_FSID=653602c3-cd42-420e-95ef-4c4033d17b56   # live root; never reused
HOST_ESP=6D89-28C5
sudo mkdir -p "$DIR" && sudo chown "$USER": "$DIR"

# 1. A sparse GPT disk: 512 MiB ESP + btrfs sized for the root's data + 40 GiB.
USED=$(sudo btrfs filesystem usage -b / | awk '/^ *Used:/ {print $2; exit}')
truncate -s $(( USED / 1024 / 1024 / 1024 + 41 ))G "$IMG"
sfdisk "$IMG" <<'SFDISK'
label: gpt
start=2048, size=1048576, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI system partition"
start=1050624, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="root"
SFDISK

# 2. Filesystems with fresh identities and the host root's mkfs features.
LOOP=$(sudo losetup --find --show --partscan "$IMG")
NEW_FSID=$(uuidgen)
sudo mkfs.fat -F 32 -n EFI "${LOOP}p1"
sudo mkfs.btrfs -U "$NEW_FSID" -L cachyos-gatec --csum crc32c -n 16384 -s 4096 \
  -O block-group-tree,free-space-tree,no-holes "${LOOP}p2"
NEW_ESP=$(sudo blkid -s UUID -o value "${LOOP}p1")
sudo mkdir -p /mnt/narf-gatec /mnt/narf-hosttop
sudo mount -o noatime,compress=zstd:1 "${LOOP}p2" /mnt/narf-gatec

# 3. Read-only snapshots of the live subvolumes, sent into the copy.
sudo mount -o subvolid=5 UUID=$HOST_FSID /mnt/narf-hosttop
sudo btrfs subvolume snapshot -r /mnt/narf-hosttop/@ /mnt/narf-hosttop/@narf-gatec-root
sudo btrfs send /mnt/narf-hosttop/@narf-gatec-root | sudo btrfs receive /mnt/narf-gatec/
# Optional: also copy @home.
sudo btrfs subvolume snapshot -r /mnt/narf-hosttop/@home /mnt/narf-hosttop/@narf-gatec-home
sudo btrfs send /mnt/narf-hosttop/@narf-gatec-home | sudo btrfs receive /mnt/narf-gatec/

# 4. Writable @ (and @home) in the copy, plus the remaining CachyOS subvolumes.
sudo btrfs subvolume snapshot /mnt/narf-gatec/@narf-gatec-root /mnt/narf-gatec/@
sudo btrfs subvolume snapshot /mnt/narf-gatec/@narf-gatec-home /mnt/narf-gatec/@home \
  || sudo btrfs subvolume create /mnt/narf-gatec/@home
for s in @root @srv @cache @tmp @log; do sudo btrfs subvolume create /mnt/narf-gatec/$s; done
sudo btrfs subvolume delete /mnt/narf-gatec/@narf-gatec-root
sudo btrfs subvolume delete /mnt/narf-gatec/@narf-gatec-home 2>/dev/null || true

# 5. Inside the COPY only: fstab names the copy's UUIDs; every other UUID line
#    (the Sabrent, other disks) is commented out. Gate login root/narf.
F=/mnt/narf-gatec/@/etc/fstab
sudo sed -i -e "s/$HOST_FSID/$NEW_FSID/g" -e "s/$HOST_ESP/$NEW_ESP/g" "$F"
sudo awk -v a="UUID=$NEW_FSID" -v b="UUID=$NEW_ESP" \
  '/^[[:space:]]*UUID=/ && $1 != a && $1 != b { print "#narf-gatec# " $0; next } { print }' \
  "$F" | sudo tee "$F.new" >/dev/null && sudo mv "$F.new" "$F"
echo 'root:narf' | sudo chpasswd -R /mnt/narf-gatec/@
grep -v '^#' "$F"                           # review: only $NEW_FSID / $NEW_ESP

# 6. Clean up: the host's temporary snapshots, the mounts, the loop device.
sudo umount /mnt/narf-gatec
sudo btrfs subvolume delete /mnt/narf-hosttop/@narf-gatec-root /mnt/narf-hosttop/@narf-gatec-home
sudo umount /mnt/narf-hosttop
sudo losetup -d "$LOOP"
sudo chown "$USER": "$IMG"
```

Then, unprivileged:

```sh
cargo xtask cachyos-gate --real-root /mnt/sabrent/narf-gatec/cachyos-root-copy.img \
  --work-dir /mnt/sabrent/narf-gatec/work
```

The gate refuses an image whose fsid or ESP serial matches a host disk, or
whose fstab names any other UUID. ext4 has no reflinks, so the gate first
makes a full copy of the image in `--work-dir`, and the host checks extract
the btrfs partition to a file again after each boot. Expect a run to take
hours for a large root. Add `--in-place` to boot the given image itself and
skip the first copy; Gate C is then single-use until the copy is rebuilt. The
copy keeps the host's machine-id and enabled units. If the graphical target
gets in the way of the serial login, run `sudo ln -sfn
/usr/lib/systemd/system/multi-user.target
/mnt/narf-gatec/@/etc/systemd/system/default.target` in step 5.

## Booting the installed CachyOS root

NARF can boot the CachyOS installation on the WD SN770 (`07:00.0`, btrfs root
`653602c3-cd42-420e-95ef-4c4033d17b56`) with the installed systemd as PID 1,
mount its fstab, and reach a getty login on `tty1`. GRUB's default entry stays
CachyOS. NARF is a one-shot entry chosen from the boot menu, so rolling back
means rebooting and taking the default entry.

### Command lines

First trial, read-only:

```text
narf.disks=root-ro root=UUID=653602c3-cd42-420e-95ef-4c4033d17b56 rootflags=subvol=/@ systemd_pid1 systemd.zram=0 systemd.unit=multi-user.target fsck.mode=skip
```

Read-write, after the root-ro trial worked:

```text
narf.disks=root-rw root=UUID=653602c3-cd42-420e-95ef-4c4033d17b56 rootflags=subvol=/@ systemd_pid1 systemd.zram=0 systemd.unit=multi-user.target fsck.mode=skip
```

`cargo xtask grub-image --root-policy root-ro|root-rw --root-uuid <uuid>
--cmdline-extra "systemd.unit=multi-user.target fsck.mode=skip"` writes these
lines (see
[Booting the installed root](#booting-the-installed-root-narfdisksroot-ro--root-rw)
for the full command). Use `systemd.unit=multi-user.target` for the first
trials: the host defaults to `graphical.target` (plasmalogin), and the KDE
session is not part of this recipe. `rootflags=subvol=@` (no slash) and `rootflags=subvolid=256`
are accepted too. `ro` / `rw` on the command line follow Linux: the last one
wins. Under `root-ro` the root is always read-only. Under `root-rw` it is
mounted writable unless the command line says `ro`.

### What happens

- **Root.** `root=UUID=` is matched against the btrfs fsid of every
  partition on both NVMe controllers, by identity and never by position.
  The matched partition is designated (`designate_root`) before the
  filesystem is built. Its `@` subvolume is then mounted through the same
  constructor `mount -t btrfs -o subvol=/@` uses, read-only under
  `root-ro`.
  - `root-ro`: systemd gets a writable tmpfs overlay over the read-only
    root. Everything it writes (journal, `/etc/machine-id`, `/var/lib`)
    lives in RAM and is gone at power-off. No byte reaches any disk.
  - `root-rw`: no overlay. `/` is the real `@` subvolume, written in place.
- **systemd runs in host mode, not container mode**
  (`systemd-detect-virt` prints the hypervisor or `none`), and its fstab
  units do the rest:
  - `/home`, `/root`, `/srv`, `/var/cache`, `/var/tmp` and `/var/log` are
    btrfs subvolume mounts of the same filesystem, with the fstab options
    (`noatime,compress=zstd:1`). Under `root-ro` the kernel answers a
    writable mount of a read-only disk with `EROFS`, so `mount(8)` retries
    read-only, as for a write-protected disk on Linux. Under `root-rw` they
    are writable views of one shared btrfs instance.
  - `/boot/efi`: the ESP (`6D89-28C5`) is checked by `fsck.vfat` and
    mounted read-only. NARF never writes it, under either policy.
  - `/tmp` is tmpfs.
- **udev.** udev sees the NVMe partitions, their filesystem UUIDs, input and
  DRM devices. `/dev/btrfs-control` answers udev's btrfs readiness check, so
  `dev-disk-by\x2duuid-…​.device` appears.
- **Logging.** journald logs to `/run/log/journal` under `root-ro`. Under
  `root-rw` it logs persistently to `/var/log/journal` (the `@log`
  subvolume).
- **Login.** getty@tty1 shows `<hostname> login:` on the framebuffer
  console. Log in with your normal user or root password (PAM, from the
  installed `/etc/shadow`). The USB keyboard is the input.

### What fails, and why that is harmless

The QEMU acceptance run (`cargo xtask cachyos-root-smoke`, below) boots a
stock CachyOS `base` install. Under `root-ro` it reaches
`systemctl is-system-running` = `running` with no failed units. Expect the
host to add failures from the packages it has on top of `base`:

| Unit | When | Why | Effect |
| --- | --- | --- | --- |
| `systemd-sysusers`, `systemd-random-seed`, `ldconfig`, `systemd-update-done`, `systemd-journal-catalog-update` | `root-rw` only | NARF's btrfs does not yet implement `chmod`/`chown`/`utimensat` on files (`Operation not supported`) | Each is a first-boot or maintenance task. They retry on the next boot. `/etc/ld.so.cache` and the random seed keep their previous contents. |
| `ananicy-cpp.service` | sometimes | it cannot create its cgroups (`Read-only file system`) | No automatic nice/ionice rules. |
| `dev-zram0.swap`, `systemd-zram-setup@zram0` | never generated | NARF has no zram block device (and no `swapon`), so the root-policy command line carries `systemd.zram=0`, zram-generator's opt-out. Without it the swap units wait 90 s for a `/dev/zram0` that never appears (`Timed out waiting for device /dev/zram0`), as on a Linux kernel built without zram. | No compressed swap. |
| `systemd-modules-load` messages | always | Linux `.ko` modules do not load under NARF (`Failed to find module`) | The unit succeeds; each module is skipped. |
| `[FAILED] Failed unmounting /root` at power-off | when a shell still has its cwd in `/root` | the unit-level unmount races the session's processes | systemd-shutdown unmounts it in its final pass, then remounts `/` read-only and syncs. |

Nothing here blocks `multi-user.target`. Under `root-rw` the system reports
`degraded`. KDE, NetworkManager, Wi-Fi, Bluetooth and sound are not part of
this recipe.

Power-off is clean in both modes. `systemctl poweroff` runs:

1. systemd-shutdown remounts `/` read-only;
2. it syncs;
3. NARF flushes both NVMe controllers;
4. NARF completes `CC.SHN` (`nvme: nvme1: … CC.SHN normal shutdown: Complete`).

### Before a real root-rw boot

- Boot `root-ro` first and confirm the login prompt.
- Take a read-only snapshot on CachyOS:
  `sudo btrfs subvolume snapshot -r / /.snapshots/pre-narf`. Keep a backup of
  `/home`.
- In NARF, shut down cleanly (`systemctl poweroff`).
- Back on CachyOS, run `sudo btrfs scrub start -B /` and
  `sudo btrfs check --readonly` from a live medium if anything looks wrong.

### Rollback

GRUB's default entry is CachyOS, so a reboot without touching the menu goes
back to Linux. After a `root-ro` boot nothing needs undoing. After a
`root-rw` boot, a `btrfs subvolume snapshot` taken before is the rollback
point. NARF writes nothing outside the root partition: not the ESP, the
Sabrent or `sda`.

### QEMU rehearsal (no root needed, no host disk touched)

```sh
cargo xtask cachyos-root-smoke          # root-ro, image SHA-256 must be unchanged
cargo xtask cachyos-root-smoke --rw     # root-rw on a scratch copy
cargo xtask cachyos-gate --cases ro,rw  # the same through OVMF -> GRUB -> Limine
```

`cachyos-root-smoke` builds `target/narf-cachyos-root.img` on first use
(`verification/data/cachyos-root/REGEN_cachyos_root_image.sh`). The script
installs CachyOS `base`, `cachyos-settings` and the CachyOS keyrings and
mirror lists with pacman, inside a user namespace, from the host's own
repositories and package cache. It copies only the host's public keyring
and mirror lists and writes nothing outside `target/`. The image has the
host root's layout: a GPT ESP plus btrfs with nodesize 16K, block-group
tree, free-space tree, no-holes, zstd and the seven `@` subvolumes, and the
host's fstab with image-only UUIDs. It is attached behind a decoy disk as the
second NVMe controller. The smoke then:

1. boots the bare-metal command line;
2. waits for `cachyos-narf login:`;
3. logs in as `root`/`narf` over the console;
4. prints the failed units with their journals, the fstab mounts and
   udev's view of the root;
5. checks the decoy disk (and, under root-ro, the root image) is
   byte-identical.

## Open implementation work

The UEFI packaging path is now implemented, but these deployment items remain:

| Item | Needed before calling it supported |
| --- | --- |
| CachyOS root acceptance | Done for root-ro (`cachyos-root-smoke`, `cachyos-gate` row 1) including login and clean shutdown; root-rw needs btrfs chmod/chown/utimes and the gate's rw rows; networking remains. |
| Encrypted root boot | Build/stage a NARF initramfs, add credential policy and kernel arguments, and provide an interactive or distribution-managed unlock path. |
| CachyOS Btrfs layout | Gate the default `@` subvolume layout, Zstd, fstab-generated mounts, snapshots, and shutdown/recovery behavior. |
| Secure Boot key lifecycle | A deploying distribution or administrator must own enrollment, rotation, revocation, recovery, and signing-key custody; NARF deliberately does not automate firmware key changes. |
| Hardware support matrix | Run repeatable silicon tests keyed by PCI/USB/ACPI IDs, firmware versions, and machine models instead of inferring support from in-tree code. |

Those changes should use focused follow-up branches because they change boot
policy, test infrastructure, filesystems, or drivers.

## If something is not supported

Do not try to make NARF the default kernel or repair the production
installation from the failed NARF boot. Reboot the existing `linux-cachyos`
entry, then choose the narrow fallback for the missing layer:

1. If `narf-uefi status` fails, mount the ESP and rerun `narf-uefi install`
   with an explicit `--esp`. If the active manager still has no NARF entry,
   use QEMU or the standalone NARF ISO/USB image and report the manager and
   ESP layout.
2. If the root is encrypted, keep it locked and use a disposable unencrypted
   ext4 test image. The measured-initramfs keyfile flow is for intentionally
   constructed test images, not an automatic CachyOS unlock replacement.
3. If the filesystem is XFS, F2FS, or ZFS, do not mount it through NARF. Clone
   the workload onto a disposable ext4 image instead. Treat an existing Btrfs
   CachyOS root the same way until its full boot layout has an acceptance test.
4. If storage does not bind, stop before mounting or writing. Reproduce with a
   QEMU virtio-blk or NVMe device and report the physical controller's PCI ID.
5. If networking is missing, collect logs offline and reproduce with QEMU
   e1000. Prefer a known supported wired device over Wi-Fi for bare-metal
   bring-up.
6. If graphics or input fails, use serial output, the boot framebuffer, and a
   USB keyboard. A graphical desktop is not the first proof of a sound boot.
7. If implementing the missing support, keep it in an external crate and add
   it through a composition first. Record the exact PCI/USB/ACPI identity and
   firmware requirements before choosing built-in versus runtime-module form.

From CachyOS, collect read-only inventory before filing a report:

```sh
uname -a
lspci -nnk
lsusb
lsblk -f
findmnt -no SOURCE,FSTYPE,OPTIONS /
findmnt /boot /boot/efi
```

Include that inventory, the exact NARF commit, how the image was built, the
boot method, kernel arguments, and the complete serial log. If the failure is
device-specific, identify the vendor/device ID and firmware revision rather
than only the product name.

For the authoritative implementation status, see [STATUS.md](../STATUS.md),
the [desktop compatibility track](DESKTOP_LINUX_PLAN.md), and the
[release-packaging guide](../packaging/README.md).
