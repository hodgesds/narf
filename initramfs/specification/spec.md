# initramfs — Specification

> Status: **v0.1** (Stage 5 design draft).

## 1. Purpose & scope

**Owns:**

- The **bootloader → kernel handoff** of the initramfs phys
  region: where the bytes live in physical memory, how the
  kernel finds them, and how it validates the handoff.
- The **CPIO newc parser** that turns a raw byte slice into an
  enumerable `Initramfs` value with `(name, &[u8])` entries —
  no allocation past the entry vector itself.
- The **staging API** that lets cross-cutting consumers
  (`narf-firmware::scan_initramfs`, future `firmware-blobs`,
  `userspace::loader` for the init binary, etc.) borrow the
  `Initramfs` without each one re-reading the CPIO archive.
- The **boot-path mount** that exposes the initramfs as a
  read-only filesystem at a well-known mount point (`/initrd`
  on Linux convention; `/boot` here to dodge confusion with
  initrd's reclaim-on-pivot semantics that NARF doesn't use).
- The **`Stage::Late` consumer hook** order: every consumer
  registered under `Stage::Late` runs AFTER initramfs staging
  completes, so consumers can rely on `staged_initramfs()`
  returning `Some(_)` when the build profile expects an
  initramfs to be present.

**Does NOT own:**

- Filesystem semantics beyond initramfs (`narf-filesystem`).
- Bootloader-specific protocols beyond extraction (`boot/` owns
  multiboot2 / PVH / FDT parsing). This crate consumes
  `narf_boot::BootInfo::initramfs` and turns the phys range into
  a CPIO-parsed value.
- DMA-coherent allocation (`io/`) — initramfs blobs are
  read-only from a fixed phys region the bootloader marked
  reserved; no DMA mapping is needed.
- Firmware blob delivery semantics (`narf-firmware`). This crate
  hands `narf-firmware` a `&'static Initramfs`; the firmware
  registry walks `firmware/*` entries. Same pattern applies
  to other potential consumers (initial userspace binary,
  device tree overlays, etc.).
- Pivot-root / chroot semantics. The initramfs is permanently
  mounted; there's no "real root" handoff phase.

## 2. Why a separate crate

Today initramfs functionality lives inside `narf-filesystem`'s
`Initramfs` struct + CPIO newc parser. That worked when only the
VFS read path consumed the archive, but Stage 6 (firmware loader)
brought in a second consumer, and the boot path needs to stage
the archive once for both.

Splitting `initramfs/` out of `narf-filesystem/` gains:

1. **One staging point.** Both `narf-firmware` and
   `narf-filesystem` (and any future consumer) borrow the same
   `&'static Initramfs` instead of each re-reading the CPIO
   archive from the phys region. The `STAGED_INITRAMFS` static
   moves out of `narf-firmware` (where it currently lives as a
   step-3 stopgap) into here.

2. **Boot-path layering clarity.** `boot/` parses the
   bootloader's module-list / chosen-node entry and produces a
   `MemRegion { kind: InitramfsImage, … }`. The kernel boot
   path then calls `initramfs::stage_from_boot_info(&boot_info)`
   exactly once. No subsystem reaches into `boot/` directly to
   discover the initramfs.

3. **Test surface independence.** Today's CPIO smokes live
   under `filesystem` since the parser does. With the parser
   here, the `narf-filesystem`'s tests stay focused on VFS
   semantics; CPIO byte-format coverage moves to `initramfs/`'s
   own `src/tests.rs`.

4. **Dependency direction.** `narf-firmware` already depends on
   `narf-filesystem` only for the CPIO parser surface; with the
   parser in its own crate, `narf-firmware` can depend on
   `narf-initramfs` directly without dragging the VFS in.

## 3. Design principles

1. **Stage once, borrow forever.** The kernel boot path stages
   the parsed `Initramfs` exactly once into a process-global
   `OnceLock`-shaped static; subsequent consumers borrow
   `&'static Initramfs`. There is no unstaging — initramfs is a
   boot artifact that lives until kernel shutdown.

2. **Allocation-free read.** CPIO entries borrow from the
   phys-memory archive; the only allocation is the entry vector
   itself (one `Vec<InitramfsEntry>` per parse). No
   per-entry `String`s, no per-entry data copies. The phys
   region is identity-mapped on Stage-1 boot (the bootloader's
   reserved range stays usable until the MMU bring-up converts
   it to a kernel-virtual mapping; that's a `memory/` concern).

3. **Defensive parsing.** The CPIO newc reader rejects
   malformed input rather than panic. Stage::Bootstrap calls
   `Initramfs::from_cpio` which returns a typed `CpioError`
   variant for every failure mode (truncated header, bad magic,
   unaligned data start, name overflows the archive bounds).

4. **Single mount point.** The initramfs mounts at `/boot` (no
   leading-slash variation, no per-target divergence). The
   filesystem registry exposes the mount via the standard
   `narf_filesystem::registry()` surface; consumers walk it the
   same way they walk any other mount.

5. **Mirror existing kernel patterns.** Staging API matches
   `narf-firmware::install_trusted_loader_authority` (one-shot
   process-global). CPIO parsing returns `Result` with a typed
   error enum like every other Stage-3 parser.

## 4. Boot-path handoff

### 4.1 Bootloader-supplied region

Multi-architecture handoff:

- **multiboot2** (x86_64, BIOS/UEFI): the bootloader places the
  CPIO archive at a 4-KiB-aligned phys address and emits a
  `MULTIBOOT2_TAG_TYPE_MODULE` entry pointing at it. The
  module's `cmdline` string MUST be the canonical name
  `"initramfs"` (case-insensitive); modules with other names
  are ignored by `initramfs/`. The kernel-build script writes
  exactly one such tag per kernel image; multiboot2 supports
  more, but `initramfs/` accepts the first matching entry and
  ignores duplicates.

- **PVH** (x86_64, virtualized): the `hvm_start_info::modlist`
  entry has the same shape; the cmdline string still must be
  `"initramfs"`. The PVH spec doesn't impose alignment, but
  `boot/` enforces 4 KiB.

- **U-Boot / FDT** (aarch64): the `chosen` node carries
  `linux,initrd-start` + `linux,initrd-end` properties (Linux
  convention). `boot/` reads them and packages the range as a
  `MemRegion { kind: InitramfsImage }`.

- **No initramfs** (raw `-kernel` boot, smoke testing): the
  bootloader emits no module tag. `BootInfo::initramfs`
  returns `None`; `Stage::Bootstrap`'s `initramfs-stage`
  initcall returns `InitResult::NotPresent`; `Stage::Late`
  consumers see `staged_initramfs() == None`.

### 4.2 BootInfo extension

`narf_boot::BootInfo` gains an `initramfs: Option<MemRegion>`
field. The field is `Option` rather than `MemRegion` because the
no-initramfs path is supported (smoke harnesses, minimal boot
images). When present, the region's `start` is 4-KiB-aligned and
`len` is the exact archive byte count.

### 4.3 Staging initcall

`initramfs::register_initcalls()` registers a
`Stage::Bootstrap` slot named `"initramfs-stage"`. The slot:

1. Reads `boot_info().initramfs`. `None` → `InitResult::NotPresent`.
2. Validates the phys region is identity-mapped (an architecture
   invariant in Stage-1 boot; a `memory/` consultation if Stage-2
   has remapped).
3. Borrows the phys range as `&'static [u8]`. The bootloader-
   reserved region stays alive for the kernel's lifetime
   (`MemRegionKind::Reserved`); no allocator action is needed.
4. Calls `narf_filesystem::Initramfs::from_cpio(name, slice)`.
5. On success, stores the result in `STAGED` (a process-global
   `IrqSafeSpinLock<Option<&'static Initramfs>>`). The
   `Initramfs` itself lives in a `'static` slot allocated from
   the boot-time arena; per-archive entry vectors are heap-
   allocated.

Consumers register at `Stage::Late` (or later) and rely on
`staged_initramfs()` returning `Some(&'static Initramfs)`.

## 5. Public API surface

```rust
/// One regular-file entry in the parsed initramfs. Borrows
/// names + data from the phys-memory archive.
#[derive(Copy, Clone, Debug)]
pub struct Entry {
    pub name: &'static str,
    pub data: &'static [u8],
    pub mode: u32,
    pub mtime: u64,
}

/// Parsed CPIO newc archive. Owns the entry vector; data
/// + names borrow from the source slice.
pub struct Initramfs { /* opaque */ }

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpioError {
    /// Archive too short for even one header.
    Truncated,
    /// `070701` magic missing from the first header.
    BadMagic,
    /// Header advertises a name length that overflows the archive.
    NameOverflow,
    /// Data section overflows the archive.
    DataOverflow,
    /// File-mode field was non-hex / out of range.
    BadMode,
}

impl Initramfs {
    /// Parse a CPIO newc archive. Source slice must outlive the
    /// returned value.
    pub fn from_cpio(
        name:    &'static str,
        archive: &'static [u8],
    ) -> Result<Self, CpioError>;

    /// Iterate every regular-file entry as `(name, data)` pairs.
    /// `name` is the path-as-it-appeared in the archive.
    pub fn iter_files(&self)
        -> impl Iterator<Item = (&'static str, &'static [u8])> + '_;

    /// Look up a single entry by exact name. Returns `None` for
    /// directories (CPIO emits dir entries; we filter to regular
    /// files at iter / lookup time).
    pub fn lookup(&self, name: &str) -> Option<Entry>;

    /// Number of regular-file entries.
    pub fn file_count(&self) -> usize;
}

/// Stage a parsed initramfs for later consumers. Idempotent —
/// first install wins.
pub fn install(fs: &'static Initramfs);

/// Borrow the staged initramfs. `None` until `install` runs.
pub fn staged() -> Option<&'static Initramfs>;

/// `true` once an initramfs has been staged.
pub fn is_staged() -> bool;

/// Stage::Bootstrap initcall that consumes
/// `boot_info().initramfs` if present, parses it, calls
/// `install`. Returns `InitResult::NotPresent` when the
/// bootloader supplied no initramfs.
pub fn register_initcalls();
```

## 6. Migration plan from the current state

Today `Initramfs` lives in `narf-filesystem` as a public type;
`narf-firmware` re-implements the staging static. Three steps,
each independently shippable:

1. **New crate skeleton, no behavior change.** Create
   `initramfs/` with the public surface. Make
   `narf-filesystem::Initramfs` a `pub use
   narf_initramfs::Initramfs` re-export so existing callers
   compile unchanged. (1 PR; deps shuffle only.)

2. **Move staging static + boot-path init.** Move
   `STAGED_INITRAMFS` from `narf-firmware` into
   `narf-initramfs`. `narf-firmware::install_initramfs` becomes
   a `#[deprecated]` thin shim around `narf_initramfs::install`.
   Add `BootInfo::initramfs` + the multiboot2-module / PVH /
   FDT parsers in `boot/`. Add the `Stage::Bootstrap`
   `initramfs-stage` initcall. (2 PRs, one for boot, one for the
   move.)

3. **Drop the deprecated shim.** After all in-tree consumers
   migrate to `narf_initramfs::staged()`, remove the firmware
   shim. (1 PR.)

After Stage-5: `narf-firmware::scan_initramfs(fs, &auth)` is
unchanged — the FS parameter is still `&Initramfs`, just from a
new crate. The `Stage::Late` `firmware-scan-initramfs` initcall
swaps its source from `narf_firmware::staged_initramfs()` to
`narf_initramfs::staged()`.

## 7. Out of scope (Stage 6+ follow-ups)

- **Initramfs writes.** This crate is read-only. A future
  ramfs / tmpfs that borrows the same byte-storage shape would
  be a sibling crate, not an extension here.
- **Compression.** xz / zstd / gzip-compressed initramfs
  archives stay decoded by the bootloader (Linux convention)
  — `boot/` hands us already-decompressed bytes.
- **Pivot-root / pseudo-FS overlay.** NARF doesn't have a
  "real root after pivot" phase; the initramfs is the only
  in-memory FS until userspace mounts virtiofs / 9p.
- **Hot-replace at runtime.** Initramfs is a boot artifact —
  there's no `unstage` path. Live system updates land via
  `narf-firmware::install` (for firmware blobs) or future
  package-installer surfaces (for userspace binaries), not by
  swapping the initramfs.
- **Cap-gated lookup.** Entries are kernel-trusted bytes that
  passed bootloader-side signature verification (when applicable);
  borrowers don't need a per-call cap. A future Stage-7 may add
  a `Cap<Initramfs, Read>` shape if multi-tenant kernel
  partitions ever land.

## 8. Open questions

- Should the staging static be **per-cpu** for read scalability?
  Lookup is rare (Stage::Bootstrap one-shot, Stage::Late
  scanners) so the spinlock is fine for now. Revisit if a
  hot-path consumer appears (none planned).
- Is the **single-mount-point** assumption (`/boot`) too rigid?
  POSIX systems often distinguish `/boot` (boot loader stage)
  from `/initrd` / `/root` (initial userspace). NARF collapses
  these to one mount because there's no pivot-root. If that
  ever changes, the mount point becomes configurable.
- Does the **CPIO newc** format suffice forever? It's the Linux
  convention so toolchains exist (`cpio`, `find . | cpio -o
  -H newc > out.cpio`). A `cpio` rewrite to support the
  HBSD / OpenBSD newcrc dialect or a NARF-native flat format is
  out of scope today.
