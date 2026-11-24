# Writing a NARF kernel module

This guide is for authors of out-of-tree NARF kernel modules. For
the design rationale, see [DESIGN.md](./DESIGN.md). For the
architecture-comparison overview, see the workspace-root
`COMPARISON.md`.

## Project layout

> **Status note.** Build your module with:
>
> ```sh
> cargo xtask build-module --manifest-path /path/to/Cargo.toml \
>   --package <your-crate> --arch x86_64
> ```
>
> which compiles the crate, takes its own object members out of the
> `staticlib` archive, and `ld -r`s them into a single relocatable
> object — merging the per-static `.modinfo` sections in the process.
> Works for `aarch64` too; it links with `rust-lld` rather than the host
> `ld`, which refuses foreign-architecture objects.
>
> Your `kernel_abi=` has to match the running kernel, and the hash is
> derived from the kernel's export table, so it is not something you can
> know when writing the crate. Read it from the target kernel and stamp
> it in at build time:
>
> ```sh
> cat /sys/kernel/abi_hash                       # e.g. 0x1f3a90c2
> cargo xtask build-module --package <your-crate> \
>       --arch x86_64 --kernel-abi 0x1f3a90c2
> ```
>
> The source's own `kernel_abi=` line is a placeholder; `--kernel-abi`
> overwrites it in place.
>
> Production kernels require an Ed25519 signature. Configure their trusted
> raw public keys with the absolute build-time path
> `NARF_MODULE_TRUSTED_KEYS`, one 64-hex-digit key per line. Have the release
> signer sign the exact final raw or compressed module bytes. For a compressed
> production module, build the envelope first and attach the signature second:
>
> ```sh
> cargo xtask build-module --package <your-crate> --arch x86_64 \
>   --kernel-abi 0x1f3a90c2 --compress --out module.ko.lz4
> # Produce module.sig over BLAKE3(module.ko.lz4) with the release signer.
> cargo xtask attach-module-signature --module module.ko.lz4 \
>   --signature module.sig --public-key module.pub
> ```
>
> xtask verifies the detached signature before writing the fixed `NRFM`
> trailer. The signature covers the compressed `NRFCMOD` header and LZ4 bytes,
> so production kernels authenticate before allocating the bounded (32 MiB
> maximum) output buffer or running the decompressor. Unsigned modules are
> accepted only by kernels built with the explicit developer/CI
> `module-allow-unsigned` feature.
>
> Out-of-line `core`, `alloc` and `compiler_builtins` code, and code
> from kernel-free dependency crates, is linked into the `.ko` from the
> staticlib archive: `build-module` offers the archive lazily after
> your crate's own objects and section-GCs the result, so only what
> your code reaches is kept. A module that wants a heap, `async` and
> locks depends on [`narf-module-rt`](./rt) (see
> [Writing against `narf-module-rt`](#writing-against-narf-module-rt)).
> A dependency on a *kernel* crate (`narf-lib`, `narf-bus`, …) still
> fails the `nm -u` gate: its symbols live in the kernel image, not in
> any KSYMTAB.

A NARF module is a stand-alone Cargo crate that builds to a single
relocatable ELF object (`crate-type = "staticlib"`). A minimal
`Cargo.toml`:

```toml
[package]
name = "rtl9999"
version = "0.1.0"
edition = "2024"
license = "GPL-2.0-or-later"

[lib]
name = "rtl9999"
crate-type = ["staticlib"]   # produces .a; we extract the .o

[dependencies]
# None. A module links *against* the kernel — the loader resolves its
# undefined symbols through KSYMTAB — so it declares what it calls in an
# `extern "C"` block and depends on nothing. In particular do NOT depend
# on `narf-modules`: that is the loader, and pulling it in would compile
# a second copy of the memory, filesystem, console and time crates into
# your module, all already resident in the running kernel.
```

Source layout:

```
rtl9999/
  Cargo.toml
  src/
    lib.rs
  modinfo.txt        ← static modinfo k=v lines (see below)
  kparams.txt        ← optional initial parameter values
```

## The `.modinfo` section

The kernel reads metadata from a `.modinfo` ELF section. The
recommended workflow is to write `modinfo.txt` and have your build
script (or a one-line `objcopy` call) inject it into the final
object:

```
# modinfo.txt
name=rtl9999
version=0.1.0
license=GPL-2.0-or-later
author=Some Author
description=RTL9999 vendor driver
target_domain=net
required_caps=DmaBuffer:Write,BusDevice:Write,NetIface:Write
depends=narf-pci,narf-io
kernel_abi=0xCAFEBEEF      # see DESIGN.md §3
```

To inject:

```sh
objcopy --add-section .modinfo=modinfo.txt --set-section-flags \
    .modinfo=alloc,readonly rtl9999.a rtl9999.ko
```

(For Phase 1, a small helper script lives at
`tools/mkmodule.sh`. Production builds will get a Cargo `build.rs`
wrapper that does this automatically.)

The format is one `key=value` per line. Recognised keys:

  * `name=` — module name. Required. Becomes
    `/sys/module/<name>/`. Must be unique among loaded modules.
  * `version=` — semver, free-form. Surfaced in
    `/sys/module/<name>/version`.
  * `license=` — SPDX identifier. Must be GPL-compatible.
  * `author=` — free-form.
  * `description=` — free-form.
  * `target_domain=` — author's default PKS-isolated driver-domain hint.
    The system owner may override it at load with `domain=<name>`; a runtime
    module can never select `FRAME`. Known names: `net`,
    `block`, `graphics`, `input`, `crypto`, `misc`, `scratch`,
    `driver0`..`driver4`. If absent, defaults to `scratch`.
  * `required_caps=` — comma-separated list of `Kind:Right`
    capability specs. The kernel refuses to load if the module
    references a cap-gated export it didn't declare. Example:
    `required_caps=DmaBuffer:Write,BusDevice:Write,NetIface:Write`.
  * `depends=` — comma-separated list of module names this module
    needs loaded first. Phase 1 doesn't auto-load deps; modprobe
    is expected to.
  * `kernel_abi=` — 32-bit hex hash of the kernel's exported ABI
    surface. Get it from `cat /sys/kernel/abi_hash` after boot. It is
    derived from the export table, so it changes when the symbols you
    can call change — not on every kernel rebuild.

## What you can call

A module may call the kernel only through the exported ABI in
`modules/src/kabi.rs`. This is a hand-written surface, not a projection
of the kernel's internal APIs, and the reason is that **Rust has no
stable ABI**: the layout of `&dyn Trait`, of any `repr(Rust)` struct,
and the calling convention itself may all change between compilations
with nothing in the toolchain reporting it. Only `extern "C"` over
primitives and `repr(C)` types can safely cross into a separately
compiled module.

So the surface is small and grows deliberately. Today:

| Symbol | Signature | Notes |
|---|---|---|
| `narf_printk` | `(*const u8, usize) -> i32` | UTF-8 bytes to the console; `-22` on null / empty / invalid UTF-8 |
| `narf_kmalloc` | `(usize, usize) -> *mut u8` | size, align; null on failure or invalid layout |
| `narf_kfree` | `(*mut u8, usize, usize) -> ()` | must repeat the exact size and align |
| `narf_monotonic_ns` | `() -> u64` | monotonic clock |
| `narf_register_pci_driver` | `(*const u8, usize, u16, u16, usize) -> i32` | register a PCI ID and C-ABI probe callback |
| `narf_register_usb_driver` | `(*const u8, usize, u16, u16, u16, u8, u8, u8, usize) -> i32` | name, `match_flags`, vendor, product, interface class/subclass/protocol, probe; flags as Linux `usb_device_id` (1 VID/PID, 2 class, 4 subclass, 8 protocol). Offered only devices no built-in driver claimed; `-ENODEV` without a USB stack |
| `narf_pci_enable` | `(u64, u16) -> i32` | enable command bits on the callback's device |
| `narf_bar_map` | `(u64, u8) -> u64` | map a BAR and return an opaque handle |
| `narf_bar_len` | `(u64, u64, *mut u64) -> i32` | length of a mapped BAR handle |
| `narf_mmio_read32` | `(u64, u64, u64, *mut u32) -> i32` | bounded BAR read |
| `narf_mmio_write32` | `(u64, u64, u64, u32) -> i32` | bounded BAR write |
| `narf_mmio_wait32` | `(u64, u64, u64, u32, u32, u64) -> i32` | responsive masked register wait; 1 ns–1 s |
| `narf_dma_alloc` | `(u64, usize) -> u64` | coherent allocation in the selected domain; requires `DmaBuffer` |
| `narf_dma_addr` | `(u64, u64, u64, *mut u64) -> i32` | device-visible address at a checked offset |
| `narf_dma_write` | `(u64, u64, u64, *const u8, usize) -> i32` | bounded copy into DMA memory |
| `narf_dma_read` | `(u64, u64, u64, *mut u8, usize) -> i32` | bounded copy out of DMA memory |
| `narf_dma_wait8` | `(u64, u64, u64, u8, u8, u64) -> i32` | responsive masked DMA-status wait; 1 ns–1 s |
| `narf_dma_free` | `(u64, u64) -> i32` | revoke and release a DMA handle |
| `narf_dma_alloc_mapped` | `(u64, usize, u32, *mut usize, *mut u64, *mut usize) -> u64` | coherent buffer below `2^addr_bits` (32..=64) **with its CPU mapping**, for drivers whose rings the CPU walks; writes CPU address, device address and reserved length; handle shared with `narf_dma_free`/`narf_dma_addr`; requires `DmaBuffer` |
| `narf_pci_identity` | `(u64, *mut u8, usize) -> i32` | 16-byte LE record: vendor, device, subsystem vendor/device, revision, class, segment, bus, devfn; requires `BusDevice` |
| `narf_msi_enable` | `(u64, u16, *mut u16, *mut u16, *mut u64, *mut u32) -> i32` | exactly `want` (power of two ≤ 32) aligned plain-MSI vectors, delivery left off; writes count, first kernel vector, Message Address and vector 0's Data; `-28` ask for fewer, `-95` no MSI, `-16` MSI/MSI-X already set up; requires `BusDevice` |
| `narf_msi_set_enabled` | `(u64, u32) -> i32` | flip MSI delivery for that block |
| `narf_pcie_aspm` | `(u64, u16, *mut u16) -> i32` | set Link Control's ASPM field (bits 1:0) only; writes the previous field |
| `narf_msix_enable` | `(u64) -> i32` | discover/retain MSI-X; `-95` when unsupported; requires `BusDevice` |
| `narf_msix_claim` | `(u64, *mut u16) -> i32` | allocate/program one kernel IRQ vector |
| `narf_irq_set_handler` | `(u64, u16, usize, u64) -> i32` | attach `extern "C" fn(u64) -> i32`; callback runs in task context |
| `narf_spawn_poller` | `(u64, usize, u64) -> i32` | immediate then 1-ms task-context callback; non-zero return retires it |
| `narf_netif_register` | `(u64, *const u8, usize, *mut u32) -> i32` | register a copy-mode Ethernet interface and TX callback; requires `NetIface` |
| `narf_netif_register_with_context` | `(u64, *const u8, usize, *mut u32) -> i32` | TX callback receives `(dev_token, frame, len)`; use for multiple devices per module; requires `NetIface` |
| `narf_netif_rx` | `(u64, u32, *mut u8, usize) -> i32` | synchronously deliver copied RX bytes to the registered interface |
| `narf_usb_config_descriptor` | `(u64, *mut u8, usize, *mut usize) -> i32` | copy the probed configuration descriptor; `-105` with the required length when short; requires `BusDevice` |
| `narf_usb_configure` | `(u64, *const u8, usize, usize, u64, *mut u64) -> i32` | configure endpoints by address (attributes come from the descriptor); returns a request id |
| `narf_usb_control` | `(u64, *const u8, *const u8, usize, usize, u64, *mut u64) -> i32` | 8-byte SETUP + OUT data (or `len = 0` for IN); `SET_ADDRESS` refused |
| `narf_usb_submit` | `(u64, u8, *const u8, usize, usize, u64, *mut u64) -> i32` | one bulk/interrupt transfer on a configured endpoint; IN passes a null data pointer and its capacity |
| `narf_usb_poll` | `(u64, u64, *mut u8, usize, *mut usize) -> i32` | `-11` pending; `-105` keeps the result; otherwise copies IN data, stores the length, returns the URB status and consumes the id |
| `narf_usb_cancel` | `(u64, u64) -> i32` | request cancellation of a bulk or interrupt-IN request; keep polling |
| `narf_usb_serial_register` | `(u64, u32, usize, u64, *mut u32) -> i32` | publish `/dev/ttyUSB<N>` backed by the device; kick callback on writes |
| `narf_usb_serial_tx` | `(u64, u32, *mut u8, usize, *mut usize) -> i32` | take bytes writers queued on the node |
| `narf_usb_serial_rx` | `(u64, u32, *const u8, usize) -> i32` | deliver received bytes to readers; returns bytes accepted |
| `narf_blk_register` | `(u64, *const u8, usize, *const u64, usize, u64) -> i32` | publish a disk: name, geometry `[block size, capacity, max blocks, flags]`, request callback, cookie |
| `narf_blk_copy_in` | `(u64, u64, u64, u64, usize, usize) -> i32` | inside a write request: copy request bytes into one of the module's DMA buffers |
| `narf_blk_copy_out` | `(u64, u64, u64, u64, usize, usize) -> i32` | inside a read request: copy DMA buffer bytes into the request |
| `narf_blk_fill` | `(u64, u64, usize, *const u8, usize) -> i32` | inside a read request: copy module memory into the request (USB drivers) |
| `narf_blk_fetch` | `(u64, u64, usize, *mut u8, usize) -> i32` | inside a write request: copy request bytes into module memory (USB drivers) |
| `narf_usb_wait` | `(u64, u64, u64) -> i32` | wait up to 1 s for a callback-less bulk/interrupt request, polling it inline |
| `narf_udelay` | `(u64) -> i32` | busy-wait 1 ns–1 s while the kernel sleep pumps keep ticking |
| `narf_random_bytes` | `(*mut u8, usize) -> i32` | ≤ 4096 bytes from the health-tested entropy source; `-11` when none is healthy (output zeroed) |
| `narf_smbios_read` | `(usize, *mut u8, usize, *mut usize) -> i32` | copy the firmware SMBIOS structure table from an offset; writes its total length; `-61` with no table |
| `narf_firmware_signed` | `(u64) -> i32` | 1/0: whether an open firmware handle carries a verified signer; requires `Firmware` |
| `narf_module_param` | `(*const u8, usize, *mut u8, usize, *mut usize) -> i32` | the calling module's parameter value (see [Module parameters](#module-parameters)); `-2` undeclared, `-105` with the needed length |

Declare them as you would any foreign function:

```rust
unsafe extern "C" {
    fn narf_printk(ptr: *const u8, len: usize) -> i32;
    fn narf_monotonic_ns() -> u64;
}
```

DMA exports are link-time cap gated. A dual-build driver using them emits
`required_caps=DmaBuffer:Write` in `.modinfo` (the `narf_driver!` macro accepts
the corresponding optional `required_caps` literal); the loader refuses to
resolve those imports when the declaration is absent. MSI-X, IRQ, and poller
exports likewise require `BusDevice` (for example,
`required_caps=DmaBuffer:Write,BusDevice:Write`). Network registration and RX
require `NetIface`; a driver using the full device path normally declares all
three. The USB datapath exports (`narf_usb_*`) require `BusDevice`. Their
`dev` is the token a USB probe received; every request is submitted, then
optionally reported through a completion callback (task context, the
module's domain) and collected with `narf_usb_poll`. `drivers/usb/ftdi` is the
worked example: a USB-serial driver built entirely from completions. The block
exports (`narf_blk_*`) require `BlockDevice`. A registered disk joins the
block registry (`/dev/<name>`, partitions, filesystems). Each request runs
synchronously: the kernel calls the module's
`extern "C" fn(cookie, request, op, lba, count) -> i32` (op 0 read, 1 write,
2 flush) in the module's domain, one request per disk at a time, split to the
module's `max blocks`. The module moves data only with `narf_blk_copy_in` /
`narf_blk_copy_out` (to and from its own DMA buffers: PCI drivers) or
`narf_blk_fill` / `narf_blk_fetch` (to and from module memory: USB drivers).
The module never sees the caller's buffer. `drivers/nvme` (`module_probe.rs`)
is the PCI worked example, a polled NVMe host; `drivers/usb/storage` is the
USB one, BOT over bulk requests waited with `narf_usb_wait` (callback-less
requests only; it polls the transfer inline, so a synchronous request
callback never depends on another task running). The retained per-device cap is still checked on every invocation; the
manifest declaration only controls whether the imports can link.

IRQ callbacks never run in hard-IRQ context. The FRAME handler accounts and
wakes an in-tree task, which pins the Live module, enters its effective
load-time domain, and then calls the supplied function. A callback returning
non-zero stops its pump. Device teardown removes the binding before module
text is unmapped.

Do not hand-roll register or descriptor-status spin loops in a module. Use
`narf_mmio_wait32` or `narf_dma_wait8`: the in-tree implementation applies a
wall-clock deadline and pumps the scheduler's responsiveness hooks. The TX
callback passed to `narf_netif_register` borrows its frame only until return;
copy or DMA it synchronously. The RX buffer passed to `narf_netif_rx` is also
borrowed synchronously and may be rewritten in place by the stack before the
call returns.

For multiple adapters, use `narf_netif_register_with_context` with an
`extern "C" fn(u64, *const u8, usize) -> i32` callback. Resolve all BARs,
DMA buffers, ring positions and serialization by the supplied device token.
Two cards with identical PCI IDs are separate contexts. The e1000 and IGC
examples retain up to 32 independent contexts per module image and return
`ENOSPC` when their state table fills.

These stay undefined in the object you build; the loader resolves them
against KSYMTAB and patches the call sites. A name the kernel does not
export is a load-time failure reporting that symbol, not a link error
here — your module is linked long before it meets a kernel.

Every export is `unsafe`, including the ones taking no pointers. The
boundary is unsafe as a whole, because nothing has verified your
arguments, and marking only the pointer-taking ones would imply the rest
had been checked.

Safe wrappers may live in your crate or in a kernel-free dependency
crate: `cargo xtask build-module` links out-of-line code from the
crate's dependencies into the `.ko`, so a wrapper in another crate is
resolved inside the module and only the `narf_*` export it calls is
left for KSYMTAB.

Each export carries a CRC computed from its signature. If the kernel's
signature changes, your module is refused at load with a CRC mismatch
rather than being called with the wrong stack layout. You do not have
to do anything to opt into that.

Referencing a symbol that is *not* exported is a load-time failure, not
a link-time one: the relocator reports `SymbolNotFound` naming the
symbol.

## Writing against `narf-module-rt`

[`narf-module-rt`](./rt) is a kernel-free crate built only from
`narf_printk`, `narf_kmalloc`, `narf_kfree` and `narf_monotonic_ns`.
Depending on it gives a module:

| Piece | What it is |
|---|---|
| `heap::KernelHeap` | The module's `#[global_allocator]` (installed for you on the kernel target), so `alloc::{vec, boxed, string, format}` work. |
| `printkln!` | Whole-line console output, split only at UTF-8 boundaries. |
| `sync::SpinLock` | For state shared between concurrent upcalls; its guard is `!Send`. |
| `sync::Mutex` | Async mutex whose guard may be held across `.await`. |
| `time` | `now_ns`, `Deadline`, `sleep_until`/`sleep_ms`, `yield_now`, `spin_ns`. |
| `exec::Executor` | Runs the module's own futures. Keep one in a `static` and call `run()` from every upcall (poller, IRQ vector callbacks, probe). Tasks must be `Send`. |

The kernel never polls a module's futures: a `Future` cannot cross the
KABI. The device poller (`narf_spawn_poller`, every 1 ms) is the
executor's heartbeat; wakers and IRQ callbacks only bring the next pass
forward. Module code always runs in task context, so the locks spin
across CPUs but never mask interrupts.

`modules/rt-smoke` is the reference: it allocates, formats and runs two
futures under an async mutex from `narf_module_init`, and the
`modules/e2e` kernel test loads it on both architectures.

`drivers/wireless/ath11k` is the full-driver example: a whole Wi-Fi driver
that builds both built in and as a `.ko` from one source tree. Its kernel
services sit behind one `platform` module that re-exports the kernel crates
(built in) or `narf-module-rt` plus KABI wrappers (module) under the same
names. Pure protocol crates are linked with their `kernel` feature off.
`modules/e2e/ath11k` loads it.

## Lifecycle symbols

Every NARF module exports two C-ABI symbols the kernel calls:
`narf_module_init` and `narf_module_exit`. You write them directly —
there is no macro, and deliberately so. The plumbing is six lines, and a
macro to hide it would have to live in a crate you depend on, which for
anything but a trivial one means compiling a second copy of kernel code
into your module.

```rust
#![no_std]

/// Called once, after relocations are applied and the image is sealed.
/// Return 0 for success, or a negative errno.
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_init() -> i32 {
    if !hardware_present() {
        return -19;   // -ENODEV
    }
    0
}

/// Called on `rmmod` once the refcount reaches zero. Optional — omit it
/// and the loader treats the module as having nothing to tear down.
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_exit() {
    teardown_everything();
}
```

Returning the errno yourself is the point: a wrapper that mapped a
`Result` onto `0` / `-1` would throw away exactly the distinction
`insmod` reports to the user.

## Declaring capability requirements

A module that calls cap-gated kernel exports must list the cap in
its `required_caps=`. The kernel refuses to link the export
otherwise. Example:

```rust
// In your module:
fn my_init() -> Result<(), &'static str> {
    // This call uses narf_block::register_block_device, which is
    // a cap-gated export requiring `CapKind::BlockDevice`.
    narf_block::register_block_device(/* … */);
    Ok(())
}
```

Your `modinfo.txt` must contain:

```
required_caps=BlockDevice:Write
```

If you forget, the loader rejects the module with:

```
modules: load rejected — required cap BlockDevice missing for
         symbol narf_block_register_block_device
```

## Module parameters

A module declares its parameters, with defaults, in a `.narf_kparams`
section: one `name=value` per line. The simplest way is a `#[used]`
static, which survives `build-module`'s section GC (it is emitted
`SHF_GNU_RETAIN`):

```rust
#[used]
#[link_section = ".narf_kparams"]
static KPARAMS: [u8; 18] = *b"debug=0\nring=4096\n";
```

(or inject a text file with `objcopy --add-section
.narf_kparams=kparams.txt --set-section-flags .narf_kparams=alloc,readonly`
after the build).

At load the kernel parses the section into the module's parameter slots,
then applies, in order:

1. every `<module>.<name>=value` token on the kernel command line, where
   `<module>` is the `.modinfo` `name=` (`ath11k.ssid=lab` sets `ssid`
   for a module named `ath11k`), and
2. the load's own `name=value` arguments (`init_module`'s parameter
   string; `domain=` is the placement option, not a parameter) — so an
   explicit load argument wins, as with Linux `modprobe`.

Values for names the module does not declare are ignored. The result is
mirrored at `/sys/module/<name>/parameters/<p>` (readable and writable).

Inside the module, read the current value with `narf_module_param`
(`-2` for an undeclared name, `-105` with the needed length when the
buffer is short), or through `narf-module-rt`:

```rust
let debug = narf_module_rt::param::get("debug")
    .ok()
    .and_then(|v| v.parse::<u32>().ok())
    .unwrap_or(0);
```

Values are strings; the module parses them. Anything on the kernel
command line is readable by every process through `/proc/cmdline`, so
secrets belong in a load-time argument, not there.

## Loading the module

Once compiled and `objcopy`'d into a `.ko`, load it via the
syscall:

```rust
use narf_modules::syscalls::sys_init_module_with_params;

let bytes: Vec<u8> = std::fs::read("rtl9999.ko").unwrap();
let module = sys_init_module_with_params(&bytes, "domain=driver3").expect("load");
```

Or from userspace via the system call (post-syscall-wiring):

```sh
# The loader-facing equivalent passes `domain=driver3` as the module params.
modprobe rtl9999 domain=driver3
```

Drivers that must register their hardware match before the boot-time device
probe can be staged in the initramfs and selected on the bootloader-supplied
kernel command line:

```text
modules_load=lib/modules/rtl9999.ko modules_domain=driver3
```

`modules_load=` accepts comma-separated archive paths. Autoload runs after the
kernel ABI and trust roots exist but before `Stage::Device`. The optional
`modules_domain=` value is the administrator's placement decision and
overrides each image's `target_domain=` author hint. Runtime-loaded text can
never be placed in `FRAME`; normal signature, ABI-hash, and required-capability
checks still apply.

Use `modules_domains=lib/modules/a.ko=driver2,lib/modules/b.ko=driver3` for
per-image placement; `modules_domain` remains the fallback. A distribution can
put an external Cargo manifest, signing inputs, initramfs path, and placement
in a source-neutral
[`--composition` file](../docs/extending/composition.md), avoiding NARF
workspace edits.

To unload:

```rust
use narf_modules::syscalls::sys_delete_module;
sys_delete_module("rtl9999").expect("unload");
```

Or:

```sh
rmmod rtl9999
```

## A complete "hello world" module

```rust
#![no_std]

extern crate alloc;
use alloc::sync::Arc;

use narf_filesystem::procfs::{register_proc, ProcFile, unregister_proc};

#[derive(Debug)]
struct HelloFile;

impl ProcFile for HelloFile {
    fn read(&self) -> alloc::vec::Vec<u8> {
        b"hello from rtl9999\n".to_vec()
    }
}

fn my_init() -> Result<(), &'static str> {
    register_proc("foo", Arc::new(HelloFile));
    Ok(())
}

fn my_exit() {
    unregister_proc("foo");
}

#[unsafe(no_mangle)]
pub extern "C" fn narf_module_init() -> i32 {
    match my_init() {
        Ok(()) => 0,
        Err(_) => -22,   // -EINVAL
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn narf_module_exit() {
    my_exit()
}
```

With:

```
# modinfo.txt
name=rtl9999
version=0.1.0
license=GPL-2.0-or-later
author=Example
description=Hello world
target_domain=misc
kernel_abi=0x00000000
```

After `modprobe rtl9999`, `cat /proc/foo` prints `hello from
rtl9999`. After `rmmod rtl9999`, `/proc/foo` is gone.

## Reference counting

If your module exposes long-lived handles (open file descriptors,
held capabilities), you must increment the module's refcount when
the handle is acquired and decrement when it's released. The
kernel refuses to unload a module with non-zero refcount.

```rust
use narf_modules::registry;

fn open_handle() {
    if let Some(m) = registry::lookup("rtl9999") {
        m.refcount.get();
    }
}

fn close_handle() {
    if let Some(m) = registry::lookup("rtl9999") {
        m.refcount.put();
    }
}
```

Phase 1 caveat: there's no automatic instrumentation. Authors must
do this by hand. A future `Arc<Module>`-rooted holder type will
make refcount management RAII.

## Reading the manifest at runtime

```rust
if let Some(m) = narf_modules::registry::lookup("rtl9999") {
    let v = &m.manifest.version;
    // …
}
```

## Lifecycle errors

`init` returning a non-zero value:

  * `-19` — `ENODEV`, device not present. The kernel logs but
    doesn't taint.
  * `-22` — `EINVAL`, generic bad-arg.
  * Any other negative value is surfaced verbatim in the kernel
    log + syscall return.

`exit` returning is mandatory once `rmmod` is in progress —
there's no way to refuse from inside `exit`. To refuse unload,
keep the refcount non-zero.

`rmmod` itself answers `-EBUSY`, changing nothing, while:

  * the module's `init` is still running;
  * another unload of it is already in progress;
  * any kernel callback is inside the module's text (a probe, poller, IRQ
    or USB completion, netif TX, block request). Every callback pins the
    module for its duration automatically; you do not take references
    for them.

Once `rmmod` succeeds no callback is running and none can start: `exit`
runs exactly once, then the kernel withdraws your matches, device
contexts, disks and interfaces before unmapping the image.

## Differences vs Linux `.ko`

| Aspect | Linux | NARF |
|---|---|---|
| Manifest format | NUL-separated k=v in `.modinfo` | Same |
| Lifecycle ABI | `init_module()` / `cleanup_module()` C symbols | `narf_module_init` / `narf_module_exit` |
| Cap requirements | `EXPORT_SYMBOL_GPL` ± LSM hooks | Per-symbol `required_cap` + manifest declare |
| Isolation | None (driver in TCB) | PKS/MTE per-domain |
| ABI versioning | per-symbol CRC + `vermagic` | per-symbol CRC + per-kernel `kernel_abi` hash |
| Signature | Linux-signing-keys / PKCS#7 | `sign::ModuleVerifier` (Phase 1 no-op; Ed25519 pending) |
| Parameters | `module_param!` macro | `.narf_kparams` section + `params::find` |

## Diagnostics

  * `/proc/modules` — one-line summary per loaded module.
  * `/sys/module/<name>/` — per-module attributes
    (`name`, `version`, `refcnt`, `taint`, `initstate`, `size`,
    `parameters/<p>`, `sections/<sec>`).
  * `/sys/kernel/abi_hash` (planned) — the kernel ABI hash a
    module's `kernel_abi=` must match.

## Live DMA rings and unload

Set `narf_dma_retain_on_teardown(dev, 1)` before exposing DMA addresses to a
controller. In `narf_module_exit`, stop engines and interrupts and wait for the
controller's documented master-request drain. Clear retention with value 0
only when that fence succeeds. On failure, leave retention set: the kernel
withdraws the device and quarantines its DMA allocations after unload.
`drivers/net/igc/src/module_probe.rs` implements this pattern using the shared
I225/I226 protocol. Clearing PCI Bus Master alone does not prove completion.
