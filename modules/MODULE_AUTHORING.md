# Writing a NARF kernel module

This guide is for authors of out-of-tree NARF kernel modules. For
the design rationale, see [DESIGN.md](./DESIGN.md). For the
architecture-comparison overview, see the workspace-root
`COMPARISON.md`.

## Project layout

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
# Modules link against the kernel's exported symbols via narf-modules.
# In-tree manifests add a path; out-of-tree crates use the synchronized
# version published on crates.io.
narf-modules = "0.1.0"
narf-capabilities = "0.1.0"
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
required_caps=NetIface:Write,DmaBuffer:Invoke
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
  * `target_domain=` — name of the PKS-isolated driver domain
    where the module's text + data land. Known names: `net`,
    `block`, `graphics`, `input`, `crypto`, `misc`, `scratch`,
    `driver0`..`driver5`. If absent, defaults to `scratch`.
  * `required_caps=` — comma-separated list of `Kind:Right`
    capability specs. The kernel refuses to load if the module
    references a cap-gated export it didn't declare. Example:
    `required_caps=NetIface:Write,DmaBuffer:Invoke`.
  * `depends=` — comma-separated list of module names this module
    needs loaded first. Phase 1 doesn't auto-load deps; modprobe
    is expected to.
  * `kernel_abi=` — 32-bit hex hash of the running kernel build.
    Get it from `cat /sys/kernel/abi_hash` after boot.

## The `narf_module!` macro

Every NARF module exports two C-ABI symbols the kernel calls:
`narf_module_init` and `narf_module_exit`. The recommended way is
the `narf_module!` macro, which hides the unsafe `extern "C"`
plumbing:

```rust
#![no_std]
extern crate alloc;

use core::result::Result;

fn my_init() -> Result<(), &'static str> {
    // ... register devices, install pump tasks, etc.
    Ok(())
}

fn my_exit() {
    // ... tear down, drop resources, unregister.
}

narf_modules::narf_module! {
    name: "rtl9999",
    init: my_init,
    exit: my_exit,
}
```

The macro expands to:

```rust
#[no_mangle]
pub extern "C" fn narf_module_init() -> i32 {
    match my_init() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn narf_module_exit() {
    my_exit()
}
```

You can write the C-ABI symbols directly if you need finer
control over the i32 return value:

```rust
#[no_mangle]
pub extern "C" fn narf_module_init() -> i32 {
    if !hardware_present() {
        return -19;   // -ENODEV
    }
    0
}

#[no_mangle]
pub extern "C" fn narf_module_exit() {
    teardown_everything();
}
```

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

A module that wants tunable parameters writes a `.narf_kparams`
section. The simplest way is a sibling text file injected via
`objcopy`:

```
# kparams.txt
debug=0
ring_size=4096
```

Then:

```sh
objcopy --add-section .narf_kparams=kparams.txt --set-section-flags \
    .narf_kparams=alloc,readonly rtl9999.ko
```

At load time the kernel parses the section, populates the module's
parameter slots, and creates `/sys/module/<name>/parameters/<p>`
for each. Both reads and writes are supported.

Inside your module, read the current value:

```rust
fn my_init() -> Result<(), &'static str> {
    if let Some(val) = narf_modules::params::find(
        /* &self.params slice */,
        "debug",
    ) {
        let raw = val.read();
        // raw is the current text value; parse it.
    }
    Ok(())
}
```

Phase 1 caveat: parameters are stored as strings; the module is
responsible for parsing. A future `narf_module_param!(debug: u32)`
macro will plumb the typed accessor.

## Loading the module

Once compiled and `objcopy`'d into a `.ko`, load it via the
syscall:

```rust
use narf_modules::syscalls::sys_init_module;

let bytes: Vec<u8> = std::fs::read("rtl9999.ko").unwrap();
let module = sys_init_module(&bytes).expect("load");
```

Or from userspace via the system call (post-syscall-wiring):

```sh
# Once `narf-libc` ships the `init_module` wrapper:
modprobe rtl9999
```

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

narf_modules::narf_module! {
    name: "rtl9999",
    init: my_init,
    exit: my_exit,
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
