# External kernel composition

NARF can build crates from outside its checkout into a kernel image without
adding them to the repository workspace or editing `frame/Cargo.toml`. Pass a
composition file to any command that accepts the common build options:

```sh
cargo xtask build --arch x86_64 --composition /etc/narf/acme.toml
cargo xtask run  --arch x86_64 --composition ../acme/narf.toml
cargo xtask image --arch x86_64 --composition ../acme/narf.toml
```

Paths in the file are relative to the file, not the NARF checkout. Generated
manifests, registrars, module images, and lockfiles live below
`target/narf-compositions/<hash>/`; the NARF and external source trees are not
modified.

## Manifest format

```toml
version = 1
# Development only. Production module entries should provide signature and
# public_key instead.
allow_unsigned_modules = false

[[component]]
manifest = "../acme-net/Cargo.toml"
package = "acme-net"             # optional unless the manifest is ambiguous
mode = "builtin"
features = ["narf"]              # optional
default_features = true           # default for built-ins
entry = "register"               # optional Rust path within the crate
stage = "subsys"                 # early/core/postcore/arch/subsys/fs/device/late
domain = "driver2"               # optional compile-time DomainId argument

[[component]]
manifest = "../acme-storage/Cargo.toml"
mode = "module"
features = ["module"]            # this is the module default
default_features = false          # this is the module default
domain = "driver3"               # load-time placement, never FRAME
autoload = true                   # default; stage and boot automatically
compress = true
signature = "keys/acme-storage.sig"
public_key = "keys/acme-storage.pub"
```

Unknown fields, duplicate package/mode selections, invalid stages or domains,
and unsigned modules without explicit development policy are errors.

## Built-in contract

A built-in is compiled in the same Cargo graph as `narf-frame`, so Cargo
unifies its NARF dependencies and rustc links it directly into the kernel. The
crate must be `no_std` and expose the selected `entry` (default `register`). If
no `domain` is present, the entry has this shape:

```rust
pub fn register() { /* publish drivers or services */ }
```

With `domain = "driver2"`, the domain is part of the image and cannot be
changed at runtime; the entry instead receives it explicitly:

```rust
pub fn register(domain: narf_lib::id::DomainId) { /* retain as static policy */ }
```

`xtask` generates an initcall at the requested stage. This removes the former
kernel-side dependency and retention line, but it does not make internal Rust
APIs stable. The external crate must track the source/API version of NARF it is
built against. Because built-ins execute privileged Rust in the kernel graph,
distributions must review them as part of the kernel image.

The entry is the initcall body, not a function that registers another initcall.
In particular, do not point it at a conventional `register_initcalls()` that
adds work to the same stage after that stage's snapshot has begun. Expose a
small direct `register()` wrapper around the bus/subsystem registration
instead.

Treat every selected Cargo package as trusted build input: Cargo may execute
its `build.rs` on the host, and built-in machine code becomes part of the
kernel image. Composition is source-tree isolation and reproducible selection,
not a sandbox for an untrusted crate.

## Module contract

A module remains a separately linked `.ko` and may use only the stable C KABI;
see [Building and loading runtime modules](modules.md). `xtask` builds it from
its own manifest, stamps the selected kernel's ABI hash, optionally compresses
and signs it, stages it in the initramfs for `run`/x86_64 `image`, and adds the
boot arguments needed to autoload it. Per-module placement is encoded as:

```text
modules_load=lib/modules/acme_storage.ko.lz4 \
modules_domains=lib/modules/acme_storage.ko.lz4=driver3
```

The older `modules_domain=<name>` remains a fallback for modules without a
per-path mapping. Runtime placement is an administrator decision and the
loader still rejects `FRAME`.

For every signed component, `public_key` is both the raw 32-byte Ed25519 key
used to validate the detached signature during the build and a kernel trust
anchor. `xtask` writes the selected keys to a generated trust-store file and
builds the kernel with it. If `NARF_MODULE_TRUSTED_KEYS` already names an
absolute distribution trust-store file, those keys are retained and the
composition keys are added. The detached signature must cover BLAKE3 of the
final ABI-stamped bytes (or the compressed envelope when `compress = true`).

The aarch64 direct-QEMU path carries composed modules. The current aarch64
UEFI image has no initramfs handoff, so `xtask image --arch aarch64` rejects a
composition containing modules instead of silently dropping them; built-ins
are supported.

## One-off development flags

For a quick local build, repeat `--builtin-crate <manifest-or-directory>` or
`--module-crate <manifest-or-directory>`. One-off modules are unsigned, so
they also require `--allow-unsigned-modules`. Use a composition file when you
need a package selector, features, stage, domain, compression, signatures, or
reproducible distribution policy.

`build-module` also accepts `--manifest-path /path/to/Cargo.toml` for manual
two-step module builds.
