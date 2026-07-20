# Capabilities & security

Crates: `narf-capabilities` (`capabilities/`), `narf-security` (`security/`).
`security-model/` is spec-only (no `src/`).

Capabilities are the substrate every other extension seam gates on — the
`&Cap<…, Grant>` you pass to `install_scheduler`, `install_pager`,
`mount_arc`, and friends. This doc covers the `Cap<T, Rights>` model, how
authority is minted and checked, how a subsystem defines a **new
capability-guarded resource**, and the `narf-security` helpers (leak
detection, pointer redaction, posture).

## The `Cap<T, R>` model

`capabilities/src/lib.rs:227`

```rust
pub struct Cap<T, R: Rights> {
    slot: CapSlot,
    _tag: PhantomData<T>,     // T: CapType — which resource kind
    _right: PhantomData<R>,   // R: Rights  — which rights
}
```

- **`T`** is a resource-type marker implementing `CapType` (below). It exists
  only at the type level — zero runtime cost.
- **`R`** is a rights marker implementing `Rights`. Rights form a lattice.

### Rights

`capabilities/src/lib.rs:29`

```rust
pub trait Rights: Sealed + 'static { const BITS: u32; }
```

Five concrete rights (each a zero-size marker with a `BITS` constant):

| Right | `BITS` | Line |
| --- | --- | --- |
| `Read` | `0b0_0001` | `:36` / `:79` |
| `Write` | `0b0_0010` | `:40` / `:82` |
| `Grant` | `0b0_0100` | `:46` / `:85` |
| `Spend` | `0b0_1000` | `:53` / `:88` |
| `Invoke` | `0b1_0000` | `:69` / `:91` |

`Grant` is the "authority to install / mount / hand out" right — that's why
every `install_*` and `mount` takes `&Cap<…, Grant>`.

### The lattice: `SubsetOf`

`capabilities/src/lib.rs:95`

```rust
pub trait SubsetOf<R: Rights>: Rights {}
```

Weakening relations (`:97`–`:121`): reflexive `R: SubsetOf<R>`; `Grant` ⊃
{`Read`,`Write`,`Spend`,`Invoke`}; `Write` ⊃ `Read`; `Invoke` ⊃ `Read`;
`Spend` ⊃ `Read`. This is enforced **at compile time** on `derive` — you can
only ever move *down* the lattice, never up.

### Minting, checking, deriving, revoking

```rust
// capabilities/src/lib.rs:297 — the ONLY safe way to mint from nothing.
pub fn bootstrap() -> Self;   // on Cap<T: CapType, R: Rights>

// capabilities/src/lib.rs:258 — epoch validity check (hot path)
pub fn check_live(&self) -> Result<(), CapError>;

// capabilities/src/lib.rs:272 — checked dispatch of a CapOp
pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError>;

// capabilities/src/lib.rs:285 — derive a WEAKER cap (SubsetOf enforced)
pub fn derive<R2: Rights + SubsetOf<R>>(&self) -> Result<Cap<T, R2>, CapError>;

// capabilities/src/lib.rs:280 — O(1) mass revocation via epoch bump
pub fn revoke(self);

// capabilities/src/lib.rs:239 — raw constructor; TCB-only, UNSAFE
pub const unsafe fn mint(slot: CapSlot) -> Self;
```

`bootstrap()` allocates a fresh object-table entry keyed by `T::KIND` and
stamps `R::BITS` — it is the root-authority path (a TCB responsibility, though
the function itself is safe). `revoke()` bumps the object's epoch; every cap
sharing that object index then observes `CapError::Revoked` on its next
`check_live()`.

### Supporting types

```rust
// capabilities/src/lib.rs:129 — 128-bit runtime slot
#[repr(C, align(16))]
pub struct CapSlot { pub generation: u32, pub index: u32, pub rights: u32, pub type_tag: u32 }

// capabilities/src/lib.rs:511 — resource-type marker (implement this!)
pub trait CapType: 'static { const KIND: CapKind; }

// capabilities/src/lib.rs:320 — capability-guarded operation
pub trait CapOp<T, R: Rights>: Sized {
    type Output;
    fn execute(self, cap: &Cap<T, R>) -> Result<Self::Output, CapError>;
}

// capabilities/src/lib.rs:617
pub enum CapError { Revoked, DomainMismatch, TypeMismatch, RightsTooWeak }

// capabilities/src/lib.rs:381 — the resource-kind registry (~60 variants)
#[non_exhaustive] #[repr(u32)]
pub enum CapKind {
    BusDevice = 0x0001, BlockDevice = 0x0010, NetIface = 0x0020,
    FileNode = 0x0030, Ring = 0x0040, Domain = 0x0050, Probe = 0x0060,
    Key = 0x0070, Task = 0x0080, Process = 0x00A0, /* … ~50 more … */
}
```

## Defining a new capability-guarded resource

This is the core "extend from your own crate" story for capabilities. Two
cases:

### Case A — an existing `CapKind` fits ✅ no core edit

Implement `CapType` on your marker type, reusing a suitable `CapKind`:

```rust
#![no_std]
use narf_capabilities::{Cap, CapKind, CapType, CapOp, CapError, Read, Write};

pub struct MyDevice;                         // resource-type marker (ZST)
impl CapType for MyDevice {
    const KIND: CapKind = CapKind::BusDevice; // reuse an existing kind
}

// Root authority (TCB boot path hands you one, or you bootstrap in a test):
// let root: Cap<MyDevice, Write> = Cap::<MyDevice, Write>::bootstrap();

// Derive a weaker read-only cap for handing out:
// let ro: Cap<MyDevice, Read> = root.derive::<Read>()?;

// A capability-guarded operation:
pub struct Poke(pub u32);
impl CapOp<MyDevice, Write> for Poke {
    type Output = ();
    fn execute(self, cap: &Cap<MyDevice, Write>) -> Result<(), CapError> {
        cap.check_live()?;         // authority still valid?
        // …perform the privileged poke…
        Ok(())
    }
}
// let out = root.invoke(Poke(0x1234))?;
```

The pattern the other subsystems follow (`FrameAlloc`'s `MemAlloc`,
`Scheduler`'s `SchedPolicy`, `Ring`'s `CapKind::Ring`) is exactly this:
declare a marker `struct`, `impl CapType` with a `KIND`, and gate operations
behind `&Cap<Marker, Right>`.

### Case B — you need a brand-new `CapKind` ❌ requires core edit

`CapKind` is a `#[non_exhaustive] #[repr(u32)]` enum in
`capabilities/src/lib.rs:381`. Adding a genuinely new kind (a value that
doesn't overlap any existing subsystem) means **editing that enum** — there is
no runtime `register_cap_kind`. **Signal for the parent:** third parties can
guard resources by reusing an existing `CapKind`, but a *new* kind needs a
one-line addition to the core enum. Per [`../PLUGGABILITY.md`](../PLUGGABILITY.md),
markers for pluggable backends are conventionally allotted the `0x0200..`
range.

## `narf-security` helpers

`security/src/lib.rs` re-exports three tools built on top of caps. This crate
is `#![no_std]` and pulls in **no `alloc`** — nothing here allocates.

### Capability-leak detection (debug-only)

`security/src/cap_leak.rs`

```rust
pub fn assert_no_cap_leak() -> Result<(), CapLeakError>;   // :69
pub enum CapLeakError {                                     // :31
    WriteCapCrossedDomain { from: u8, to: u8, cap_tag: u32 },
    AwaitCrossedDomain { tag: u32 },
}
```

Debug builds assert that no `Cap<_, Write>` was held across an `.await` that
resumed in a *different* domain (a capability-leak class of bug). Release
builds compile it to `Ok(())`. Track caps around await points with the debug
hooks `debug_acquire_write` (`:87`), `debug_release_write` (`:93`),
`debug_domain_transition` (`:99`).

### Pointer redaction

`security/src/redact.rs`

```rust
pub const fn kernel_va_cutoff() -> u64;      // :25 — arch-specific kernel-VA floor
pub fn redact_pointer(addr: u64) -> Redact;  // :45 — returns a formatter
pub struct Redact { /* addr */ }             // :51 — Display/Debug/LowerHex redact kernel VAs
```

Use `redact_pointer(addr)` instead of printing raw addresses in diagnostics:
kernel-VA pointers (≥ `kernel_va_cutoff()`) format as `"*"` unless the reader
holds a debug capability; user pointers pass through. `Redact::reveal()`
(`:69`) is the accessor for a proven reader.

### Posture report

`security/src/posture.rs`

```rust
pub enum Posture { Native, Isolate }         // :17 — KPTI policy
pub struct PostureReport {                    // :47 — boot-time hardening snapshot
    pub smep, smap, cet_shstk, cet_ibt, pac_addr, pac_generic, mte: AtomicBool,
    pub kpti: AtomicU8, pub kaslr, canary, w_xor_x, ro_after_init: AtomicBool,
}
pub static REPORT: PostureReport = PostureReport::new();  // :108
```

`REPORT` is the single global snapshot the boot path fills in. Query
`REPORT.floors_live()` (`:83`) to confirm the mandatory hardening floors
(SMEP, SMAP, W^X, canary, KASLR) are active, or `extras_count()` (`:93`) for
optional HW features (CET, PAC, MTE). A subsystem that adds a hardening knob
sets its field here at boot.

## Gotchas

- **`bootstrap()` is your only mint-from-nothing.** Everything else derives
  (weaker) from an existing cap. In real boot flow you receive a cap from the
  TCB rather than bootstrapping your own; `bootstrap()` in production is a TCB
  responsibility. Tests bootstrap freely.
- **`derive` only weakens.** `SubsetOf<R>` is a compile-time bound; upgrading
  rights won't compile. Good — that's the point.
- **`check_live()` on every privileged op.** The type proves you *were*
  granted; `check_live()` proves the grant *still holds* (not revoked). Both
  are needed. `invoke()` does the check for you.
- **New `CapKind` = core edit.** Reusing an existing kind is free; a new kind
  edits `capabilities/src/lib.rs`.
- **`narf-security` is alloc-free.** Don't reach for `Box`/`Vec` in code that
  links only against `narf-security`.
