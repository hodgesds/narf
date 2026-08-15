# Adding a syscall handler

Files: `userspace/src/syscall.rs` (table + ABI), `userspace/src/handlers.rs`
(the handlers + the install site).

The syscall table is a global, lock-free `SyscallTable`. Handlers are
installed with the public `install_raw`. You *can* add a handler without
editing a core crate **if** the syscall already has a `Syscall` enum variant
(or you use a NARF-extension slot). You **cannot** add a *new Linux wire
number* without editing `userspace/src/syscall.rs` — see the gotchas.

## The table

`userspace/src/syscall.rs:3609`

```rust
pub struct SyscallTable {
    handlers: Vec<Option<Box<dyn SyscallHandler>>>,
    versioned_handlers: Vec<(Syscall, u8, Box<dyn SyscallHandler>)>,
    names: Vec<(Syscall, &'static str)>,
}
```

Stored as a single global `AtomicPtr` (not per-CPU) and published once:

```rust
// userspace/src/syscall.rs:3595
static GLOBAL_TABLE: AtomicPtr<SyscallTable> = AtomicPtr::new(core::ptr::null_mut());
// userspace/src/syscall.rs:3598
pub fn install_global(table: SyscallTable);   // Box::into_raw + Release store
```

## Registering a handler: `install_raw`

`userspace/src/syscall.rs:3669`

```rust
pub fn install_raw<H: SyscallHandler + 'static>(
    &mut self,
    variant: Syscall,
    name: &'static str,
    handler: H,
);
```

`install_raw` is **`pub`** — any code with `&mut SyscallTable` during table
assembly can register a handler. The handler is anything implementing
`SyscallHandler`; the ergonomic wrapper is `RawFnHandler`:

```rust
// userspace/src/syscall.rs:3744 — NOT a type alias; a generic newtype.
pub struct RawFnHandler<F>(pub F);

impl<F> SyscallHandler for RawFnHandler<F>
where F: Fn(&mut dyn TrapContext) + Send + Sync + 'static {
    fn handle(&self, ctx: &mut dyn TrapContext) { (self.0)(ctx); }
}
```

So a handler is just a `fn(&mut dyn TrapContext)`. The in-tree install site
(`userspace/src/handlers.rs:20902`) is a long list of exactly this shape:

```rust
table.install_raw(Syscall::Read,  "read",  RawFnHandler(sys_read));
table.install_raw(Syscall::Write, "write", RawFnHandler(sys_write));
table.install_raw(Syscall::Close, "close", RawFnHandler(sys_close));
// … ~50 more …
```

## The `TrapContext` ABI

A handler receives `&mut dyn TrapContext` — the trait that abstracts the saved
CPU state across arches.

`userspace/src/syscall.rs:44`

```rust
pub trait TrapContext {
    fn args(&self) -> &SyscallArgs;                  // required — user register args
    fn set_return(&mut self, ret: SyscallReturn);    // required — write the result
    fn user_rsp(&self) -> u64;                        // required
    fn rip(&self) -> u64;                             // required
    fn set_rip(&mut self, rip: u64);                  // required
    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool; // required
    // defaults (false / no-op) for exotic paths:
    fn redirect_to_user(&mut self, _rip: u64, _rsp: u64) -> bool { false }        // :70
    unsafe fn save_user_state(&self, _out: *mut u8) -> bool { false }             // :84
    fn returning_to_user(&self) -> bool { false }                                 // :89
    fn deliver_signal(&mut self, _p: &SigDeliveryParams) -> bool { false }        // :96
    fn perform_sigreturn(&mut self, _sc: u64, _rt: bool) -> bool { false }        // :105
}
```

A normal handler only touches `args()` and `set_return()`. The concrete
implementor is `UserStateCtx<'a>` (`:111`), which wraps a
`&mut narf_scheduler::UserState`.

```rust
// userspace/src/syscall.rs:3521
#[repr(C)]
pub struct SyscallArgs { pub arg0: u64, pub arg1: u64, pub arg2: u64,
                         pub arg3: u64, pub arg4: u64, pub arg5: u64 }
```

### `SyscallReturn` — field order is load-bearing

`userspace/src/syscall.rs:3537`

```rust
#[repr(C)]
pub struct SyscallReturn {
    pub value: u64,               // offset 0 → RAX (x86_64) / X0 (aarch64)
    pub status: abi::NarfStatus,  // offset 8 → RDX (x86_64) / X1 (aarch64)
}
```

The order is an ABI contract with the hand-written `syscall`-instruction
return asm in `frame/src/x86_64/syscall.rs`, which reads RAX/RDX directly.
The comment at `syscall.rs:3572` spells it out, and a `const _` block
(`:3584`) statically asserts `offset_of(value)==0`, `offset_of(status)==8`,
`size==16` — reordering the fields fails the build. **Never reorder these
fields or grow `status` past 8 bytes.** Constructors: `SyscallReturn::ok(v)`
(`:3546`), `SyscallReturn::invalid_op()` (`:3552`).

## Dispatch flow

`userspace/src/syscall.rs:2955`

```rust
pub fn kernel_syscall_entry(num: u32, ctx: &mut dyn TrapContext) {
    // load GLOBAL_TABLE (Acquire); null ⇒ invalid_op
    // decode version + raw number from `num`
    if let Some(variant) = Syscall::from_raw(raw_n) {   // wire number → enum
        table.dispatch_ctx_versioned(variant, version, ctx);
    } else {
        ctx.set_return(SyscallReturn::invalid_op());     // unmapped wire number
    }
}
```

`dispatch_ctx_versioned` (`:3715`) casts `variant as usize`, indexes
`handlers[idx]`, and calls `handler.handle(ctx)`; a missing slot returns
`SyscallReturn::invalid_op()`.

## The `Syscall` enum and the wire tables

`userspace/src/syscall.rs:297`

```rust
#[non_exhaustive] #[repr(u32)]
pub enum Syscall { Submit, Bootstrap, /* … 100+ variants … */ }
```

Two const tables map variants ↔ wire numbers:

- **`LINUX_TABLE`** — per-arch, maps `Syscall` variants to Linux wire numbers.
  x86_64 table at `:2184`, aarch64 at `:2537`.
- **`NARF_EXTENSION_TABLE`** — arch-independent NARF-native syscalls in the
  `0x4000..=0x40FF` range (`:2843`), e.g. `(Syscall::ShmemCreate, 0x4020)`.

Lookup is `Syscall::from_raw(n) -> Option<Self>` (`:2926`) and
`Syscall::raw(self) -> u32` (`:2904`), both `const fn` linear scans over the
two tables; an unwired variant reports `u32::MAX` from `raw()`.

## Worked example: a handler on an existing variant (no core edit)

If the `Syscall` variant already exists, your crate only needs to install a
handler during table assembly:

```rust
use narf_userspace::syscall::{RawFnHandler, Syscall, SyscallReturn, SyscallTable, TrapContext};

fn sys_my_thing(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let result = do_work(a.arg0, a.arg1);      // your logic
    ctx.set_return(SyscallReturn::ok(result)); // value → RAX/X0, status Ok → RDX/X1
}

// During the kernel's table-assembly phase (where handlers.rs:20902 lives),
// with the &mut SyscallTable in hand:
pub fn install(table: &mut SyscallTable) {
    table.install_raw(Syscall::SomeExistingVariant, "my_thing", RawFnHandler(sys_my_thing));
}
```

> Confirm the exact re-export path (`narf_userspace::syscall::…`) against
> `userspace/src/lib.rs`; the module is `syscall` inside the `narf-userspace`
> crate.

## Gotchas

### The cfg-gating trap ⚠️

A `Syscall` variant can exist in the enum yet be **unreachable** because its
`LINUX_TABLE` row is `#[cfg]`-gated off. Real examples:

```
userspace/src/syscall.rs:2430  #[cfg(feature = "linux-compat")]  (Syscall::Chroot, 161)   // x86_64
userspace/src/syscall.rs:2432  #[cfg(all(feature="linux-compat", feature="container"))] (Syscall::PivotRoot, 155)
userspace/src/syscall.rs:2555  #[cfg(all(feature="linux-compat", feature="container"))] (Syscall::PivotRoot, 41)  // aarch64
userspace/src/syscall.rs:2557  #[cfg(feature = "linux-compat")]  (Syscall::Chroot, 51)
```

When the feature is **off**, that wire-number row is absent, so
`Syscall::from_raw(161)` returns `None` and `kernel_syscall_entry` replies
`invalid_op` — **even if you installed a handler for `Syscall::Chroot`.** The
handler is never reached because dispatch is keyed off the wire→variant
lookup, which failed first. If your handler is silently ENOSYS, check whether
the variant's `LINUX_TABLE` row is cfg-gated and whether that feature is
enabled in the boot build. (This exact class of bug is recorded in the
project memory as the "syscall-table cfg-gating" pitfall.)

### Adding a *new Linux wire number* requires editing core ❌

`LINUX_TABLE` and the `Syscall` enum are compile-time const arrays / enum in
`userspace/src/syscall.rs`. To wire a brand-new Linux syscall number you must
(a) add a `Syscall` variant and (b) add the `(variant, wire_number)` row to
the per-arch `LINUX_TABLE`. There is no runtime `register_wire_number`.
**Signal for the parent:** the handler-install path is open (`install_raw` is
`pub`), but the wire-number↔variant mapping is closed. A NARF-native syscall
can be added in the `NARF_EXTENSION_TABLE` `0x4000..` range with the same
edit; a Linux-numbered one likewise. Both edit `syscall.rs`.

### `install_raw` needs `&mut SyscallTable` at assembly time

The table is built, populated, then `install_global`-published once. Your
handler must be installed during that assembly window (the code around
`handlers.rs:20902`), not after publication — the published table is behind an
`AtomicPtr` and isn't mutated in place. In practice this means hooking the
boot table-assembly path, so a fully out-of-tree handler still needs a call
site in the assembly sequence.

### Handler contract

- Read args from `ctx.args()` (`arg0..arg5`).
- Always call `ctx.set_return(...)` before returning; a handler that returns
  without setting a value leaves stale registers.
- `value` → RAX/X0, `status` → RDX/X1. Encode errno-style failures in the
  handler per the existing handlers' convention (negative values / status).
- Handlers run in the syscall path. When dispatching to `FileOps`/`DirOps`,
  follow the lock-ordering rule from [filesystem.md](filesystem.md): clone the
  object and handle state under the fd-table lock, release it, then invoke the
  filesystem callback.
