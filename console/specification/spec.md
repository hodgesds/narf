# console — Specification

> Status: **v1.0** (Stage 1 design lock). v0.2 specified the
> MMU-enable handoff; v1.0 locks the structured-log format,
> virtio-console redirection, and ABI versioning.

## 1. Purpose & scope

**Owns:** Early-boot serial output, panic sink, structured log-record
format. Later: kernel-facing `log` / `tracing` integration.

**Does NOT own:** Any user-visible shell or terminal; that's userspace.

## 2. Assumptions

- `boot/` passed us the serial base address (or we use a per-arch default).
- Output is best-effort; locking is coarse (a single global spinlock is
  fine for Stage 1).

## 3. Public interface

```rust
/// Called by `boot/` before the MMU is on. `base` is the physical
/// address of the UART MMIO register block (or a port number on x86_64
/// for legacy 0x3F8 UART).
pub fn early_init(base: PhysAddr, uart: UartKind);

/// Called by `memory/` during MMU bring-up, *after* it has mapped
/// the UART's physical range into the kernel virtual address space
/// but *before* the final `CR3` write (x86_64) or `SCTLR_EL1.M=1`
/// (aarch64) that commits the new mapping as the sole translation.
///
/// Atomically swaps the console's base pointer from `PhysAddr` to
/// `VirtAddr` and flips an internal flag. After this call, `write_str`
/// uses the virtual mapping; before it, the physical one. Callers
/// MUST invoke this inside the MMU-bringup critical section — an
/// intervening `write_str` between "MMU on" and "base swapped" will
/// fault on the now-unmapped physical address.
pub fn remap_to_virtual(virt: VirtAddr);

pub fn write_str(s: &str);
pub fn write_str_level(level: u32, s: &str);
/// Physical console only (UART + FB hook); never enters the log store.
pub fn write_str_console_only(s: &str);
pub fn write_str_console_only_level(level: u32, s: &str);
pub struct Writer;              // fmt adapter → write_str
pub struct PriorityWriter<const LEVEL: u32>; // → write_str_level
pub struct ConsoleOnlyWriter;   // → write_str_console_only
pub fn panic_sink(info: &PanicInfo) -> !;
pub fn trap_sink(s: &str);
#[macro_export] macro_rules! klog { (...) => { ... } }

// Kernel log store (`console::klog`) — Linux printk ringbuffer semantics.
pub const LOG_BUF_SHIFT: u32 = 17;            // CONFIG_LOG_BUF_SHIFT default
pub const DEFAULT_LOG_BUF_LEN: usize = 1 << 17;
pub const PRINTKRB_RECORD_MAX: usize = 1024;  // record incl. NUL
pub const PRINTK_MESSAGE_MAX: usize = 2048;   // rendered record
pub const LOG_KERN: u8 = 0; pub const LOG_USER: u8 = 1;
pub const LOG_NEWLINE: u8 = 2; pub const LOG_CONT: u8 = 8;
pub enum KmsgRead { Record(usize), Empty, Dropped, TooSmall }
pub fn klog::record(s: &str);                      // DEFAULT_MESSAGE_LOGLEVEL
pub fn klog::record_level(level: u32, s: &str);
pub fn klog::emit(facility: u8, level: u8, text: &[u8]); // /dev/kmsg write
pub fn klog::first_seq() -> u64; pub fn klog::next_seq() -> u64;
pub fn klog::clear_seq() -> u64; pub fn klog::log_buf_len() -> usize;
pub fn klog::kmsg_read(cursor: &mut u64, out: &mut [u8]) -> KmsgRead;
pub fn klog::kmsg_poll(cursor: u64) -> Option<bool /* vanished */>;
pub fn klog::syslog_read(out: &mut [u8]) -> usize;
pub fn klog::syslog_read_all(out: &mut [u8], clear: bool) -> usize;
pub fn klog::syslog_all_size() -> usize;
pub fn klog::syslog_size_unread() -> usize;
pub fn klog::syslog_clear();
pub fn klog::text_since(seq: u64) -> Vec<u8>; pub fn klog::snapshot() -> Vec<u8>;
pub fn klog::set_clock(f: fn() -> u64);           // record timestamps (ns)
pub fn klog::memparse(s: &str) -> u64;
pub fn klog::log_buf_len_value(arg: &str, current: usize) -> Option<usize>;
pub fn klog::log_buf_len_setup(arg: &str);        // `log_buf_len=`
pub fn klog::setup_log_buf();                     // once the heap is live
pub fn klog::set_console_loglevel(level: u32);
```

`write_str` always records into the kernel log store, then applies Linux's
`message_level < console_loglevel` rule to physical UART/framebuffer output.
Legacy unlevelled `Writer` calls have `DEFAULT_MESSAGE_LOGLEVEL` priority.
The `quiet` boot token selects that threshold, suppressing routine boot and
runtime chatter; `debug` selects level 10, and `loglevel=N` selects an explicit
1..15 threshold in command-line order. Panic and fatal-trap sinks bypass this
filter and remain visible; they also bypass the store (its lock may be held by
the code that faulted).

The store is RECORD-based, like Linux's printk ringbuffer: each record has a
64-bit sequence number, a monotonic timestamp (`set_clock`; 0 until the clock
is installed), facility, level, `LOG_*` flags and at most
`PRINTKRB_RECORD_MAX - 1` bytes of text. Kernel text is split into records at
`\n`; an unterminated fragment waits (unreadable) for the rest of its line, and
a line that outgrows a record, or is interrupted by an injected record,
continues in a new record flagged `LOG_CONT`. The text ring defaults to
`1 << CONFIG_LOG_BUF_SHIFT` = 128 KiB (Linux's Kconfig default, shipped by Arch);
the descriptor ring holds `log_buf_len >> 5` records. `log_buf_len=` follows
`log_buf_len_update`: `memparse`, clamp to 2 GiB, round up to a power of two,
taken only if larger than the current size; `setup_log_buf` allocates the new
rings once the heap is live and migrates every record with its sequence number.
`/dev/kmsg` renders a record as `"<prio>,<seq>,<ts_usec>,<flags>;<text>\n"`
(non-printables and `\` as `\xNN`); `syslog(2)` as
`"<prio>[%5lu.%06lu] <line>\n"` per line of the record. Debug streams such as
`syscall-trace` use `ConsoleOnlyWriter` so they never evict real messages.

### 3.1 MMU-enable handoff protocol

This is a Stage 1 correctness requirement. Exact sequence that
`memory/`'s MMU bring-up must perform:

1. Build the final page tables, including an identity map for the
   UART MMIO range *and* a kernel-virtual mapping for the same range
   (double-mapping is intentional and survives for one instruction).
2. Call `console::write_str("mmu: handoff...\n")` — output via
   physical base, guaranteed visible.
3. Execute the MMU-enable instruction sequence with interrupts
   disabled:
   - x86_64: load new `CR3`; in the first instructions after the
     load, call `console::remap_to_virtual(VIRT)`.
   - aarch64: write `TTBR0_EL1` / `TTBR1_EL1`, `TCR_EL1`,
     `MAIR_EL1`; `DSB ISHST; ISB`; set `SCTLR_EL1.M`; `ISB`;
     immediately call `console::remap_to_virtual(VIRT)`.
4. Tear down the identity map for the UART range (the kernel-virtual
   mapping is now sole).

After step 3, `write_str` dereferences a `VirtAddr`; before step 3,
a `PhysAddr`. The swap itself is one aligned pointer store — no
lock, no barrier beyond the ISB already required by the MMU bring-up.

If step 3 is not performed, the first post-MMU `write_str` or
`panic_sink` faults on the unmapped physical address, and the kernel
goes silent at the worst possible moment.

## 4. Invariants & safety properties

- `panic_sink` is signal-safe: no allocation, no locks held across call sites.
- Physical console output is serialised per `write_str` call (coarse lock).
  A log record never mixes CPUs: a fragment from another CPU commits the
  pending line and starts its own record (Linux `caller_id`), and the
  interrupted line resumes as a `LOG_CONT` record.
- Ring-buffer log with fixed size so a flood cannot exhaust memory; records
  are evicted whole, oldest first, and readers detect eviction by sequence
  number (`/dev/kmsg` `EPIPE`, `syslog` READ skips to the oldest record).
- The store lock is never held across allocation or console output; a
  per-CPU re-entrancy guard drops a record attempted from an NMI/fault on the
  CPU that holds it instead of deadlocking.
- **`write_str` dereferences whichever base the handoff flag
  currently selects.** The flag is an `AtomicUsize` (0 = phys, 1 = virt);
  the base pointer is an `AtomicPtr<u8>` loaded with `Ordering::Acquire`
  on every write. No race with `remap_to_virtual` is possible because
  the handoff runs with interrupts disabled on the BSP and APs have
  not yet been brought up at that point in boot.
- **Once `remap_to_virtual` has been called, it MUST NOT be called
  again in the same boot.** The console has exactly one VirtAddr for
  its lifetime (modulo Stage 3 virtio-console redirection, which
  closes the early UART rather than remapping it).

## 5. Architecture notes

### x86_64
- 16550A-compatible UART at `0x3F8` default; base overridable from cmdline.
- Bochs/QEMU `0xE9` port available as a secondary debug sink.

### aarch64
- PL011 UART on QEMU virt (MMIO at `0x0900_0000`).
- Real hardware: usually PL011 via devicetree; configurable.

## 6. Dependencies

- **Consumes:** `arch/` (MMIO + port I/O), `boot/` (base address).
- **Provides to:** everything (logging) and `frame/` (panic).
  **`memory/` is a first-class consumer of `remap_to_virtual`** —
  MMU bring-up cannot complete without calling it.

## 7. Stage assignment

Stage 1.

## 8. Resolved decisions

### 8.1 Structured log format (resolved)

**Decision:** **plain text + key=value pairs** for the wire
format; binary token stream is a separate fast-path for
high-volume sources (`tracing/` consumes this directly).

Plain-text format:

```text
TIMESTAMP_NS LEVEL DOMAIN COMPONENT: message {key1=val1 key2=val2}
```

- TIMESTAMP_NS is monotonic-ns at the log call site.
- LEVEL is one of `TRACE|DEBUG|INFO|WARN|ERROR|CRITICAL`.
- DOMAIN is the calling task's `DomainId`.
- COMPONENT is the calling crate (`narf-drivers-virtio-blk`).
- key=value pairs are space-separated, single-quoted on
  embedded whitespace.

Plain text was chosen over JSONL because:
- Easier to grep / awk on serial-only systems.
- Smaller overhead per line on the early-boot UART.
- The kvp section captures structure adequately.

Binary token stream is separate (`tracing/` ring buffers);
console is the human-readable surface.

### 8.2 virtio-console redirection (resolved)

**Decision:** **mandatory in Stage 3** via the
`Console::redirect_to_virtio` API.

When `bus/` probes a virtio-console device, `console/`
auto-redirects log output to it (in addition to the UART).
The redirected output is the same plain-text format. This
is what makes `cargo xtask run` show a clean kernel log
without serial-port plumbing.

The UART stays the primary; virtio-console is additive. If
virtio-console becomes unavailable (device removed, host
disconnect), log continues on UART without interruption.

## 9. ABI versioning

`console/` exports through SDK at `@v0`:

- `Writer` impl of `core::fmt::Write` (drivers use
  `writeln!(narf_console::Writer, ...)` for early-boot
  diagnostics; production code uses `tracing/` instead).
- The structured-log format above (parsers depend on this
  layout being stable).

`CONSOLE_ABI_MAJOR = 1`, `CONSOLE_ABI_MINOR = 0`. Adding a
log level or kvp delimiter is a major bump (parsers break).
Adding a new optional kvp on existing logs is freely allowed
(parsers ignore unknown keys).

## 10. Open questions

(none — all v0.2 questions resolved in §8)
