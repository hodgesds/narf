# Watchdog subsystem specification

## 1. Purpose & scope

The watchdog class owns the kernel side of hardware watchdogs:
a device registry (`WatchdogDevice` trait + global registry) and
one production driver, Intel TCO (iTCO), probed from the ACPI
WDDT. In scope: timer programming, pet (keepalive), halt, and
status. Out of scope: SMI routing, NO_REBOOT control, the PCI
TCOBASE probe route, sysfs/`/dev/watchdog` publication, and
SBSA/SP805 watchdogs (see §8).

## 2. Assumptions

- At most one watchdog block per machine; duplicate names
  replace (backlight-registry idempotency).
- The WDDT Address field is the TCO register-block base in I/O
  space (WDDT 1.0). A base outside the 16-bit I/O-port space
  fails probe rather than being truncated.
- The TCO timer ticks at ~0.6s (EDC TTMR description); the
  driver never assumes a WDDT `period_us` unit (unpinned).
- Probe performs no register writes; arming is an explicit
  `set_timeout` action.
- The driver never programs registers whose semantics are not
  pinned to a citable source (NO_REBOOT, TCO_DAT_IN/OUT, the
  TCO message registers).

## 3. Public interface

- `trait WatchdogDevice: Send + Sync + Debug` — `name()`,
  `set_timeout(secs) -> Result<(), WatchdogError>`, `pet()`,
  `stop()`, `status() -> WatchdogStatus`.
- `register_watchdog(Arc<dyn WatchdogDevice>)`,
  `unregister_watchdog(name)`, `watchdog_devices()`,
  `watchdog_device(name)`, `__reset_for_test()`.
- `WatchdogStatus { armed, timed_out, second_timeout,
  timeleft_secs, no_reboot_control }`; `WatchdogError {
  InvalidTimeout, NotPresent }`.
- `itco::PortIo` trait (`read_u8/write_u8/read_u16/write_u16`
  over I/O ports); `RealPortIo` (x86_64, via
  `narf_arch::x86_64::io_port`).
- `itco::ItcoWatchdog<P: PortIo>` — `probe_from_info(WddtInfo,
  P) -> Option<Arc<Self>>`, `probe_from_wddt()` (x86_64,
  boot-parsed WDDT), `base()`, `tick_range()`.
- `register_initcalls()` — Stage::Device `"watchdog/itco"`
  initcall on x86_64 (no-op elsewhere); `NotPresent` when no
  usable WDDT is present.
- Boot wiring (frame, TCB-touch — see the safety argument):
  `parse_wddt` runs best-effort alongside the other ACPI table
  parses, and the enumeration calls
  `narf_drivers_watchdog::register_initcalls()`.

### Pinned TCO register map (EDC ID 834819 + Linux iTCO_wdt)

| Register | Offset | Width | Semantics |
|----------|--------|-------|-----------|
| TCO_RLD  | +0x00  | u16   | Read = current count (9:0); any write reloads. |
| TCO1_STS | +0x04  | u16   | RW/1C; bit 3 TIMEOUT (first expiry). |
| TCO2_STS | +0x06  | u8    | Bit 1 SECOND_TO_STS (second expiry). |
| TCO1_CNT | +0x08  | u16   | Bit 11 TMR_HLT (1 = halted). |
| TCO2_CNT | +0x0a  | u16   | Documented, not programmed. |
| TCO_TMR  | +0x12  | u16   | Bits 9:0 reload value; 0/1 ignored; ~0.6s/tick. |

Timeout conversion: `ticks = ceil(secs / 0.6)`, valid on
[2, 1023] intersected with the WDDT count bounds when those
intersect [2, 1023]; otherwise the EDC range. Out-of-range
requests are rejected, never silently clamped.

`set_timeout` write order: clear TIMEOUT → program TMR →
clear halt → write RLD. `pet` order: write RLD → clear
TIMEOUT. `stop` sets halt only.

## 4. Invariants

- A probe never writes a register; only `set_timeout`, `pet`,
  and `stop` write, and only within the probed block.
- STS1 writes carry exactly the TIMEOUT bit (RW/1C discipline);
  no blanket status clear can wipe unrelated sticky bits.
- CNT1 writes are read-modify-write, preserving every bit
  except TMR_HLT.
- A requested timeout is never silently replaced by a
  different one: out-of-range requests fail.
- The driver never touches NO_REBOOT, SMI_EN/TCO_EN, or the
  message registers; `status().no_reboot_control` is always
  false until a later lane pins the control bit.
- The registry holds at most one device per name; unregister
  removes exactly that name.

## 5. Architecture notes (x86_64, aarch64)

- x86_64: full driver via I/O-port instructions. The TCO block
  is I/O space; no MMIO mapping is involved.
- aarch64: the crate compiles with the class + registry only;
  no iTCO device registers (there is no iTCO block on ARM
  platforms; SBSA/SP805 are a separate embedded lane).

## 6. Dependencies

- `narf_acpi` (WDDT), `narf_arch` (I/O ports, x86_64),
  `narf_init` (Stage::Device), `narf_lib` (IrqSafeSpinLock),
  `narf_kernel_test` (smokes). Frame wires the crate in
  (dep + initcall enumeration + boot-time `parse_wddt`).

## 7. Stage assignment

Stage 5 "Silicon" (desktop bring-up): the watchdog is basic
recovery hygiene for boards and laptops, probed from firmware
tables like the other platform devices.

## 8. Open questions

- NO_REBOOT bit position on TCO v6 (Cannon Lake+): the LKML
  note says only "part of the TCO1_CNT register". A lane with
  the Cannon Lake PCH datasheet (or a pinned header) should
  add NO_REBOOT control + flip `no_reboot_control`.
- PCI TCOBASE probe route (SMBus device config offset 0x50,
  EDC): for machines whose firmware omits WDDT. WDDT-first
  keeps this lane minimal.
- Sysfs bridge (`/sys/class/watchdog`) + `/dev/watchdog`
  publication: the class exists; user visibility is a
  follow-on.
- SBSA generic + SP805 watchdogs: embedded programme scope.
- WDDT `period_us` semantics: if a citable source pins its
  unit, the tick conversion can consume it instead of the
  fixed 0.6s EDC tick.
