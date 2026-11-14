# pwm-lpss — Specification

> Status: **v0.1** (Draft).
>
> Intel Low Power Subsystem (LPSS) PWM controller driver: the first
> production `PwmDevice` implementor in-tree (issue #1699). Covers
> Bay Trail, Braswell, Broxton and Tangier SoCs, enumerated over PCI.

All register facts below are transcribed from Linux
`drivers/pwm/pwm-lpss.c`, `drivers/pwm/pwm-lpss.h` and
`drivers/pwm/pwm-lpss-pci.c` (torvalds/linux master). No offset,
bit or formula in this driver is invented.

## 1. Purpose & scope

**Owns:**
- The LPSS PWM controller driver: PCI probe/bind for the 9 device
  IDs in Linux `pwm_lpss_pci_ids[]`, BAR0 mapping, and the
  `PwmDevice` implementation (channel config, enable/disable,
  channel count).
- The LPSS timing arithmetic: `base_unit` / `on_time_div` derivation
  from (`frequency_hz`, `duty_cycle_ns`, `polarity`), including the
  software polarity inversion (the block has no polarity bit).
- The `SW_UPDATE` latch protocol: refuse a new update while one is
  latched; wait (bounded, cooperative) for the block to clear it.

**Does NOT own:**
- The `PwmDevice` trait or the controller registry — those live in
  `pwm/` (`narf_pwm`); the registry landed with #1700 (closed) and
  this driver registers into it from `probe()` (#1722).
- PWM consumers (fan, LED, backlight) — they take
  `Arc<dyn PwmDevice>` and are unaffected by which controller
  supplies it.

## 2. Assumptions

1. The PCI bus walk has enumerated the function and `probe_all`
   dispatches it to this driver by exact `(vendor, device)` match.
   The function's BAR0 is a mapped MMIO window covering
   `npwm * 0x400` bytes.
2. The LPSS clock rates are fixed per SoC (Bay Trail 25 MHz; all
   others 19.2 MHz) — taken from Linux board data, not measured.
3. `SW_UPDATE` clears at the start of the next output cycle. At the
   slowest programmable frequency (22-bit base_unit, 19.2 MHz
   clock: ~4.6 Hz) one period is ~218 ms; the poll budget (~100k
   reads, Linux's 500 ms window) covers it.
4. One controller owns its register block exclusively; concurrent
   callers on the same channel are serialised by the driver's async
   mutex.

## 3. Public Interface

### 3.1 Board data

```rust
pub struct LpssBoardInfo {
    pub clk_rate: u32,        // input clock, Hz
    pub npwm: u32,            // channel count
    pub base_unit_bits: u32,  // width of the base_unit field
    pub bypass: bool,         // ENABLE-after-wait (Broxton) vs before
}

pub const LPSS_BYT_INFO: LpssBoardInfo; // 25 MHz, 1 ch, 16-bit
pub const LPSS_BSW_INFO: LpssBoardInfo; // 19.2 MHz, 1 ch, 16-bit
pub const LPSS_BXT_INFO: LpssBoardInfo; // 19.2 MHz, 4 ch, 22-bit, bypass
pub const LPSS_TNG_INFO: LpssBoardInfo; // 19.2 MHz, 4 ch, 22-bit

pub const SUPPORTED_DEVICE_IDS: &[u16]; // all 9 Linux PCI IDs
pub fn board_info_for(device_id: u16) -> Option<&'static LpssBoardInfo>;
```

### 3.2 Driver

```rust
pub struct LpssPwm { /* MMIO region + board data + channel state */ }
impl LpssPwm {
    pub fn new(name: String, mmio: MmioRegion, info: &'static LpssBoardInfo) -> Self;
    pub fn name(&self) -> &str;
    pub fn info(&self) -> &'static LpssBoardInfo;
}

#[async_trait]
impl PwmDevice for LpssPwm {
    async fn set_config(&self, channel: u32, config: &PwmConfig) -> Result<(), PwmError>;
    async fn enable(&self, channel: u32) -> Result<(), PwmError>;
    async fn disable(&self, channel: u32) -> Result<(), PwmError>;
    fn channel_count(&self) -> u32;
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError>;
pub fn probed_controllers() -> Vec<Arc<dyn PwmDevice>>;
pub fn register_pci_driver();
pub fn register_initcalls(); // Stage::Subsys "pwm-lpss"

/// The phandle of `device`'s own Devicetree node: `probe()`
/// registers the controller in the `narf_pwm` registry under this
/// phandle, so a DT consumer whose `pwms` specifier names that node
/// resolves this controller (#1722). Found the way Linux
/// `pci_set_of_node` finds it — descend from the PCI host bridge
/// through the `reg` devfn hops (`narf_firmware_fdt::
/// for_pci_function`) and read the node's `phandle` property; the
/// same shape as ath11k's `dt_facts`. `None` when the boot carries
/// no DTB (x86_64, the only real LPSS platform) or the tree
/// describes no (unique) node for this function — then `probe()`
/// registers nothing and the controller stays reachable only via
/// `probed_controllers()`. No phandle is invented.
pub fn dt_phandle_for(device: &BusDevice) -> Option<u32>;
pub fn dt_phandle_for_in(blob: &[u8], device: &BusDevice) -> Option<u32>;
```

### 3.3 Register model

| Item | Value | Linux source |
|---|---|---|
| Channel stride | `0x400` | `PWM_SIZE` |
| Control register | `channel * 0x400 + 0x00` | `PWM` |
| `PWM_ENABLE` | bit 31 | `BIT(31)` |
| `PWM_SW_UPDATE` | bit 30 | `BIT(30)` |
| `base_unit` field | bits `[8 .. 8+base_unit_bits)` | `PWM_BASE_UNIT_SHIFT` |
| `on_time_div` field | bits `[7:0]` | `PWM_ON_TIME_DIV_MASK` |

Formulas (Linux `pwm_lpss_prepare`):
- `period_ns = 1e9 / frequency_hz`; `freq = 1e9 / period_ns`
- `base_unit = round(freq * 2^base_unit_bits / clk_rate)`, clamped to `[1, 2^base_unit_bits - 1]`
- Normal: `on_time_div = 255 - floor(255 * duty_ns / period_ns)`
- Inversed (software emulation): `on_time_div = floor(255 * duty_ns / period_ns)`

## 4. Invariants

1. **No update while latched.** A `set_config` / `enable` that
   finds `SW_UPDATE` set returns `HardwareError` without writing
   (Linux `pwm_lpss_is_updating()` → `-EBUSY`; NARF has no Busy
   variant). Writing over a latched update can freeze the block.
2. **Timing writes preserve ENABLE.** `prepare()` is a
   read-modify-write that masks only the `base_unit` and
   `on_time_div` fields, so reprogramming an enabled channel does
   not glitch it off.
3. **Enable has a waveform.** `enable()` on a never-configured
   channel returns `InvalidConfig` — there is nothing to enable.
   (Linux `apply()` always carries full state, so this case cannot
   arise there.)
4. **Channel bounds.** `channel >= npwm` is `InvalidChannel` on
   every method; `frequency_hz == 0`, `period_ns == 0`, or
   `duty_cycle_ns > period_ns` is `InvalidConfig`.
5. **One writer at a time.** All config/enable/disable sequences
   run under the driver's async mutex, so two tasks cannot
   interleave a prepare/wait pair on the same channel.

## 5. Architecture notes (x86_64, aarch64)

- x86_64 only in practice: LPSS PWM is an Intel SoC block
  enumerated over PCI. The code itself is arch-neutral (MMIO
  through `MmioRegion`, no arch intrinsics) and compiles on
  aarch64; it simply never matches a device there.
- The `SW_UPDATE` wait is cooperative: bursts of 32 volatile reads
  with `yield_now()` between bursts, so the wait never starves the
  executor (cf. i801's `yield_now()` poll loops). No IRQ is
  involved; the block raises no interrupt for the latch.
- The driver holds its async mutex across the wait (the
  AGENTS.md-blessed pattern: `narf_lib::mutex::Mutex` is safe to
  hold across `.await`; an `IrqSafeSpinLock` guard would make the
  future `!Send`).

## 6. Dependencies

- `narf-pwm`: `PwmDevice` / `PwmConfig` / `Polarity` / `PwmError`.
- `narf-firmware-fdt`: `for_pci_function` / `prop_phandle` /
  `discover` for the DT-node phandle lookup (`dt_phandle_for`); its
  `pci::tests` synthetic-tree builder for the DT fixture tests.
- `narf-bus`: PCI match registration, `map_bar`, `MmioRegion`,
  `set_command`.
- `narf-lib`: async mutex, `IrqSafeSpinLock` (probed static).
- `narf-init`: `Stage::Subsys` registration.
- `narf-scheduler`: cooperative yield in the update wait; test
  harness (`__reset_queues_for_test`, `run_until_empty`).
- `narf-memory`: `PhysAddr` (fixture MMIO backing only).

## 7. Stage assignment

Stage 5 "Silicon" — desktop/embedded bring-up (same stage as the
`pwm-fan` consumer in #1700 and the LED/backlight PWM consumers).

## 8. Open questions

1. **Phandle for a PCI-enumerated controller — RESOLVED (#1722).**
   The controller registers under the phandle of its own DT node,
   found via `for_pci_function` (Linux `pci_set_of_node`). On a
   DTB-less x86 boot it registers nowhere and `probed_controllers()`
   stays the only path — that static is therefore kept, not removed.
2. **Suspend/resume.** Linux removed the LPSS save/restore
   handlers (consumers re-apply state). NARF consumers
   (`PwmFan`, `LedPwm`) likewise re-apply on resume; no driver
   suspend hook is planned unless a consumer proves otherwise.
3. **ACPI-enumerated LPSS.** Bay Trail parts can also appear as
   ACPI `INT33FC` platform devices (Linux `pwm-lpss-platform.c`).
   Only the PCI path is implemented here; the ACPI path is a
   follow-up if an ACPI-enumerated board needs it.
