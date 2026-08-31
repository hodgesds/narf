//! High Precision Event Timer (HPET) — clean-room.
//!
//! Spec: Intel **"IA-PC HPET (High Precision Event Timers)
//! Specification"** rev 1.0a, October 2004, document 309216-001.
//! Free PDF mirror:
//! <https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/software-developers-hpet-spec-1-0a.pdf>
//! Section references (`§2.3`, `§3.2`) point at that document.
//!
//! HPET is a free-running monotonic counter at a fixed,
//! firmware-discoverable frequency (~14.31818 MHz on most systems).
//! NARF uses HPET as a TSC-validation cross-check + fallback
//! clocksource on hosts where TSC isn't invariant.
//!
//! ## Discovery
//!
//! The HPET base address normally lives in the ACPI **HPET** table.
//! Without a full ACPI parser in tree, we fall back to the
//! ubiquitous default placement: x86_64 chipsets (Intel ICH /
//! AMD FCH / QEMU q35) all expose HPET at physical `0xFED00000`.
//! Boot code can override the discovered base via
//! [`set_base_phys`] once an ACPI walker lands.
//!
//! ## Register layout (§3.2)
//!
//! | offset  | name                      | width |
//! |---------|---------------------------|-------|
//! | 0x000   | General Capabilities + ID | u64   |
//! | 0x010   | General Configuration     | u64   |
//! | 0x020   | General Interrupt Status  | u64   |
//! | 0x0F0   | Main Counter Value        | u64   |
//! | 0x100+  | Per-comparator block      | …     |
//!
//! General Capabilities + ID (§3.2.1):
//!
//! | bits    | field                                  |
//! |---------|----------------------------------------|
//! | [7:0]   | REV_ID                                 |
//! | [12:8]  | NUM_TIM_CAP — number of comparators-1  |
//! | [13]    | COUNT_SIZE — 1 = 64-bit main counter   |
//! | [15]    | LEG_RT_CAP                             |
//! | [16:31] | VENDOR_ID                              |
//! | [32:63] | COUNTER_CLK_PERIOD (femtoseconds)      |
//!
//! Main Counter Value: free-running 64-bit (or 32-bit) counter.
//!
//! ## Per-timer comparator block (§2.3.5 / §2.3.6)
//!
//! Each timer N (0..NUM_TIM_CAP) has a 32-byte block at
//! `base + 0x100 + 0x20*N`. Two registers per block matter for
//! one-shot programming:
//!
//! | offset   | name                    | width |
//! |----------|-------------------------|-------|
//! | block+0  | Tn_CONFIG_AND_CAP       | u64   |
//! | block+8  | Tn_COMPARATOR_VALUE     | u64   |
//!
//! `Tn_CONFIG_AND_CAP` low bits (§2.3.5):
//!
//! | bits      | field                                          |
//! |-----------|------------------------------------------------|
//! | [1]       | Tn_INT_TYPE_CNF — 0=edge, 1=level              |
//! | [2]       | Tn_INT_ENB_CNF — 0=disabled, 1=enabled         |
//! | [3]       | Tn_TYPE_CNF — 0=one-shot, 1=periodic           |
//! | [4]       | Tn_PER_INT_CAP (RO) — periodic-mode supported  |
//! | [5]       | Tn_SIZE_CAP (RO) — 0=32-bit, 1=64-bit timer    |
//! | [6]       | Tn_VAL_SET_CNF — direct-write to accumulator   |
//! | [8]       | Tn_32MODE_CNF — force 32-bit mode              |
//! | [9..=13]  | Tn_INT_ROUTE_CNF — selected GSI                |
//! | [14]      | Tn_FSB_EN_CNF — FSB-style MSI delivery         |
//! | [15]      | Tn_FSB_INT_DEL_CAP (RO)                        |
//! | [32..=63] | Tn_INT_ROUTE_CAP (RO) — bitmask of valid GSIs  |
//!
//! `General Interrupt Status` (§3.2.3) bit N is the level-mode
//! latch for timer N: must be cleared (write-1-to-clear) before
//! re-arming a level-triggered comparator.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Default HPET physical base on x86_64 (Intel ICH / AMD FCH /
/// QEMU q35). ACPI HPET-table parsing can override via
/// [`set_base_phys`].
pub const HPET_DEFAULT_BASE: u64 = 0xFED0_0000;

const REG_CAP_ID: u64 = 0x000;
const REG_GEN_CONF: u64 = 0x010;
const REG_INT_STS: u64 = 0x020;
const REG_MAIN_CNT: u64 = 0x0F0;
const REG_TIMER_BASE: u64 = 0x100;
const REG_TIMER_STRIDE: u64 = 0x20;
const TIMER_REG_CONFIG: u64 = 0x00;
const TIMER_REG_COMPARATOR: u64 = 0x08;
/// Per-timer FSB-MSI route register (HPET §2.3.6). Bits[31:0]
/// = MSI data value (vector + delivery + trigger). Bits[63:32]
/// = MSI address value (FED-format). Used only when
/// `TN_FSB_EN_CNF` is set in the timer's CONFIG.
const TIMER_REG_FSB_ROUTE: u64 = 0x10;

const GEN_CONF_ENABLE_CNF: u64 = 1 << 0;

// Per-timer Tn_CONFIG_AND_CAP bits (§2.3.5).
const TN_INT_TYPE_CNF: u64 = 1 << 1;
const TN_INT_ENB_CNF: u64 = 1 << 2;
const TN_TYPE_CNF_PERIODIC: u64 = 1 << 3;
const TN_PER_INT_CAP: u64 = 1 << 4;
const TN_SIZE_CAP: u64 = 1 << 5;
const TN_VAL_SET_CNF: u64 = 1 << 6;
const TN_32MODE_CNF: u64 = 1 << 8;
const TN_INT_ROUTE_CNF_SHIFT: u32 = 9;
const TN_INT_ROUTE_CNF_MASK: u64 = 0x1F << TN_INT_ROUTE_CNF_SHIFT;
const TN_FSB_EN_CNF: u64 = 1 << 14;
/// Tn_FSB_INT_DEL_CAP (RO): timer supports FSB-MSI delivery.
const TN_FSB_INT_DEL_CAP: u64 = 1 << 15;
const TN_INT_ROUTE_CAP_SHIFT: u32 = 32;

/// One femtosecond.
pub const FEMTOS_PER_SEC: u64 = 1_000_000_000_000_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpetError {
    /// HPET memory window doesn't carry a valid capabilities word.
    NotPresent,
    /// COUNTER_CLK_PERIOD reads as zero or implausibly large.
    BadFrequency,
}

#[derive(Copy, Clone, Debug)]
pub struct HpetCaps {
    pub rev_id: u8,
    /// Number of comparators (NUM_TIM_CAP + 1).
    pub num_comparators: u8,
    pub counter_64bit: bool,
    pub legacy_route_cap: bool,
    pub vendor_id: u16,
    /// Tick period in femtoseconds.
    pub clk_period_fs: u32,
}

impl HpetCaps {
    /// Tick frequency in Hz.
    pub fn frequency_hz(&self) -> u64 {
        if self.clk_period_fs == 0 {
            return 0;
        }
        FEMTOS_PER_SEC / self.clk_period_fs as u64
    }
}

#[derive(Debug)]
pub struct Hpet {
    base_phys: u64,
    caps: HpetCaps,
}

impl Hpet {
    /// Probe HPET at `base_phys`. Reads the capabilities word + the
    /// counter clock period; returns `NotPresent` if the
    /// capabilities word is all-zeros / all-ones (no chip behind
    /// the address) and `BadFrequency` if `clk_period_fs == 0`.
    ///
    /// # Safety
    /// Caller asserts that `base_phys` is a valid 1 KiB MMIO
    /// window backed by HPET.
    pub unsafe fn probe(base_phys: u64) -> Result<Self, HpetError> {
        // SAFETY: caller-asserted MMIO window; identity-mapped on
        // x86_64 (HPET base is in the legacy MMIO hole below 4 GiB).
        // SAFETY: Valid memory or trusted environment
        let cap = unsafe { read_u64(base_phys + REG_CAP_ID) };
        if cap == 0 || cap == u64::MAX {
            return Err(HpetError::NotPresent);
        }
        let clk = ((cap >> 32) & 0xFFFF_FFFF) as u32;
        if clk == 0 || clk > 200_000_000 {
            // > 0.2 ns / tick is implausible for any real HPET.
            return Err(HpetError::BadFrequency);
        }
        let caps = HpetCaps {
            rev_id: (cap & 0xFF) as u8,
            num_comparators: (((cap >> 8) & 0x1F) + 1) as u8,
            counter_64bit: (cap >> 13) & 1 != 0,
            legacy_route_cap: (cap >> 15) & 1 != 0,
            vendor_id: ((cap >> 16) & 0xFFFF) as u16,
            clk_period_fs: clk,
        };
        Ok(Self { base_phys, caps })
    }

    /// Enable the main counter (set GEN_CONF.ENABLE_CNF).
    ///
    /// # Safety
    /// Caller owns the HPET window exclusively.
    pub unsafe fn enable(&self) {
        // SAFETY: identity-mapped MMIO.
        let g = unsafe { read_u64(self.base_phys + REG_GEN_CONF) };
        // SAFETY: same.
        unsafe {
            write_u64(self.base_phys + REG_GEN_CONF, g | GEN_CONF_ENABLE_CNF);
        }
    }

    /// Disable the main counter.
    ///
    /// # Safety
    /// Caller owns the HPET window exclusively.
    pub unsafe fn disable(&self) {
        // SAFETY: identity-mapped MMIO.
        let g = unsafe { read_u64(self.base_phys + REG_GEN_CONF) };
        // SAFETY: same.
        unsafe {
            write_u64(self.base_phys + REG_GEN_CONF, g & !GEN_CONF_ENABLE_CNF);
        }
    }

    /// Snapshot of the main counter (free-running ticks).
    ///
    /// # Safety
    /// HPET window must be live.
    pub unsafe fn read_counter(&self) -> u64 {
        // SAFETY: caller-asserted live window.
        unsafe { read_u64(self.base_phys + REG_MAIN_CNT) }
    }

    pub fn caps(&self) -> HpetCaps {
        self.caps
    }
    pub fn base_phys(&self) -> u64 {
        self.base_phys
    }

    /// Per-timer block base for comparator `n`
    /// (`base + 0x100 + 0x20*n`, §2.3).
    #[inline]
    fn timer_block(&self, n: u8) -> u64 {
        self.base_phys + REG_TIMER_BASE + REG_TIMER_STRIDE * n as u64
    }

    /// Read `Tn_CONFIG_AND_CAP` (§2.3.5).
    ///
    /// # Safety
    /// Caller asserts the HPET window is live and `n` is a valid
    /// comparator index (`< caps.num_comparators`).
    pub unsafe fn read_timer_config(&self, n: u8) -> u64 {
        // SAFETY: caller-asserted live window + valid index.
        unsafe { read_u64(self.timer_block(n) + TIMER_REG_CONFIG) }
    }

    /// Read `Tn_COMPARATOR_VALUE` (§2.3.6). Returns the full 64-bit
    /// register; on a 32-bit timer the upper word is undefined per
    /// spec, so callers must mask to 32 bits in that case.
    ///
    /// # Safety
    /// Caller asserts the HPET window is live and `n` is a valid
    /// comparator index.
    pub unsafe fn read_timer_comparator(&self, n: u8) -> u64 {
        // SAFETY: caller-asserted live window + valid index.
        unsafe { read_u64(self.timer_block(n) + TIMER_REG_COMPARATOR) }
    }

    /// Returns the bitmask of GSIs this timer can route to
    /// (`Tn_INT_ROUTE_CAP`, bits 32..=63 of `Tn_CONFIG_AND_CAP`,
    /// §2.3.5). Bit `i` set means GSI `i` is a valid destination.
    ///
    /// # Safety
    /// Same as [`read_timer_config`].
    pub unsafe fn timer_route_cap(&self, n: u8) -> u32 {
        // SAFETY: forwards.
        let cfg = unsafe { self.read_timer_config(n) };
        (cfg >> TN_INT_ROUTE_CAP_SHIFT) as u32
    }

    /// `true` if comparator `n` is a 64-bit timer
    /// (`Tn_SIZE_CAP`, §2.3.5 bit 5).
    ///
    /// # Safety
    /// Same as [`read_timer_config`].
    pub unsafe fn timer_is_64bit(&self, n: u8) -> bool {
        // SAFETY: forwards.
        let cfg = unsafe { self.read_timer_config(n) };
        cfg & TN_SIZE_CAP != 0
    }

    /// Program comparator `n` for a one-shot interrupt that fires
    /// when the main counter reaches `deadline` (in HPET ticks).
    ///
    /// Sequence (§2.3.5 / §2.3.6):
    ///   1. Disable the timer (`Tn_INT_ENB_CNF` cleared) so we can
    ///      mutate config + comparator without delivering a stale
    ///      interrupt.
    ///   2. Force 32-bit mode (`Tn_32MODE_CNF`) on 32-bit timers so
    ///      the high word of the 64-bit comparator register is
    ///      ignored.
    ///   3. Clear periodic + FSB; select level-trigger so the
    ///      IOAPIC can drop one delivery if the deadline races us
    ///      and re-arm cleanly via the status latch.
    ///   4. Program `Tn_INT_ROUTE_CNF` to `gsi`.
    ///   5. Write the comparator. For one-shot the spec only
    ///      defines the comparator-as-deadline semantic when the
    ///      timer is in non-periodic mode (`Tn_TYPE_CNF` clear),
    ///      so `Tn_VAL_SET_CNF` is left clear.
    ///   6. Clear the `General Interrupt Status` latch for this
    ///      timer (write 1 to bit `n`) so a stale level-mode
    ///      assertion from a previous arming doesn't immediately
    ///      re-fire when we set `Tn_INT_ENB_CNF`.
    ///   7. Set `Tn_INT_ENB_CNF`.
    ///
    /// # Safety
    /// Caller asserts `n` is a valid comparator index, `gsi` is in
    /// the bitmask returned by [`Self::timer_route_cap`], and the
    /// HPET MMIO window is live + exclusively owned for the duration
    /// of this call. Callers must arrange IDT vector + IOAPIC
    /// programming so that the GSI lands at a real handler.
    pub unsafe fn arm_oneshot_comparator(&self, n: u8, gsi: u8, deadline: u64) {
        let block = self.timer_block(n);
        // SAFETY: caller-asserted live window + valid index.
        let mut cfg = unsafe { read_u64(block + TIMER_REG_CONFIG) };
        // Step 1: disable + clear periodic / FSB / val-set so we're
        // in a known one-shot, IRQ-disabled state.
        cfg &= !(TN_INT_ENB_CNF
            | TN_TYPE_CNF_PERIODIC
            | TN_VAL_SET_CNF
            | TN_FSB_EN_CNF
            | TN_INT_ROUTE_CNF_MASK);
        // Step 2/3: level-triggered (so a stale latch is observable
        // + clearable rather than silently lost on edge).
        cfg |= TN_INT_TYPE_CNF;
        // Step 2 cont.: on 32-bit timers, force 32-bit mode so the
        // upper bits of the 64-bit comparator register aren't
        // consulted — the spec leaves them undefined on
        // `Tn_SIZE_CAP == 0` parts.
        if cfg & TN_SIZE_CAP == 0 {
            cfg |= TN_32MODE_CNF;
        }
        // Step 4: route bits.
        cfg |= ((gsi as u64) << TN_INT_ROUTE_CNF_SHIFT) & TN_INT_ROUTE_CNF_MASK;
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_CONFIG, cfg) };

        // Step 5: program the deadline. Mask to 32 bits in 32-bit
        // mode to avoid setting an unreachable comparator.
        let value = if cfg & TN_32MODE_CNF != 0 {
            deadline & 0xFFFF_FFFF
        } else {
            deadline
        };
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_COMPARATOR, value) };

        // Step 6: write-1-to-clear the level latch for this timer.
        // The General Interrupt Status register is at REG_INT_STS;
        // bit N corresponds to comparator N (§3.2.3). Other bits
        // are write-zero-no-effect, so OR-write of just `1 << n` is
        // safe.
        // SAFETY: same.
        unsafe { write_u64(self.base_phys + REG_INT_STS, 1u64 << n) };

        // Step 7: enable interrupt delivery.
        cfg |= TN_INT_ENB_CNF;
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_CONFIG, cfg) };
    }

    /// Arm comparator `n` in PERIODIC mode firing every
    /// `period_ticks` HPET ticks on `gsi`. Returns immediately
    /// after programming; the first IRQ fires after `period_ticks`
    /// from the time of the call.
    ///
    /// Periodic mode requires `Tn_PER_INT_CAP` (per-timer
    /// capability). Use [`Hpet::supports_periodic`] to check.
    ///
    /// HPET §2.3.9.2 sequence:
    ///   1. Set TN_TYPE_CNF (periodic) + TN_VAL_SET_CNF + route
    ///      bits + level-triggered, INT_ENB=0.
    ///   2. Write `main_counter + period_ticks` to TIMER_COMPARATOR
    ///      (first write sets the trigger value; TN_VAL_SET_CNF
    ///      auto-clears).
    ///   3. Write `period_ticks` to TIMER_COMPARATOR again (second
    ///      write sets the increment).
    ///   4. Clear status latch.
    ///   5. Set TN_INT_ENB_CNF.
    ///
    /// # Safety
    /// Same as [`Self::arm_oneshot_comparator`].
    pub unsafe fn arm_periodic_comparator(&self, n: u8, gsi: u8, period_ticks: u64) {
        let block = self.timer_block(n);
        // SAFETY: caller-asserted live window + valid index.
        let mut cfg = unsafe { read_u64(block + TIMER_REG_CONFIG) };
        // Step 1: program config (still disabled until step 5).
        cfg &= !(TN_INT_ENB_CNF | TN_FSB_EN_CNF | TN_INT_ROUTE_CNF_MASK);
        cfg |= TN_TYPE_CNF_PERIODIC | TN_VAL_SET_CNF | TN_INT_TYPE_CNF;
        if cfg & TN_SIZE_CAP == 0 {
            cfg |= TN_32MODE_CNF;
        }
        cfg |= ((gsi as u64) << TN_INT_ROUTE_CNF_SHIFT) & TN_INT_ROUTE_CNF_MASK;
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_CONFIG, cfg) };

        // Step 2: read current main counter, write `now + period`
        // as the first comparator value.
        // SAFETY: same.
        let now = unsafe { read_u64(self.base_phys + REG_MAIN_CNT) };
        let trigger = now.wrapping_add(period_ticks);
        let trigger_w = if cfg & TN_32MODE_CNF != 0 {
            trigger & 0xFFFF_FFFF
        } else {
            trigger
        };
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_COMPARATOR, trigger_w) };

        // Step 3: write period as the increment (TN_VAL_SET_CNF
        // already auto-cleared by step 2's write).
        let period_w = if cfg & TN_32MODE_CNF != 0 {
            period_ticks & 0xFFFF_FFFF
        } else {
            period_ticks
        };
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_COMPARATOR, period_w) };

        // Step 4: clear status latch for this timer.
        // SAFETY: same.
        unsafe { write_u64(self.base_phys + REG_INT_STS, 1u64 << n) };

        // Step 5: enable interrupt delivery.
        cfg |= TN_INT_ENB_CNF;
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_CONFIG, cfg) };
    }

    /// True iff comparator `n` supports periodic mode
    /// (`Tn_PER_INT_CAP`). Not all HPET timers do — the spec
    /// guarantees only timer 0 has it on every part; others vary.
    pub fn supports_periodic(&self, n: u8) -> bool {
        if n >= self.caps.num_comparators {
            return false;
        }
        // SAFETY: index bounded.
        let cfg = unsafe { self.read_timer_config(n) };
        cfg & TN_PER_INT_CAP != 0
    }

    /// True iff comparator `n` supports FSB-MSI delivery
    /// (`Tn_FSB_INT_DEL_CAP`). Modern HPETs (post-2008-ish) all
    /// support it; legacy ICH7 / older Intel chipsets may not.
    /// When supported, MSI delivery bypasses the IOAPIC entirely
    /// — useful on platforms where IOAPIC routing for HPET's
    /// GSIs is broken (e.g. Renoir).
    pub fn supports_fsb(&self, n: u8) -> bool {
        if n >= self.caps.num_comparators {
            return false;
        }
        // SAFETY: index bounded.
        let cfg = unsafe { self.read_timer_config(n) };
        cfg & TN_FSB_INT_DEL_CAP != 0
    }

    /// Arm comparator `n` in periodic mode via FSB-MSI delivery.
    /// Bypasses the IOAPIC — the timer delivers IRQs as PCI-style
    /// MSI writes to the LAPIC, addressed via `msi_addr` (FED-
    /// format: `0xFEE0_0000 | (apic_id << 12)` for physical-mode
    /// fixed delivery) carrying `msi_data` (which encodes the
    /// vector and delivery mode).
    ///
    /// This is the canonical modern HPET delivery path (matches
    /// Linux's `hpet_msi_write` + `HPET_TN_FSB_CAP` flow).
    ///
    /// Same register-write sequence as the IOAPIC path, plus the
    /// FSB route programming inserted between the config write
    /// and the comparator writes (so the config's
    /// `TN_FSB_EN_CNF` bit is already set when the FSB route is
    /// programmed).
    ///
    /// # Safety
    /// Same as [`Self::arm_periodic_comparator`]. Caller must
    /// also ensure `supports_fsb(n)` returned true.
    pub unsafe fn arm_periodic_msi_comparator(
        &self,
        n: u8,
        msi_addr: u32,
        msi_data: u32,
        period_ticks: u64,
    ) {
        let block = self.timer_block(n);
        // SAFETY: caller-asserted live window + valid index.
        let mut cfg = unsafe { read_u64(block + TIMER_REG_CONFIG) };
        cfg &= !(TN_INT_ENB_CNF | TN_INT_ROUTE_CNF_MASK | TN_INT_TYPE_CNF);
        // Enable FSB delivery; periodic mode + SETVAL to write
        // both the initial comparator and the period.
        cfg |= TN_FSB_EN_CNF | TN_TYPE_CNF_PERIODIC | TN_VAL_SET_CNF;
        if cfg & TN_SIZE_CAP == 0 {
            cfg |= TN_32MODE_CNF;
        }
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_CONFIG, cfg) };

        // FSB route: low 32 = data (vector + delivery), high 32
        // = address (FED-format). Written as one 64-bit MMIO; some
        // HPETs accept this, others want two 32-bit writes. The
        // HPET spec permits 32-bit access to either half, so do
        // 32-bit writes for compatibility.
        // SAFETY: same.
        unsafe {
            let fsb_lo = (block + TIMER_REG_FSB_ROUTE) as *mut u32;
            let fsb_hi = (block + TIMER_REG_FSB_ROUTE + 4) as *mut u32;
            core::ptr::write_volatile(fsb_lo, msi_data);
            core::ptr::write_volatile(fsb_hi, msi_addr);
        }

        // Double-write of comparator: absolute first, then period.
        // SAFETY: same.
        let now = unsafe { read_u64(self.base_phys + REG_MAIN_CNT) };
        let trigger = now.wrapping_add(period_ticks);
        let trigger_w = if cfg & TN_32MODE_CNF != 0 {
            trigger & 0xFFFF_FFFF
        } else {
            trigger
        };
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_COMPARATOR, trigger_w) };
        let period_w = if cfg & TN_32MODE_CNF != 0 {
            period_ticks & 0xFFFF_FFFF
        } else {
            period_ticks
        };
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_COMPARATOR, period_w) };

        // Clear status latch (MSI is edge-triggered so the latch
        // shouldn't accumulate, but Linux clears it on init).
        // SAFETY: same.
        unsafe { write_u64(self.base_phys + REG_INT_STS, 1u64 << n) };

        // Enable interrupt delivery.
        cfg |= TN_INT_ENB_CNF;
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_CONFIG, cfg) };
    }

    /// Disable comparator `n` (clear `Tn_INT_ENB_CNF`) and clear
    /// any pending status latch.
    ///
    /// # Safety
    /// Same as [`Self::arm_oneshot_comparator`].
    pub unsafe fn disarm_comparator(&self, n: u8) {
        let block = self.timer_block(n);
        // SAFETY: caller-asserted live window + valid index.
        let cfg = unsafe { read_u64(block + TIMER_REG_CONFIG) };
        // SAFETY: same.
        unsafe { write_u64(block + TIMER_REG_CONFIG, cfg & !TN_INT_ENB_CNF) };
        // SAFETY: same.
        unsafe { write_u64(self.base_phys + REG_INT_STS, 1u64 << n) };
    }

    /// Clear the level-mode latch for comparator `n` (§3.2.3).
    /// Edge-triggered timers do not latch — calling this on an
    /// edge-mode timer is a no-op the hardware silently absorbs.
    ///
    /// # Safety
    /// Same as [`Self::arm_oneshot_comparator`].
    pub unsafe fn clear_status(&self, n: u8) {
        // SAFETY: caller-asserted live window + valid index.
        unsafe { write_u64(self.base_phys + REG_INT_STS, 1u64 << n) };
    }
}

// ── Singleton + raw reads ──────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn read_u64(phys: u64) -> u64 {
    // SAFETY: caller-asserted identity-mapped MMIO.
    unsafe { core::ptr::read_volatile(phys as *const u64) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_u64(phys: u64, v: u64) {
    // SAFETY: caller-asserted identity-mapped MMIO.
    unsafe {
        core::ptr::write_volatile(phys as *mut u64, v);
    }
}

// On non-x86_64, HPET doesn't exist (Generic Timer fills the role).
// Stub the helpers so the module compiles cross-arch.
#[cfg(not(target_arch = "x86_64"))]
unsafe fn read_u64(_phys: u64) -> u64 {
    0
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn write_u64(_phys: u64, _v: u64) {}

static HPET: IrqSafeSpinLock<Option<Hpet>> = IrqSafeSpinLock::new(None);
static BASE_OVERRIDE: AtomicU64 = AtomicU64::new(0);

/// Override the HPET MMIO base — for ACPI HPET-table parsing.
/// Must be called before [`init`].
///
/// Despite the name this is the address the driver DEREFERENCES, not
/// necessarily a physical one. `frame` now passes the `ioremap` virtual
/// base: HPET lives below 4 GiB, and that region stopped being mapped in
/// every address space when PML4[0] became user space.
pub fn set_base_phys(phys: u64) {
    BASE_OVERRIDE.store(phys, Ordering::Release);
}

/// Physical base the caller should `ioremap` before calling
/// [`set_base_phys`] with the resulting virtual address: the
/// ACPI-provided override if one was recorded, else the architectural
/// default.
pub fn base_phys_for_ioremap() -> u64 {
    match BASE_OVERRIDE.load(Ordering::Acquire) {
        0 => HPET_DEFAULT_BASE,
        v => v,
    }
}

/// Probe + enable HPET. Returns `Ok` on x86_64 with a working
/// HPET, `Err(NotPresent)` everywhere else (aarch64) or when the
/// HPET window is inert.
///
/// # Safety
/// First-caller wins; callers assert single-threaded boot context.
pub unsafe fn init() -> Result<(), HpetError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(HpetError::NotPresent);
    }
    let base = match BASE_OVERRIDE.load(Ordering::Acquire) {
        0 => HPET_DEFAULT_BASE,
        v => v,
    };
    // SAFETY: caller-asserted boot-time exclusivity.
    let dev = unsafe { Hpet::probe(base) }?;
    // SAFETY: caller asserted single-threaded.
    unsafe {
        dev.enable();
    }
    *HPET.lock() = Some(dev);
    Ok(())
}

/// Tick frequency in Hz (0 if HPET wasn't initialised).
pub fn frequency_hz() -> u64 {
    HPET.lock().as_ref().map_or(0, |h| h.caps.frequency_hz())
}

/// Read the main counter (0 if HPET wasn't initialised).
pub fn read_counter() -> u64 {
    let g = HPET.lock();
    match g.as_ref() {
        Some(h) => {
            // SAFETY: HPET stays alive for the lifetime of the
            // singleton; the lock holds for the read.
            // SAFETY: Valid memory or trusted environment
            unsafe { h.read_counter() }
        }
        None => 0,
    }
}

/// Capabilities snapshot (None if HPET wasn't initialised).
pub fn caps() -> Option<HpetCaps> {
    HPET.lock().as_ref().map(|h| h.caps)
}

/// `true` iff HPET probe succeeded.
pub fn is_present() -> bool {
    HPET.lock().is_some()
}

/// Convert a HPET tick delta to nanoseconds. Returns 0 if HPET
/// isn't initialised or the period is degenerate.
pub fn ticks_to_nanos(ticks: u64) -> u64 {
    let g = HPET.lock();
    match g.as_ref() {
        Some(h) => {
            let period_fs = h.caps.clk_period_fs as u64;
            // ns = ticks * period_fs / 1_000_000.
            ticks.saturating_mul(period_fs) / 1_000_000
        }
        None => 0,
    }
}

/// Number of comparators reported by the singleton HPET (0 if HPET
/// wasn't initialised).
pub fn num_comparators() -> u8 {
    HPET.lock().as_ref().map_or(0, |h| h.caps.num_comparators)
}

/// `Tn_INT_ROUTE_CAP` for comparator `n` — bitmask of GSIs the
/// timer can drive. Returns 0 when HPET isn't initialised or `n`
/// is out of range.
pub fn timer_route_cap(n: u8) -> u32 {
    let g = HPET.lock();
    match g.as_ref() {
        Some(h) if n < h.caps.num_comparators => {
            // SAFETY: HPET singleton alive for the lock scope; index
            // bounded against `num_comparators`.
            // SAFETY: Valid memory or trusted environment
            unsafe { h.timer_route_cap(n) }
        }
        _ => 0,
    }
}

/// `true` when comparator `n` is a 64-bit timer
/// (`Tn_SIZE_CAP`, §2.3.5). `false` when HPET isn't initialised
/// or `n` is out of range — callers should treat the comparator as
/// 32-bit in that case (the safer assumption for deadline math).
pub fn timer_is_64bit(n: u8) -> bool {
    let g = HPET.lock();
    match g.as_ref() {
        Some(h) if n < h.caps.num_comparators => {
            // SAFETY: same as `timer_route_cap`.
            unsafe { h.timer_is_64bit(n) }
        }
        _ => false,
    }
}

/// Outcome of [`arm_oneshot`] / [`arm_periodic`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArmError {
    /// HPET wasn't initialised.
    NotPresent,
    /// `n >= num_comparators`.
    BadComparator,
    /// `gsi` is not a member of `Tn_INT_ROUTE_CAP` for this timer
    /// — the comparator can't drive that line.
    BadGsi,
    /// Periodic-mode arm requested but `Tn_PER_INT_CAP == 0` on
    /// this comparator. Spec guarantees periodic mode only on
    /// timer 0; pick another comparator.
    NoPeriodic,
}

/// Program comparator `n` for a one-shot wakeup at `deadline`
/// (HPET ticks) routed to `gsi`. The caller must already have
/// installed an IDT vector + IOAPIC redirection for `gsi` — this
/// only touches the HPET MMIO. See `narf-interrupts::hpet_oneshot`
/// for the integrated `vector::alloc` + IOAPIC + HPET path.
///
/// Returns `Err(BadGsi)` when `gsi` isn't in this timer's
/// `Tn_INT_ROUTE_CAP`. The hardware is left untouched in the
/// error case.
///
/// # Safety
/// Caller asserts the HPET MMIO window is live and that the IDT /
/// IOAPIC plumbing for `gsi` is in place before this fires.
pub unsafe fn arm_oneshot(n: u8, gsi: u8, deadline: u64) -> Result<(), ArmError> {
    let g = HPET.lock();
    let h = g.as_ref().ok_or(ArmError::NotPresent)?;
    if n >= h.caps.num_comparators {
        return Err(ArmError::BadComparator);
    }
    // SAFETY: lock scope keeps singleton alive; index bounded.
    let route_cap = unsafe { h.timer_route_cap(n) };
    if gsi >= 32 || (route_cap & (1u32 << gsi)) == 0 {
        return Err(ArmError::BadGsi);
    }
    // SAFETY: caller-asserted IDT/IOAPIC readiness; index bounded;
    // GSI validated against the route-cap mask.
    // SAFETY: Valid memory or trusted environment
    unsafe { h.arm_oneshot_comparator(n, gsi, deadline) };
    Ok(())
}

/// Arm comparator `n` in PERIODIC mode firing every
/// `period_ticks` HPET ticks on `gsi`. Returns `Err` if HPET
/// isn't initialised, `n` is out of range, `gsi` isn't in the
/// timer's route-cap mask, or the timer doesn't support periodic
/// mode (`Tn_PER_INT_CAP == 0`).
///
/// # Safety
/// Caller asserts HPET MMIO is live and that IDT / IOAPIC
/// plumbing for `gsi` is in place before this fires.
pub unsafe fn arm_periodic(n: u8, gsi: u8, period_ticks: u64) -> Result<(), ArmError> {
    let g = HPET.lock();
    let h = g.as_ref().ok_or(ArmError::NotPresent)?;
    if n >= h.caps.num_comparators {
        return Err(ArmError::BadComparator);
    }
    if !h.supports_periodic(n) {
        return Err(ArmError::NoPeriodic);
    }
    // SAFETY: index bounded.
    let route_cap = unsafe { h.timer_route_cap(n) };
    if gsi >= 32 || (route_cap & (1u32 << gsi)) == 0 {
        return Err(ArmError::BadGsi);
    }
    // SAFETY: caller-asserted IDT/IOAPIC readiness; index + gsi
    // validated.
    // SAFETY: Valid memory or trusted environment
    unsafe { h.arm_periodic_comparator(n, gsi, period_ticks) };
    Ok(())
}

/// Clear the level-mode status latch for comparator `n`. Must
/// be called from the comparator's ISR before re-arming the
/// IOAPIC line (HPET §3.2.3). Returns `Err` if HPET isn't
/// initialised or `n` is out of range.
///
/// # Safety
/// Caller asserts the HPET MMIO window is live.
pub unsafe fn clear_status(n: u8) -> Result<(), ArmError> {
    let g = HPET.lock();
    let h = g.as_ref().ok_or(ArmError::NotPresent)?;
    if n >= h.caps.num_comparators {
        return Err(ArmError::BadComparator);
    }
    // SAFETY: index bounded; HPET MMIO live for the lock scope.
    unsafe { h.clear_status(n) };
    Ok(())
}

/// True iff comparator `n` supports periodic mode. Diagnostic;
/// callers should pick the lowest-numbered timer that returns
/// true.
pub fn comparator_supports_periodic(n: u8) -> bool {
    let g = HPET.lock();
    let h = match g.as_ref() {
        Some(h) => h,
        None => return false,
    };
    h.supports_periodic(n)
}

/// True iff comparator `n` supports FSB-MSI delivery. When true,
/// callers should prefer [`arm_periodic_msi`] over the IOAPIC
/// routing path — MSI bypasses the IOAPIC and gives a direct
/// LAPIC delivery, which works on platforms (Renoir) where the
/// IOAPIC silently drops HPET's GSI.
pub fn comparator_supports_fsb(n: u8) -> bool {
    let g = HPET.lock();
    let h = match g.as_ref() {
        Some(h) => h,
        None => return false,
    };
    h.supports_fsb(n)
}

/// Arm comparator `n` in periodic mode with FSB-MSI delivery.
/// `msi_addr` and `msi_data` are the standard PCI MSI message
/// format: address typically `0xFEE0_0000 | (apic_id << 12)`,
/// data carries vector + delivery + trigger encoding.
///
/// # Safety
/// Caller asserts the HPET MMIO window is live, comparator `n`
/// is not being used by another driver, and `comparator_supports_fsb(n)`
/// returned true.
pub unsafe fn arm_periodic_msi(
    n: u8,
    msi_addr: u32,
    msi_data: u32,
    period_ticks: u64,
) -> Result<(), ArmError> {
    let g = HPET.lock();
    let h = g.as_ref().ok_or(ArmError::NotPresent)?;
    if n >= h.caps.num_comparators {
        return Err(ArmError::BadComparator);
    }
    if !h.supports_periodic(n) {
        return Err(ArmError::NoPeriodic);
    }
    if !h.supports_fsb(n) {
        return Err(ArmError::BadComparator);
    }
    // SAFETY: caller-asserted live window; index bounded;
    // capability checks above.
    // SAFETY: Valid memory or trusted environment
    unsafe { h.arm_periodic_msi_comparator(n, msi_addr, msi_data, period_ticks) };
    // SAFETY: same.
    unsafe { h.clear_status(n) };
    Ok(())
}

/// Disarm comparator `n` (clear enable + status latch). Returns
/// `Err` if HPET isn't initialised or `n` is out of range.
///
/// # Safety
/// Caller asserts the HPET MMIO window is live.
pub unsafe fn disarm(n: u8) -> Result<(), ArmError> {
    let g = HPET.lock();
    let h = g.as_ref().ok_or(ArmError::NotPresent)?;
    if n >= h.caps.num_comparators {
        return Err(ArmError::BadComparator);
    }
    // SAFETY: caller-asserted live window; index bounded.
    unsafe { h.disarm_comparator(n) };
    Ok(())
}

/// Read `Tn_CONFIG_AND_CAP` for comparator `n`, or `None` when HPET
/// is not present / `n` is out of range. Diagnostic helper for
/// drivers that want to inspect their programming.
pub fn read_timer_config(n: u8) -> Option<u64> {
    let g = HPET.lock();
    let h = g.as_ref()?;
    if n >= h.caps.num_comparators {
        return None;
    }
    // SAFETY: HPET singleton alive for the lock scope; index bounded.
    Some(unsafe { h.read_timer_config(n) })
}

#[doc(hidden)]
pub fn __reset_for_test() {
    *HPET.lock() = None;
    BASE_OVERRIDE.store(0, Ordering::Release);
}

/// HPET-driven TSC calibration. Snaps HPET + TSC at the start of a
/// short busy-wait, then again at the end, and computes
/// `tsc_hz = Δtsc * hpet_hz / Δhpet`. Returns `Some(hz)` on
/// success or `None` if HPET isn't initialised, the period reads
/// degenerate, or no HPET ticks were observed during the wait
/// (clock stuck — the caller should retry from a different source).
///
/// The `calibration_window_hpet_ticks` argument bounds the
/// busy-wait length in HPET ticks. With a typical 14.318 MHz HPET,
/// a 100 ms window is ~1.4M ticks — long enough to dwarf the few
/// hundred TSC cycles that bracket a single MMIO read, short
/// enough to keep boot snappy.
#[cfg(target_arch = "x86_64")]
pub fn calibrate_tsc_via_hpet(calibration_window_hpet_ticks: u64) -> Option<u64> {
    let hpet_hz = frequency_hz();
    if hpet_hz == 0 || calibration_window_hpet_ticks == 0 {
        return None;
    }
    let g = HPET.lock();
    let dev = g.as_ref()?;
    // SAFETY: HPET singleton is alive for the lock scope; the
    // window read is volatile + naturally aligned.
    // SAFETY: Valid memory or trusted environment
    let hpet_t0 = unsafe { dev.read_counter() };
    let tsc_t0 = narf_arch::x86_64::tsc::rdtsc();
    let hpet_deadline = hpet_t0.wrapping_add(calibration_window_hpet_ticks);
    // Tight loop on HPET — RDTSC + an MMIO read per iteration is
    // fine for a one-shot boot-time calibration.
    loop {
        // SAFETY: same as above.
        let now = unsafe { dev.read_counter() };
        if now.wrapping_sub(hpet_t0) >= calibration_window_hpet_ticks || now == hpet_deadline {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: same.
    let hpet_t1 = unsafe { dev.read_counter() };
    let tsc_t1 = narf_arch::x86_64::tsc::rdtsc();
    drop(g);
    let d_hpet = hpet_t1.wrapping_sub(hpet_t0);
    let d_tsc = tsc_t1.wrapping_sub(tsc_t0);
    if d_hpet == 0 {
        return None;
    }
    // tsc_hz = d_tsc * hpet_hz / d_hpet — stay in u64. Worst case
    // 5 GHz TSC × ~100 MHz HPET × 100 ms window ≈ 5e16, comfortably
    // below u64::MAX (1.8e19). The previous u128-widened form lowered
    // to a `__udivti3` call in compiler-builtins that thin LTO failed
    // to relocate correctly — non-canonical RIP, #GP. Plain u64
    // arithmetic produces the same result inline.
    let prod = d_tsc.saturating_mul(hpet_hz);
    let hz = prod / d_hpet;
    if hz == 0 {
        None
    } else {
        Some(hz)
    }
}
