//! DesignWare APB GPIO register layout — clean-room.
//!
//! ## Reference (public only)
//!
//! - **Synopsys DesignWare APB GPIO** databook (datasheet-grade
//!   public excerpts; common to many ARM SoCs that license the IP).
//!   Register names + offsets used here are the IP's public layout.
//!
//! No GPL / Linux source consulted.
//!
//! ## Layout
//!
//! Up to 4 banks (A-D), each with 32 pins. Per-bank registers (32-bit)
//! at the offsets below. Bit `i` of every register corresponds to
//! pin `i` of the bank.

extern crate alloc;

/// Offsets within the GPIO controller MMIO. Bank-A only — Bank-B/C/D
/// add `+0x0C` per extra bank (see [`bank_offset`]).
pub mod regs {
    pub const SWPORTA_DR: usize = 0x00; // Bank A Data
    pub const SWPORTA_DDR: usize = 0x04; // Bank A Data Direction (1 = output)
    pub const SWPORTA_CTL: usize = 0x08; // Bank A Source Select (0 = sw, 1 = hw)
    pub const SWPORTB_DR: usize = 0x0C;
    pub const SWPORTB_DDR: usize = 0x10;
    pub const SWPORTB_CTL: usize = 0x14;
    pub const SWPORTC_DR: usize = 0x18;
    pub const SWPORTC_DDR: usize = 0x1C;
    pub const SWPORTC_CTL: usize = 0x20;
    pub const SWPORTD_DR: usize = 0x24;
    pub const SWPORTD_DDR: usize = 0x28;
    pub const SWPORTD_CTL: usize = 0x2C;
    pub const INTEN: usize = 0x30; // Interrupt Enable (Bank A only)
    pub const INTMASK: usize = 0x34; // Interrupt Mask (Bank A only)
    pub const INTTYPE_LEVEL: usize = 0x38; // 0 = level, 1 = edge
    pub const INT_POLARITY: usize = 0x3C; // 0 = active-low/falling, 1 = active-high/rising
    pub const INTSTATUS: usize = 0x40;
    pub const RAW_INTSTATUS: usize = 0x44;
    pub const DEBOUNCE: usize = 0x48;
    pub const PORTA_EOI: usize = 0x4C; // Write 1 to clear Bank-A IRQ status bit
    pub const EXT_PORTA: usize = 0x50; // External port read-back
    pub const EXT_PORTB: usize = 0x54;
    pub const EXT_PORTC: usize = 0x58;
    pub const EXT_PORTD: usize = 0x5C;
}

/// Returns the (DR, DDR, CTL) offsets for a given bank index (0..=3).
pub fn bank_offset(bank: u8) -> Option<(usize, usize, usize)> {
    match bank {
        0 => Some((regs::SWPORTA_DR, regs::SWPORTA_DDR, regs::SWPORTA_CTL)),
        1 => Some((regs::SWPORTB_DR, regs::SWPORTB_DDR, regs::SWPORTB_CTL)),
        2 => Some((regs::SWPORTC_DR, regs::SWPORTC_DDR, regs::SWPORTC_CTL)),
        3 => Some((regs::SWPORTD_DR, regs::SWPORTD_DDR, regs::SWPORTD_CTL)),
        _ => None,
    }
}

/// Compute a new DDR / DR pair for setting pin `pin` (0..=31) of
/// bank `bank` to output mode and driving `value`.
pub fn make_set_output(prev_ddr: u32, prev_dr: u32, pin: u8, value: bool) -> (u32, u32) {
    let mask = 1u32 << (pin & 0x1F);
    let ddr = prev_ddr | mask;
    let dr = if value {
        prev_dr | mask
    } else {
        prev_dr & !mask
    };
    (ddr, dr)
}

/// Compute a new DDR for setting pin `pin` to input mode.
pub fn make_set_input(prev_ddr: u32, pin: u8) -> u32 {
    prev_ddr & !(1u32 << (pin & 0x1F))
}

/// Read the level of pin `pin` from a snapshot of `EXT_PORTx`.
pub fn pin_level(ext_port: u32, pin: u8) -> bool {
    ext_port & (1u32 << (pin & 0x1F)) != 0
}

/// Build interrupt config: bit `i` of each return value programs
/// pin `i`. `edge_triggered = true` → INTTYPE_LEVEL bit set.
/// `rising_or_high = true` → INT_POLARITY bit set.
pub fn make_interrupt_config(
    pin: u8,
    edge_triggered: bool,
    rising_or_high: bool,
) -> (u32, u32, u32) {
    let mask = 1u32 << (pin & 0x1F);
    let inten = mask;
    let inttype_level = if edge_triggered { mask } else { 0 };
    let int_polarity = if rising_or_high { mask } else { 0 };
    (inten, inttype_level, int_polarity)
}
