//! `ATOM_DCN_INIT_DATA` walker — clean-room.
//!
//! Reference: AMD `AtomBios.h` (MIT-licensed structure shape).
//! The DCN init-data table (id `0x14` per AtomBios.h) carries
//! per-board display-engine initialization parameters: maximum
//! pixel clock, DCE engine count, default scanout pixel format,
//! and the boot-display preferred mode.
//!
//! ## Layout (V1.x)
//!
//! ```text
//! +0x00   ATOM_COMMON_TABLE_HEADER (4 B)
//! +0x04   ulMaxDispEngineNum            u8
//! +0x05   ulMaxActiveDispEngineNum      u8
//! +0x06   ulMaxPPLLNum                  u8
//! +0x07   ulCoreRefClkSource            u8
//! +0x08   ulDispClkUsed                 u32  (10 kHz units)
//! +0x0C   ulMaxDispclk                  u32  (10 kHz units)
//! +0x10   ulBootDispMode_h_active       u16
//! +0x12   ulBootDispMode_v_active       u16
//! +0x14   ulBootDispMode_pixel_clock    u32  (10 kHz units)
//! +0x18   ucBootDispMode_format         u8   (0=XRGB8888, …)
//! +0x19   ucReserved[3]
//! ```
//!
//! Stage-7 ships V1 decoding. The table appears with the same
//! shape on Vega+ (DCN1+) chips; older Carrizo / Tonga used a
//! different layout we don't bother with.

use core::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DcnInitError {
    Truncated,
    UnsupportedVersion(u8),
}

/// Decoded `ATOM_DCN_INIT_DATA` payload.
#[derive(Copy, Clone)]
pub struct DcnInitData {
    pub structure_size:        u16,
    pub format_revision:       u8,
    pub content_revision:      u8,
    pub max_disp_engines:      u8,
    pub max_active_engines:    u8,
    pub max_ppll:              u8,
    pub core_ref_clk_source:   u8,
    pub disp_clk_used_10khz:   u32,
    pub max_disp_clk_10khz:    u32,
    pub boot_h_active:         u16,
    pub boot_v_active:         u16,
    pub boot_pixel_clock_10khz: u32,
    pub boot_format_code:      u8,
}

impl fmt::Debug for DcnInitData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DcnInitData")
            .field("rev", &(self.format_revision, self.content_revision))
            .field("max_engines",  &self.max_disp_engines)
            .field("active",       &self.max_active_engines)
            .field("max_dispclk_mhz", &(self.max_disp_clk_10khz / 100))
            .field("boot_mode",    &(self.boot_h_active, self.boot_v_active))
            .field("boot_pclk_mhz", &(self.boot_pixel_clock_10khz / 100))
            .finish()
    }
}

/// Decode a `ATOM_DCN_INIT_DATA` table. Caller obtains the
/// slice via `Atombios::data_table(0x14)`.
pub fn parse(raw: &[u8]) -> Result<DcnInitData, DcnInitError> {
    // Minimum table size: 4 byte header + 0x16 byte body = 0x1A.
    if raw.len() < 0x1A { return Err(DcnInitError::Truncated); }
    let structure_size   = u16::from_le_bytes([raw[0], raw[1]]);
    let format_revision  = raw[2];
    let content_revision = raw[3];
    if format_revision != 1 {
        return Err(DcnInitError::UnsupportedVersion(format_revision));
    }
    let read_u32 = |o: usize| u32::from_le_bytes([
        raw[o], raw[o + 1], raw[o + 2], raw[o + 3],
    ]);
    let read_u16 = |o: usize| u16::from_le_bytes([raw[o], raw[o + 1]]);
    Ok(DcnInitData {
        structure_size, format_revision, content_revision,
        max_disp_engines:      raw[0x04],
        max_active_engines:    raw[0x05],
        max_ppll:              raw[0x06],
        core_ref_clk_source:   raw[0x07],
        disp_clk_used_10khz:   read_u32(0x08),
        max_disp_clk_10khz:    read_u32(0x0C),
        boot_h_active:         read_u16(0x10),
        boot_v_active:         read_u16(0x12),
        boot_pixel_clock_10khz: read_u32(0x14),
        boot_format_code:      raw[0x18],
    })
}
