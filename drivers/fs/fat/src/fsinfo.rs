//! FAT32 FSInfo sector structure.
//!
//! Based on Microsoft FAT Gen1 Specification (v1.03), pages 21-22.
//! URL: https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct FsInfo {
    pub lead_sig: u32, // 0x41615252
    pub reserved1: [u8; 480],
    pub struc_sig: u32,  // 0x61417272
    pub free_count: u32, // Hint for free cluster count (0xFFFFFFFF if unknown)
    pub nxt_free: u32,   // Hint for next free cluster
    pub reserved2: [u8; 12],
    pub trail_sig: u32, // 0xAA550000
}

impl FsInfo {
    pub const LEAD_SIG: u32 = 0x41615252;
    pub const STRUC_SIG: u32 = 0x61417272;
    pub const TRAIL_SIG: u32 = 0xAA550000;

    pub fn is_valid(&self) -> bool {
        self.lead_sig == Self::LEAD_SIG
            && self.struc_sig == Self::STRUC_SIG
            && self.trail_sig == Self::TRAIL_SIG
    }
}
