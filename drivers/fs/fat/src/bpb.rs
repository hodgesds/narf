//! BIOS Parameter Block (BPB) structures.
//!
//! Based on Microsoft FAT Gen1 Specification (v1.03), pages 7-13.
//! URL: https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf

use super::FatVersion;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Bpb {
    pub jmp_boot: [u8; 3],
    pub oem_name: [u8; 8],
    pub bytes_per_sec: u16,
    pub sec_per_clus: u8,
    pub rsvd_sec_cnt: u16,
    pub num_fats: u8,
    pub root_ent_cnt: u16,
    pub tot_sec_16: u16,
    pub media: u8,
    pub fat_sz_16: u16,
    pub sec_per_trk: u16,
    pub num_heads: u16,
    pub hidd_sec: u32,
    pub tot_sec_32: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Fat16ExtBpb {
    pub drv_num: u8,
    pub reserved1: u8,
    pub boot_sig: u8,
    pub vol_id: u32,
    pub vol_lab: [u8; 11],
    pub fil_sys_type: [u8; 8],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Fat32ExtBpb {
    pub fat_sz_32: u32,
    pub ext_flags: u16,
    pub fs_ver: u16,
    pub root_clus: u32,
    pub fs_info: u16,
    pub bk_boot_sec: u16,
    pub reserved: [u8; 12],
    pub drv_num: u8,
    pub reserved1: u8,
    pub boot_sig: u8,
    pub vol_id: u32,
    pub vol_lab: [u8; 11],
    pub fil_sys_type: [u8; 8],
}

impl Bpb {
    pub fn total_sectors(&self) -> u32 {
        if self.tot_sec_16 != 0 {
            self.tot_sec_16 as u32
        } else {
            self.tot_sec_32
        }
    }

    pub fn fat_size(&self, fat32_ext: Option<&Fat32ExtBpb>) -> u32 {
        if self.fat_sz_16 != 0 {
            self.fat_sz_16 as u32
        } else if let Some(ext) = fat32_ext {
            ext.fat_sz_32
        } else {
            0
        }
    }

    /// Determine FAT version based on cluster count logic (MS spec p. 14).
    pub fn detect_version(&self, fat32_ext: Option<&Fat32ExtBpb>) -> FatVersion {
        let root_dir_sectors = (self.root_ent_cnt as u32 * 32).div_ceil(self.bytes_per_sec as u32);
        let fat_size = self.fat_size(fat32_ext);
        let data_sectors = self.total_sectors()
            - (self.rsvd_sec_cnt as u32 + (self.num_fats as u32 * fat_size) + root_dir_sectors);
        let count_of_clusters = data_sectors / self.sec_per_clus as u32;

        if count_of_clusters < 4085 {
            FatVersion::Fat12
        } else if count_of_clusters < 65525 {
            FatVersion::Fat16
        } else {
            FatVersion::Fat32
        }
    }
}
