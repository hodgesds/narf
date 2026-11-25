#![cfg(target_arch = "x86_64")]
//! Fixture tests for the AQC1xx older-generations (hw_atl) driver.
//!
//! The fake here carries its own `FAKE_*` literals transcribed from the
//! Linux atlantic sources (`drivers/net/ethernet/aquantia/atlantic/`,
//! torvalds/linux @ 4dce97c6c265544342e716e62fd24bbb232590c5), independent of
//! the driver constants, so a shared transcription error cannot hide
//! behind both sides. The fake models a device conversation, not the
//! driver: register writes have side effects (MIF download steps, MPI
//! state transitions, RBL/FLB boot paths, the A0 register-reset dance).
//!
//! Pure tests assert hand-computed literals. Conversation tests assert
//! the exact register values the bring-up sequence leaves behind.
//!
//! Assertions are panic-free (`kt_assert!` / `kt_assert_eq!`): the test
//! kernel cannot unwind, so a panicking smoke would take the whole run
//! down and silently skip every test after it.

use alloc::vec::Vec;
use core::cell::RefCell;

use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, kt_assert_ne, TestResult};

use super::*;

use crate::aqc113::RegIo as _;
use crate::aqc113::{reg_rpf_uc_ctl, reg_rpf_uc_daflsw, reg_rx_dma_tail};

// ---------------------------------------------------------------------------
// Fake device (Linux-literal register model)
// ---------------------------------------------------------------------------

const FAKE_MIF_CMD: u64 = 0x200;
const FAKE_MIF_CMD_START: u32 = 0x8000;
const FAKE_MIF_ADDR: u64 = 0x208;
const FAKE_MIF_VAL: u64 = 0x20C;
const FAKE_MIF_ID: u64 = 0x1C;
const FAKE_FW_VER: u64 = 0x18;
const FAKE_MPI_RPC_ADDR: u64 = 0x334;
const FAKE_MPI_CONTROL: u64 = 0x368;
const FAKE_MPI_STATE_1X: u64 = 0x36C;
const FAKE_MPI_STATE_2X: u64 = 0x370;
const FAKE_UCP_0X370: u64 = 0x370;
const FAKE_EFUSE_1X: u64 = 0x374;
const FAKE_EFUSE_2X: u64 = 0x364;
const FAKE_MBOX_ADDR: u64 = 0x360;
const FAKE_BOOT_EXIT_CODE: u64 = 0x388;
const FAKE_DAISY_CHAIN: u64 = 0x704;
const FAKE_BOOT_MARKER: u32 = 0xDEAD;
const FAKE_GLB_SOFT_RES: u64 = 0x0;
const FAKE_ITR_RES: u64 = 0x2300;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FakeBoot {
    /// Flashless boot: 0x704 gains bit 0x10 when 0x404 is written 0x180e0.
    Flb,
    /// ROM boot: 0x388 reads back this status once the marker is written.
    Rbl(u32),
    /// Neither RBL nor FLB: 0x704 reads 0x06000000, 0x388 reads 0.
    Neither,
}

struct FakeRegs {
    bank: RefCell<Vec<(u64, u32)>>,
    log: RefCell<Vec<(u64, u32)>>,
    mif_mem: RefCell<Vec<(u32, u32)>>,
    mif_addr: RefCell<u32>,
    mif_val: RefCell<u32>,
    mif_cmd: RefCell<u32>,
    fw_version: u32,
    mif_id: u32,
    mbox_addr: u32,
    rpc_addr: u32,
    efuse_addr: u32,
    /// FW1x MPI state word (0x36C): low byte state, bits[23:16] HAL speed.
    mpi_state: RefCell<u32>,
    /// FW2x MPI state word (0x370): FW2X_RATE_* bits.
    mpi_state_2x: RefCell<u32>,
    /// HAL speed code the fake firmware reports after MPI_INIT (FW1x).
    negotiated_hal: u32,
    ucp370: RefCell<u32>,
    boot: FakeBoot,
    daisy: RefCell<bool>,
    /// When set, MPI_CONTROL writes never move the MPI state (DEINIT hangs).
    mpi_state_frozen: bool,
    /// When set, MIF downloads never complete.
    mif_stuck: bool,
    fw2x_mode: bool,
}

impl FakeRegs {
    fn new() -> Self {
        Self::with_boot(FakeBoot::Flb)
    }

    fn with_boot(boot: FakeBoot) -> Self {
        let fake = Self {
            bank: RefCell::new(Vec::new()),
            log: RefCell::new(Vec::new()),
            mif_mem: RefCell::new(Vec::new()),
            mif_addr: RefCell::new(0),
            mif_val: RefCell::new(0),
            mif_cmd: RefCell::new(0),
            fw_version: 0x01050006,
            mif_id: 0x0000000A,
            mbox_addr: 0x0010_0000,
            rpc_addr: 0x0020_0000,
            efuse_addr: 0x0000_1000,
            mpi_state: RefCell::new(0),
            mpi_state_2x: RefCell::new(0),
            negotiated_hal: 8,
            ucp370: RefCell::new(0x12345678),
            boot,
            daisy: RefCell::new(false),
            mpi_state_frozen: false,
            mif_stuck: false,
            fw2x_mode: false,
        };
        // Mailbox header at mbox_addr: [version=1, tid=7, error=0].
        fake.mif_write(fake.mbox_addr, 1);
        fake.mif_write(fake.mbox_addr + 4, 7);
        fake.mif_write(fake.mbox_addr + 8, 0);
        fake
    }

    fn mif_read(&self, addr: u32) -> u32 {
        self.mif_mem
            .borrow()
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }

    fn mif_write(&self, addr: u32, value: u32) {
        let mut mem = self.mif_mem.borrow_mut();
        if let Some(slot) = mem.iter_mut().find(|(a, _)| *a == addr) {
            slot.1 = value;
        } else {
            mem.push((addr, value));
        }
    }

    /// Preload the two efuse MAC dwords at `efuse_addr + 160`.
    /// Linux's `hw_atl_utils_get_mac_permanent` byte-swaps each
    /// downloaded dword and copies the bytes in order, so the MAC
    /// is the big-endian bytes of the first dword followed by
    /// the big-endian bytes of the second: word 0 holds bytes
    /// 0..4, word 1 holds bytes 4..6 in its top half.
    fn preload_efuse_mac(&self, mac: [u8; 6]) {
        let lo = ((mac[0] as u32) << 24)
            | ((mac[1] as u32) << 16)
            | ((mac[2] as u32) << 8)
            | mac[3] as u32;
        let hi = ((mac[4] as u32) << 24) | ((mac[5] as u32) << 16);
        self.mif_write(self.efuse_addr + 160, lo);
        self.mif_write(self.efuse_addr + 164, hi);
    }

    fn bank_read(&self, off: u64) -> u32 {
        self.bank
            .borrow()
            .iter()
            .rev()
            .find(|(a, _)| *a == off)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }

    fn bank_write(&self, off: u64, value: u32) {
        let mut bank = self.bank.borrow_mut();
        if let Some(slot) = bank.iter_mut().rev().find(|(a, _)| *a == off) {
            slot.1 = value;
        } else {
            bank.push((off, value));
        }
    }

    fn observed(&self, off: u64) -> u32 {
        self.read32(off)
    }

    fn logged(&self, off: u64, value: u32) -> bool {
        self.log
            .borrow()
            .iter()
            .any(|(a, v)| *a == off && *v == value)
    }

    fn logged_any(&self, off: u64) -> bool {
        self.log.borrow().iter().any(|(a, _)| *a == off)
    }

    fn set_fw2x(&mut self) {
        self.fw2x_mode = true;
    }
}

impl RegIo for FakeRegs {
    fn read32(&self, off: u64) -> u32 {
        match off {
            FAKE_FW_VER => self.fw_version,
            FAKE_MIF_ID => self.mif_id,
            FAKE_MIF_CMD => *self.mif_cmd.borrow(),
            FAKE_MIF_ADDR => *self.mif_addr.borrow(),
            FAKE_MIF_VAL => *self.mif_val.borrow(),
            FAKE_MPI_RPC_ADDR => self.rpc_addr,
            FAKE_MBOX_ADDR => self.mbox_addr,
            FAKE_EFUSE_1X => self.efuse_addr,
            FAKE_EFUSE_2X => self.efuse_addr,
            FAKE_MPI_STATE_1X => {
                if self.fw2x_mode {
                    self.bank_read(off)
                } else {
                    *self.mpi_state.borrow()
                }
            }
            FAKE_MPI_STATE_2X => {
                if self.fw2x_mode {
                    *self.mpi_state_2x.borrow()
                } else {
                    *self.ucp370.borrow()
                }
            }
            FAKE_BOOT_EXIT_CODE => match self.boot {
                FakeBoot::Rbl(status) => status,
                _ => 0,
            },
            FAKE_DAISY_CHAIN => match self.boot {
                FakeBoot::Neither => 0x06000000,
                FakeBoot::Flb => {
                    if *self.daisy.borrow() {
                        0x10
                    } else {
                        0
                    }
                }
                FakeBoot::Rbl(_) => 0,
            },
            0x3A0 | 0x3A8 | 0x3AC | 0x3B0 => 1,
            _ => self.bank_read(off),
        }
    }

    fn write32(&self, off: u64, value: u32) {
        self.log.borrow_mut().push((off, value));
        match off {
            FAKE_MIF_ADDR => *self.mif_addr.borrow_mut() = value,
            FAKE_MIF_CMD => {
                *self.mif_cmd.borrow_mut() = value;
                if value & FAKE_MIF_CMD_START != 0 && !self.mif_stuck {
                    // One download step: the firmware loads MIF_VAL from the
                    // device memory at MIF_ADDR, advances MIF_ADDR by 4 and
                    // clears the busy bit. The mailbox transaction id at
                    // mbox_addr + 4 advances on every host read, modelling
                    // the firmware processing the mailbox continuously.
                    let a = *self.mif_addr.borrow();
                    let v = self.mif_read(a);
                    if a == self.mbox_addr.wrapping_add(4) {
                        self.mif_write(a, v.wrapping_add(1));
                    }
                    *self.mif_val.borrow_mut() = v;
                    *self.mif_addr.borrow_mut() = a.wrapping_add(4);
                    *self.mif_cmd.borrow_mut() = 0;
                }
            }
            FAKE_MPI_CONTROL => {
                self.bank_write(off, value);
                if !self.fw2x_mode && !self.mpi_state_frozen {
                    let state = value & 0xFF;
                    if state == 2 {
                        *self.mpi_state.borrow_mut() = (self.negotiated_hal << 16) | 2;
                    } else {
                        let cur = *self.mpi_state.borrow();
                        *self.mpi_state.borrow_mut() = (cur & !0xFF) | state;
                    }
                }
            }
            FAKE_UCP_0X370 => {
                if !self.fw2x_mode {
                    *self.ucp370.borrow_mut() = value;
                }
            }
            0x404 => {
                if value == 0x180E0 && self.boot == FakeBoot::Flb {
                    *self.daisy.borrow_mut() = true;
                }
            }
            FAKE_GLB_SOFT_RES => {
                // The GLB soft-reset bit clears itself (the A0 reset poll
                // completes immediately).
                self.bank_write(off, value & !0x8000);
            }
            FAKE_ITR_RES => {
                // The ITR reset bit clears itself (the A0 reset poll
                // completes immediately).
                self.bank_write(off, value & !0x8000_0000);
            }
            _ => self.bank_write(off, value),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure decode / constant tests
// ---------------------------------------------------------------------------

fn smoke_aqc100_pci_match_table() -> TestResult {
    kt_assert_eq!(ALL_DEV_IDS.len(), 17);
    kt_assert!(ALL_DEV_IDS.contains(&0x00B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x07B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x08B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x09B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x11B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x12B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x80B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x87B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x88B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x89B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x91B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x92B1));
    kt_assert!(ALL_DEV_IDS.contains(&0x0001));
    kt_assert!(ALL_DEV_IDS.contains(&0xD100));
    kt_assert!(ALL_DEV_IDS.contains(&0xD107));
    kt_assert!(ALL_DEV_IDS.contains(&0xD108));
    kt_assert!(ALL_DEV_IDS.contains(&0xD109));
    kt_assert!(!ALL_DEV_IDS.contains(&0x04C0));
    kt_assert!(!ALL_DEV_IDS.contains(&0x00C0));
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_pci_match_table);

fn smoke_aqc100_name_and_speed_for_known_ids() -> TestResult {
    kt_assert_eq!(name_for(0x00B1), "aqc100");
    kt_assert_eq!(name_for(0x07B1), "aqc107");
    kt_assert_eq!(name_for(0x08B1), "aqc108");
    kt_assert_eq!(name_for(0x09B1), "aqc109");
    kt_assert_eq!(name_for(0x11B1), "aqc111");
    kt_assert_eq!(name_for(0x12B1), "aqc112");
    kt_assert_eq!(name_for(0x80B1), "aqc100");
    kt_assert_eq!(name_for(0xD100), "aqc100");
    kt_assert_eq!(name_for(0xD107), "aqc107");
    kt_assert_eq!(name_for(0xD108), "aqc108");
    kt_assert_eq!(name_for(0xD109), "aqc109");
    kt_assert_eq!(name_for(0x0001), "aqc107");
    kt_assert_eq!(name_for(0xFFFF), "aqc100");
    // B1 caps: aqc100 10G|5G|2G5|1G|100M = 0x1F; aqc108 0x1E; aqc109 0x1C.
    kt_assert_eq!(speed_mask_for(0x00B1, Backend::B1), 0x1F);
    kt_assert_eq!(speed_mask_for(0x07B1, Backend::B1), 0x1F);
    kt_assert_eq!(speed_mask_for(0x08B1, Backend::B1), 0x1E);
    kt_assert_eq!(speed_mask_for(0x09B1, Backend::B1), 0x1C);
    kt_assert_eq!(speed_mask_for(0x11B1, Backend::B1), 0x1E);
    kt_assert_eq!(speed_mask_for(0x12B1, Backend::B1), 0x1C);
    kt_assert_eq!(speed_mask_for(0x87B1, Backend::B1), 0x1F);
    kt_assert_eq!(speed_mask_for(0x92B1, Backend::B1), 0x1C);
    // A0 caps differ only for aqc100: no 10G (0x1E, not 0x1F).
    kt_assert_eq!(speed_mask_for(0xD100, Backend::A0), 0x1E);
    kt_assert_eq!(speed_mask_for(0xD107, Backend::A0), 0x1F);
    kt_assert_eq!(speed_mask_for(0xD108, Backend::A0), 0x1E);
    kt_assert_eq!(speed_mask_for(0xD109, Backend::A0), 0x1C);
    kt_assert_eq!(speed_mask_for(0x0001, Backend::A0), 0x1F);
    // B0 caps match B1 caps.
    kt_assert_eq!(speed_mask_for(0xD100, Backend::B0), 0x1F);
    kt_assert_eq!(speed_mask_for(0xD109, Backend::B0), 0x1C);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/aqc100",
    smoke_aqc100_name_and_speed_for_known_ids
);

fn smoke_aqc100_fw_gen_for_version() -> TestResult {
    kt_assert_eq!(fw_gen_for(0x01050006), Some(FwGen::Fw1x));
    kt_assert_eq!(fw_gen_for(0x01060000), Some(FwGen::Fw1x));
    kt_assert_eq!(fw_gen_for(0x01050005), None);
    kt_assert_eq!(fw_gen_for(0x02000000), Some(FwGen::Fw2x));
    kt_assert_eq!(fw_gen_for(0x03010026), Some(FwGen::Fw2x));
    kt_assert_eq!(fw_gen_for(0x04000000), Some(FwGen::Fw2x));
    kt_assert_eq!(fw_gen_for(0), None);
    kt_assert_eq!(fw_gen_for(0x05000000), None);
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_fw_gen_for_version);

fn smoke_aqc100_chip_features() -> TestResult {
    kt_assert_eq!(
        chip_features(0x00000001),
        Some(ChipFeatures {
            backend: Backend::A0,
            tpo2: false,
            rpf2: false,
        })
    );
    kt_assert_eq!(
        chip_features(0x00000002),
        Some(ChipFeatures {
            backend: Backend::B0,
            tpo2: true,
            rpf2: true,
        })
    );
    kt_assert_eq!(
        chip_features(0x0000000A),
        Some(ChipFeatures {
            backend: Backend::B1,
            tpo2: true,
            rpf2: true,
        })
    );
    kt_assert_eq!(chip_features(0x00000003), None);
    kt_assert_eq!(chip_features(0x00000000), None);
    // The low nibble alone selects the backend (upper bits ignored).
    kt_assert_eq!(
        chip_features(0xDEAD_BEEA).map(|f| f.backend),
        Some(Backend::B1)
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_chip_features);

fn smoke_aqc100_mac_efuse_and_fallback() -> TestResult {
    // The efuse words are the MAC's big-endian bytes: word 0
    // holds bytes 0..4, word 1 holds bytes 4..6 in its top half
    // (Linux byte-swaps each downloaded dword, then copies the
    // bytes in order — see `decode_mac_efuse`).
    let mac = decode_mac_efuse(&[0x525400AB, 0xCDEF0000]);
    kt_assert_eq!(mac, [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);
    // All-zero efuse words decode to an all-zero MAC.
    kt_assert_eq!(decode_mac_efuse(&[0, 0]), [0; 6]);
    // Multicast efuse MACs are invalid.
    kt_assert!(mac_needs_fallback([0x53, 0x54, 0x00, 0xAB, 0xCD, 0xEF]));
    // A zero OUI is invalid.
    kt_assert!(mac_needs_fallback([0, 0, 0, 0xAB, 0xCD, 0xEF]));
    kt_assert!(!mac_needs_fallback([0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]));
    // Fallback MAC: 30:0E:E3:00:XX:XX from the low 16 bits of UCP 0x370.
    kt_assert_eq!(
        fallback_mac(0x12345678),
        [0x30, 0x0E, 0xE3, 0x00, 0x56, 0x78]
    );
    kt_assert_eq!(
        fallback_mac(0x0000_ABCD),
        [0x30, 0x0E, 0xE3, 0x00, 0xAB, 0xCD]
    );
    // A valid efuse MAC must not be replaced by the fallback.
    kt_assert!(!mac_needs_fallback(decode_mac_efuse(&[
        0x525400AB, 0xCDEF0000
    ])));
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_mac_efuse_and_fallback);

fn smoke_aqc100_fw2x_rate_mask() -> TestResult {
    kt_assert_eq!(fw2x_rate_mask(0x1F), 0xF20);
    kt_assert_eq!(fw2x_rate_mask(0x1E), 0x720);
    kt_assert_eq!(fw2x_rate_mask(0x1C), 0x320);
    kt_assert_eq!(fw2x_rate_mask(0), 0);
    kt_assert_eq!(fw2x_rate_mask(0x20), 0);
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_fw2x_rate_mask);

fn smoke_aqc100_link_status_decode() -> TestResult {
    // FW1x: MPI_STATE 0x36C low byte = state, bits[23:16] = HAL speed code.
    let st = |speed: u32, state: u32| (speed << 16) | state;
    kt_assert_eq!(
        link_status_1x_decode(st(1, 2)),
        LinkStatus {
            carrier: true,
            mbps: 10000,
            full_duplex: true,
        }
    );
    kt_assert_eq!(link_status_1x_decode(st(2, 2)).mbps, 5000);
    kt_assert_eq!(link_status_1x_decode(st(4, 2)).mbps, 5000);
    kt_assert_eq!(link_status_1x_decode(st(8, 2)).mbps, 2500);
    kt_assert_eq!(link_status_1x_decode(st(16, 2)).mbps, 1000);
    kt_assert_eq!(link_status_1x_decode(st(32, 2)).mbps, 100);
    kt_assert!(!link_status_1x_decode(st(0, 2)).carrier);
    kt_assert!(!link_status_1x_decode(st(64, 2)).carrier);
    // Linux decodes the speed field only (`hw_atl_utils_mpi_get_link_status`
    // never looks at the state field; the caller treats mbps != 0 as
    // carrier) — a DEINIT state with a valid speed code still reads up.
    kt_assert!(link_status_1x_decode(st(1, 0)).carrier);
    kt_assert_eq!(link_status_1x_decode(st(1, 0)).mbps, 10000);
    // FW2x: rate bits in MPI_STATE 0x370, priority 10G > 5G > 2G5 > 1G > 100M.
    kt_assert_eq!(link_status_2x_decode(0x800).mbps, 10000);
    kt_assert_eq!(link_status_2x_decode(0x400).mbps, 5000);
    kt_assert_eq!(link_status_2x_decode(0x200).mbps, 2500);
    kt_assert_eq!(link_status_2x_decode(0x100).mbps, 1000);
    kt_assert_eq!(link_status_2x_decode(0x020).mbps, 100);
    kt_assert_eq!(link_status_2x_decode(0xF20).mbps, 10000);
    kt_assert_eq!(link_status_2x_decode(0x220).mbps, 2500);
    kt_assert!(!link_status_2x_decode(0x0).carrier);
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_link_status_decode);

fn smoke_aqc100_register_offsets() -> TestResult {
    kt_assert_eq!(REG_MPI_FW_VERSION, 0x18);
    kt_assert_eq!(REG_MIF_ID, 0x1C);
    kt_assert_eq!(REG_MIF_CMD, 0x200);
    kt_assert_eq!(REG_MIF_ADDR, 0x208);
    kt_assert_eq!(REG_MIF_VAL, 0x20C);
    kt_assert_eq!(REG_MIF_RESET_TIMEOUT, 0x348);
    kt_assert_eq!(REG_MPI_RPC_ADDR, 0x334);
    kt_assert_eq!(REG_MPI_CONTROL, 0x368);
    kt_assert_eq!(REG_MPI_STATE, 0x36C);
    kt_assert_eq!(REG_FW2X_MBOX_ADDR, 0x360);
    kt_assert_eq!(REG_EFUSE_ADDR_2X, 0x364);
    kt_assert_eq!(REG_EFUSE_ADDR_1X, 0x374);
    kt_assert_eq!(REG_UCP_0X370, 0x370);
    kt_assert_eq!(REG_GLB_CPU_SEM_BASE, 0x3A0);
    kt_assert_eq!(reg_glb_cpu_sem(2), 0x3A8);
    kt_assert_eq!(reg_glb_cpu_sem(3), 0x3AC);
    kt_assert_eq!(reg_glb_cpu_sem(4), 0x3B0);
    kt_assert_eq!(REG_GLB_CPU_SCRATCH_BASE, 0x300);
    // Scratchpad index n is at 0x300 + n*4 — and Linux's
    // `hw_atl_scrpad25_get` / `hw_atl_scrpad12_get` names are
    // 1-based, so they read indices 24 (0x360, the mailbox
    // address) and 11 (0x32C, the RPC completion flag), not
    // indices 25/12.
    kt_assert_eq!(reg_glb_cpu_scratch(25), 0x364);
    kt_assert_eq!(reg_glb_cpu_scratch(24), 0x360);
    kt_assert_eq!(reg_glb_cpu_scratch(12), 0x330);
    kt_assert_eq!(reg_glb_cpu_scratch(11), 0x32C);
    kt_assert_eq!(REG_SCRPAD_MBOX_ADDR, 0x360);
    kt_assert_eq!(REG_MPI_BOOT_EXIT_CODE, 0x388);
    kt_assert_eq!(REG_MPI_DAISY_CHAIN_STATUS, 0x704);
    kt_assert_eq!(REG_MAC_PHY_CONTROL, 0x4000);
    kt_assert_eq!(REG_RPB_RX_BUF, 0x5700);
    kt_assert_eq!(REG_RX_FLR_RSS_CONTROL1, 0x54C0);
    kt_assert_eq!(REG_PCI_REG_CONTROL6, 0x1014);
    kt_assert_eq!(REG_TX_DMA_TOTAL_REQ_LIMIT, 0x7B20);
    kt_assert_eq!(REG_TX_DMA_DEBUG_CTL, 0x8920);
    kt_assert_eq!(REG_TPO2_CTL, 0x7040);
    kt_assert_eq!(REG_RPF2_CTL, 0x5040);
    kt_assert_eq!(REG_ITR_RES, 0x2300);
    kt_assert_eq!(REG_IRQ_GLB_CTL, 0x2300);
    kt_assert_eq!(REG_ITR_IAMRLSW, 0x2090);
    kt_assert_eq!(REG_GEN_IRQ_MAP_BASE, 0x2180);
    kt_assert_eq!(reg_rx_dma_stat(0), 0x5B14);
    kt_assert_eq!(reg_rx_dma_stat(3), 0x5B14 + 3 * 0x20);
    kt_assert_eq!(reg_rx_dma_ctl(0), 0x5B08);
    kt_assert_eq!(reg_rx_dma_head_ptr(0), 0x5B0C);
    kt_assert_eq!(reg_rx_dma_head_ptr(3), 0x5B0C + 3 * 0x20);
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_register_offsets);

fn a0_wb(status: u16, type_: u32, pkt_len: u16) -> RxdWb {
    RxdWb {
        type_,
        rss_hash: 0,
        status,
        pkt_len,
        next_desc_ptr: 0,
        vlan: 0,
    }
}

fn smoke_aqc100_decode_rx_wb_a0() -> TestResult {
    // frame_max 2048 = RX_BUF_LEN. EOP is status bit 1 (0x2);
    // the A0 completion test is status & 0x5.
    // Plain frame, no EOP: length is min(pkt_len, frame_max).
    kt_assert_eq!(
        decode_rx_wb_a0(&a0_wb(0x5, 0, 5), 2048),
        RxDecode {
            len: 5,
            csum: RxCsumResult::None,
            error: false,
            is_eop: false,
        }
    );
    // EOP set: length is pkt_len mod frame_max.
    kt_assert_eq!(
        decode_rx_wb_a0(&a0_wb(0x3, 0, 5), 2048),
        RxDecode {
            len: 5,
            csum: RxCsumResult::None,
            error: false,
            is_eop: true,
        }
    );
    // L4 checksum trusted: csum_en bit 1 (type_ bit 20), TCP
    // pkt_type 0x04, rx_stat bit 2 clear.
    kt_assert_eq!(
        decode_rx_wb_a0(&a0_wb(0x3, 0x100040, 5), 2048),
        RxDecode {
            len: 5,
            csum: RxCsumResult::Ok,
            error: false,
            is_eop: true,
        }
    );
    // Same frame with rx_stat bit 2 set (status bit 4): L4 verdict
    // is not trusted, but the frame itself is fine.
    kt_assert_eq!(
        decode_rx_wb_a0(&a0_wb(0x13, 0x100040, 5), 2048),
        RxDecode {
            len: 5,
            csum: RxCsumResult::None,
            error: false,
            is_eop: true,
        }
    );
    // UDP (pkt_type 0x00) with csum_en bit 1: also trusted.
    kt_assert_eq!(
        decode_rx_wb_a0(&a0_wb(0x3, 0x100000, 100), 2048),
        RxDecode {
            len: 100,
            csum: RxCsumResult::Ok,
            error: false,
            is_eop: true,
        }
    );
    // DMA error bit (type_ 0x1000) flags the frame.
    kt_assert_eq!(
        decode_rx_wb_a0(&a0_wb(0x3, 0x1000, 5), 2048),
        RxDecode {
            len: 5,
            csum: RxCsumResult::None,
            error: true,
            is_eop: true,
        }
    );
    // Non-EOP oversize frame clamps to frame_max.
    kt_assert_eq!(
        decode_rx_wb_a0(&a0_wb(0x1, 0, 3000), 2048),
        RxDecode {
            len: 2048,
            csum: RxCsumResult::None,
            error: false,
            is_eop: false,
        }
    );
    // EOP with pkt_len == frame_max wraps to frame_max, not 0.
    kt_assert_eq!(
        decode_rx_wb_a0(&a0_wb(0x3, 0, 2048), 2048),
        RxDecode {
            len: 2048,
            csum: RxCsumResult::None,
            error: false,
            is_eop: true,
        }
    );
    // EOP with pkt_len == frame_max + 1 wraps to 1.
    kt_assert_eq!(
        decode_rx_wb_a0(&a0_wb(0x3, 0, 2049), 2048),
        RxDecode {
            len: 1,
            csum: RxCsumResult::None,
            error: false,
            is_eop: true,
        }
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_decode_rx_wb_a0);

fn smoke_aqc100_sample_a0_completion() -> TestResult {
    // Dword 2 carries status (low 16) + pkt_len (high 16); the
    // other dwords pass through untouched.
    let d = [0x1111_1111u32, 0x2222_2222, 0x001E_0005, 0x3333_4444];
    let wb = match sample_a0_wb(|i| d[i]) {
        Some(w) => w,
        None => return TestResult::Fail("sample 0x5"),
    };
    kt_assert_eq!(wb.type_, 0x1111_1111);
    kt_assert_eq!(wb.rss_hash, 0x2222_2222);
    kt_assert_eq!(wb.status, 0x5);
    kt_assert_eq!(wb.pkt_len, 0x1E);
    kt_assert_eq!(wb.next_desc_ptr, 0x4444);
    kt_assert_eq!(wb.vlan, 0x3333);
    // The A0 completion test is status & 0x5 != 0: DD alone and
    // bit 2 alone both complete; EOP alone (bit 1) does not.
    kt_assert!(sample_a0_wb(|_| 0x0000_0001).is_some());
    kt_assert!(sample_a0_wb(|_| 0x0000_0004).is_some());
    kt_assert!(sample_a0_wb(|_| 0x0000_0003).is_some());
    kt_assert!(sample_a0_wb(|_| 0x0000_0002).is_none());
    kt_assert!(sample_a0_wb(|_| 0x0000_0000).is_none());
    // Length comes from the high half of dword 2.
    let wb = match sample_a0_wb(|i| [0, 0, 0x002C_0005, 0][i]) {
        Some(w) => w,
        None => return TestResult::Fail("sample 0x2c05"),
    };
    kt_assert_eq!(wb.pkt_len, 0x2C);
    kt_assert_eq!(wb.status, 0x5);
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_sample_a0_completion);

// ---------------------------------------------------------------------------
// Conversation tests: simulated device bring-up
// ---------------------------------------------------------------------------

/// Drive the FW1x B1 bring-up sequence against the fake, asserting the
/// register values the sequence leaves behind. MAC 52:54:00:AB:CD:EF is
/// preloaded in the fake efuse memory.
fn fake_bringup_fw1x_b1(fake: &FakeRegs) -> TestResult {
    let version = match soft_reset(fake) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("soft_reset"),
    };
    kt_assert_eq!(version, 0x01050006);
    let features = match chip_features(fake.read32(FAKE_MIF_ID)) {
        Some(f) => f,
        None => return TestResult::Fail("chip features"),
    };
    kt_assert_eq!(features.backend, Backend::B1);
    kt_assert_eq!(fw_gen_for(version), Some(FwGen::Fw1x));
    let (mbox, rpc) = match fw_mpi_init(fake, FwGen::Fw1x) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("fw_mpi_init"),
    };
    kt_assert_eq!(mbox, 0x0010_0000);
    kt_assert_eq!(rpc, 0x0020_0000);
    let mac = match get_mac_permanent(fake, FwGen::Fw1x, true) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("get_mac_permanent"),
    };
    kt_assert_eq!(mac, [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);
    if hw_reset(fake, Backend::B1, mbox, FwGen::Fw1x).is_err() {
        return TestResult::Fail("hw_reset");
    }
    if hw_init(fake, features, FwGen::Fw1x, mac, 0x1F).is_err() {
        return TestResult::Fail("hw_init");
    }
    TestResult::Pass
}

fn smoke_aqc100_fake_bringup_fw1x_b1() -> TestResult {
    let fake = FakeRegs::new();
    fake.preload_efuse_mac([0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);
    let r = fake_bringup_fw1x_b1(&fake);
    if !matches!(r, TestResult::Pass) {
        return r;
    }

    // MPI_CONTROL: speed mask 0x1F << 16, state INIT (2).
    kt_assert_eq!(fake.observed(FAKE_MPI_CONTROL), 0x001F0002);
    // The fake firmware negotiated 2G5 (HAL code 8) on MPI_INIT.
    kt_assert_eq!(read_link_status(&fake, FwGen::Fw1x).mbps, 2500);
    kt_assert!(read_link_status(&fake, FwGen::Fw1x).carrier);
    // TPO2 / RPF2 chip features are wired.
    kt_assert_eq!(fake.observed(0x7040), 0x10000);
    kt_assert_eq!(fake.observed(0x5040), 0xF0000);
    // RX flow control mode = 1 (bits [5:4] of 0x5700).
    kt_assert_eq!(fake.observed(0x5700) & 0x30, 0x10);
    kt_assert_eq!(fake.observed(0x54C0), 0);
    // Unicast filters: only filter 0 enabled; every filter acts HOST.
    // (Filter 0's control word is overwritten by mac_addr_set below.)
    kt_assert_eq!(fake.observed(reg_rpf_uc_ctl(1)), 0x00010000);
    kt_assert_eq!(fake.observed(reg_rpf_uc_ctl(32)), 0x00010000);
    // MAC filter words at filter 0, with NO tag field (hw_atl2-only).
    kt_assert_eq!(fake.observed(reg_rpf_uc_daflsw(0)), 0x00ABCDEF);
    kt_assert_eq!(fake.observed(reg_rpf_uc_ctl(0)), 0x80015254);
    // Multicast masks, VLAN TPIDs, VLAN control (B1 = 0xE).
    kt_assert_eq!(fake.observed(0x5270), 0);
    kt_assert_eq!(fake.observed(0x5250), 0x10FFF);
    kt_assert_eq!(fake.observed(0x5284), 0x88A88100);
    kt_assert_eq!(fake.observed(0x5280), 0xE);
    // Writeback interrupts enabled.
    kt_assert_eq!(fake.observed(0x5A30), 0x4);
    kt_assert_eq!(fake.observed(0x7B40), 0x2);
    // Broadcast action HOST + threshold 0xFFFF.
    kt_assert_eq!(fake.observed(0x5100), 0xFFFF1000);
    // PCI control 6 MRRS + TX DMA request limit.
    kt_assert_eq!(fake.observed(0x1014), 0x404);
    kt_assert_eq!(fake.observed(0x7B20), 24);
    // Interrupts: single-vector GLB, auto-mask all ones, B1 gen map.
    kt_assert_eq!(fake.observed(0x2300), 0x20000022);
    kt_assert_eq!(fake.observed(0x2090), 0xFFFF_FFFF);
    kt_assert_eq!(fake.observed(0x2180), 0x88880000);

    // Rings: program, pre-fill, tail, start.
    let tx_base: u64 = 0x0000_1000_0000;
    let rx_base: u64 = 0x0000_2000_0000;
    program_rings(&fake, tx_base, rx_base);
    kt_assert_eq!(fake.observed(0x7C00), tx_base as u32);
    kt_assert_eq!(fake.observed(0x7C04), (tx_base >> 32) as u32);
    kt_assert_eq!(fake.observed(0x5B00), rx_base as u32);
    kt_assert_eq!(fake.observed(0x5B04), (rx_base >> 32) as u32);
    kt_assert_eq!(fake.observed(0x7C08), 0x100);
    kt_assert_eq!(fake.observed(0x5B08), 0x100);
    kt_assert_eq!(fake.observed(0x7C10), 0);
    kt_assert_eq!(fake.observed(0x5B18), 2);
    kt_assert_eq!(fake.observed(0x2100), 0x80008000);
    set_rx_tail(&fake, 255);
    kt_assert_eq!(fake.observed(reg_rx_dma_tail(0)), 255);
    start_hw(&fake);
    kt_assert_eq!(fake.observed(0x7C08), 0x80000100);
    kt_assert_eq!(fake.observed(0x5B08), 0x80000100);
    kt_assert_eq!(fake.observed(0x5700) & 0x1, 0x1);
    kt_assert_eq!(fake.observed(0x7900) & 0x1, 0x1);
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_fake_bringup_fw1x_b1);

fn smoke_aqc100_fake_bringup_fw2x_b1() -> TestResult {
    let mut fake = FakeRegs::new();
    fake.set_fw2x();
    fake.fw_version = 0x02000005;
    fake.mpi_state_2x = RefCell::new(0x200); // Firmware reports 2G5.
    fake.preload_efuse_mac([0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);

    let version = match soft_reset(&fake) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("soft_reset"),
    };
    kt_assert_eq!(fw_gen_for(version), Some(FwGen::Fw2x));
    let features = match chip_features(fake.read32(FAKE_MIF_ID)) {
        Some(f) => f,
        None => return TestResult::Fail("chip features"),
    };
    kt_assert_eq!(features.backend, Backend::B1);
    let (mbox, rpc) = match fw_mpi_init(&fake, FwGen::Fw2x) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("fw_mpi_init"),
    };
    kt_assert_eq!(mbox, 0x0010_0000);
    kt_assert_eq!(rpc, 0x0020_0000);
    let mac = match get_mac_permanent(&fake, FwGen::Fw2x, true) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("get_mac_permanent"),
    };
    kt_assert_eq!(mac, [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);
    if hw_reset(&fake, Backend::B1, mbox, FwGen::Fw2x).is_err() {
        return TestResult::Fail("hw_reset");
    }
    if hw_init(&fake, features, FwGen::Fw2x, mac, 0x1F).is_err() {
        return TestResult::Fail("hw_init");
    }

    // FW2x: MPI_CONTROL carries the rate mask, CONTROL2 the FC bits.
    kt_assert_eq!(fake.observed(FAKE_MPI_CONTROL), 0xF20);
    kt_assert_eq!(fake.observed(0x36C), 0x18);
    kt_assert_eq!(fake.observed(0x36C) & (1 << 22), 0); // LINK_DROP cleared.
    kt_assert_eq!(read_link_status(&fake, FwGen::Fw2x).mbps, 2500);
    kt_assert!(read_link_status(&fake, FwGen::Fw2x).carrier);
    // Shared B1 register writes still land.
    kt_assert_eq!(fake.observed(0x7040), 0x10000);
    kt_assert_eq!(fake.observed(0x5040), 0xF0000);
    kt_assert_eq!(fake.observed(0x5280), 0xE);
    kt_assert_eq!(fake.observed(0x1014), 0x404);
    kt_assert_eq!(fake.observed(0x7B20), 24);
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_fake_bringup_fw2x_b1);

fn smoke_aqc100_fake_bringup_a0() -> TestResult {
    let mut fake = FakeRegs::new();
    fake.fw_version = 0x01050006;
    fake.mif_id = 0x00000001;
    fake.preload_efuse_mac([0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);

    let version = match soft_reset(&fake) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("soft_reset"),
    };
    kt_assert_eq!(version, 0x01050006);
    let features = match chip_features(fake.read32(FAKE_MIF_ID)) {
        Some(f) => f,
        None => return TestResult::Fail("chip features"),
    };
    kt_assert_eq!(features.backend, Backend::A0);
    let (mbox, _) = match fw_mpi_init(&fake, FwGen::Fw1x) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("fw_mpi_init"),
    };
    let mac = match get_mac_permanent(&fake, FwGen::Fw1x, true) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("get_mac_permanent"),
    };
    if hw_reset(&fake, Backend::A0, mbox, FwGen::Fw1x).is_err() {
        return TestResult::Fail("hw_reset");
    }
    if hw_init(&fake, features, FwGen::Fw1x, mac, 0x1F).is_err() {
        return TestResult::Fail("hw_init");
    }

    // A0 TX DMA debug ctl writes: 0x800000b8 then 0xb8.
    kt_assert!(fake.logged(0x8920, 0x800000B8));
    kt_assert!(fake.logged(0x8920, 0x000000B8));
    // A0 interrupts use the all-8s generation map.
    kt_assert_eq!(fake.observed(0x2180), 0x88888888);
    // A0: no 0x7040 feature bit, no 0x5040 write, VLAN ctl 0x2.
    kt_assert_eq!(fake.observed(0x7040), 0);
    kt_assert!(!fake.logged_any(0x5040));
    kt_assert_eq!(fake.observed(0x5280), 0x2);
    // A0 writes neither PCI_CONTROL6 nor the TX DMA request limit.
    kt_assert!(!fake.logged_any(0x1014));
    kt_assert!(!fake.logged_any(0x7B20));
    // Shared RX path still lands.
    kt_assert_eq!(fake.observed(0x54C0), 0);
    kt_assert_eq!(fake.observed(reg_rpf_uc_ctl(0)), 0x80015254);
    kt_assert_eq!(fake.observed(0x5284), 0x88A88100);
    kt_assert_eq!(read_link_status(&fake, FwGen::Fw1x).mbps, 2500);
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_fake_bringup_a0);

fn smoke_aqc100_fake_rbl_boot() -> TestResult {
    // ROM boot with a valid exit code boots through the RBL path.
    let fake = FakeRegs::with_boot(FakeBoot::Rbl(0x0001));
    fake.preload_efuse_mac([0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);
    if soft_reset(&fake).is_err() {
        return TestResult::Fail("rbl soft_reset");
    }
    kt_assert!(fake.logged(FAKE_BOOT_EXIT_CODE, FAKE_BOOT_MARKER));
    let r = fake_bringup_fw1x_b1(&FakeRegs::with_boot(FakeBoot::Rbl(0x0001)));
    if !matches!(r, TestResult::Pass) {
        return r;
    }

    // ROM boot with exit code 0xF1A7 means no firmware was detected.
    let fake = FakeRegs::with_boot(FakeBoot::Rbl(0xF1A7));
    kt_assert!(matches!(soft_reset(&fake), Err(NicError::NoFirmware)));
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_fake_rbl_boot);

fn smoke_aqc100_fake_boot_failures() -> TestResult {
    // Neither RBL nor FLB: the tight entry loop exhausts and errors.
    let fake = FakeRegs::with_boot(FakeBoot::Neither);
    kt_assert!(matches!(soft_reset(&fake), Err(NicError::Other(_))));

    // FW1x DEINIT never completes: the 10ms poll times out.
    // The fake boots at MPI state DEINIT (0), so the poll would
    // pass immediately unless the state starts elsewhere — park
    // it at INIT so the frozen transition has to time out.
    let mut fake = FakeRegs::new();
    fake.mpi_state_frozen = true;
    *fake.mpi_state.borrow_mut() = MPI_INIT;
    kt_assert!(matches!(soft_reset(&fake), Err(NicError::FwTimeout)));

    // MIF downloads never complete: FW2x MAC fetch fails, FW1x falls back.
    let mut fake = FakeRegs::new();
    fake.set_fw2x();
    fake.fw_version = 0x02000005;
    fake.mif_stuck = true;
    kt_assert!(matches!(
        get_mac_permanent(&fake, FwGen::Fw2x, true),
        Err(NicError::FwTimeout)
    ));
    let mut fake = FakeRegs::new();
    fake.mif_stuck = true;
    *fake.ucp370.borrow_mut() = 0x0000_ABCD;
    let mac = match get_mac_permanent(&fake, FwGen::Fw1x, true) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("fallback mac"),
    };
    kt_assert_eq!(mac, [0x30, 0x0E, 0xE3, 0x00, 0xAB, 0xCD]);

    // UCP 0x370 zero seeds a fresh value satisfying the seed mask.
    let fake = FakeRegs::new();
    *fake.ucp370.borrow_mut() = 0;
    fake.preload_efuse_mac([0, 0, 0, 0, 0, 0]);
    let mac = match get_mac_permanent(&fake, FwGen::Fw1x, true) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("seeded mac"),
    };
    let seed = *fake.ucp370.borrow();
    kt_assert_ne!(seed, 0);
    kt_assert_eq!(seed & 0x02020202, 0x02020202);
    kt_assert_eq!(seed & 0x01010101, 0);
    kt_assert_eq!(mac, fallback_mac(seed));
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc100", smoke_aqc100_fake_boot_failures);

// ---------------------------------------------------------------------------
// Multi-instance cookie dispatch
// ---------------------------------------------------------------------------

// Same shape as `smoke_aqc113_multi_instance_cookie_dispatch` in
// `drivers/net/aqc1xx/src/aqc113/tests.rs`: two AQC devices probe,
// both register in the `CONTROLLERS` vec; a transmit on the second
// device routes to the second instance (not the first); removing
// one device leaves the other functional. The QEMU test VM has no
// AQC silicon, so only the no-silicon branch runs in CI; the live
// branch runs on real hardware with one or two AQC NICs.
//
// Routing is proven by the posted frame itself, not by the send
// result: `transmit` copies the frame into the slot buffer and
// advances `tx_head` when the descriptor is posted, before the
// 250 ms DD-writeback poll, so a link-down device still shows the
// post on the right instance even when the poll times out — and a
// concurrent stack frame on another port cannot fake the addressed
// port's slot bytes.
fn smoke_aqc100_multi_instance_cookie_dispatch() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: the kernel-test runner executes post-boot, so the memory
    // map and allocator are online; `ECAM_DEFAULT_BASE` is the standard
    // MMCONFIG window and the enumerator only reads 4-byte config words,
    // rejecting all-1s for unpopulated slots.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let aqc_addrs: Vec<narf_bus::BusAddr> = devs
        .iter()
        .filter(|d| {
            matches!(&d.kind, BusKind::Pcie { .. })
                && d.id.vendor == AQC_VENDOR
                && ALL_DEV_IDS.contains(&d.id.device)
        })
        .map(|d| d.addr)
        .collect();
    let n = aqc_addrs.len();
    if n == 0 {
        kt_assert_eq!(
            instance_count(),
            0,
            "instance_count != 0 with no aqc100 silicon"
        );
        kt_assert!(controller(0).is_none());
        kt_assert!(controller(usize::MAX).is_none());
        kt_assert!(!is_probed());
        kt_assert!(with_controller(0, |c| c.mac).is_none());
        kt_assert!(with_controller_mut(0, |_| ()).is_none());
        // Detach is a no-op without silicon — must not panic, and
        // must not conjure an instance.
        aqc100_detach(0);
        aqc100_detach(usize::MAX);
        kt_assert_eq!(
            instance_count(),
            0,
            "detach conjured an instance with no silicon"
        );
        // Cookie dispatch without a controller fails instead of
        // resolving to a first (nonexistent) instance.
        let frame = [0u8; 64];
        kt_assert!(aqc100_send_frame(0, &frame, narf_net::TxMeta::plain()).is_err());
        kt_assert!(aqc100_send_frame(1, &frame, narf_net::TxMeta::plain()).is_err());
        kt_assert!(narf_net::iface::send_on("eth999", &frame).is_err());
        return TestResult::Pass;
    }
    __reset_for_test();
    register_pci_driver();
    let authority = bootstrap_registry_authority();
    kt_assert!(probe_all_pci(&authority).is_ok(), "probe_all_pci");
    kt_assert!(is_probed(), "aqc100 not probed");
    kt_assert_eq!(
        instance_count(),
        n,
        "instance_count != enumerated AQC device count after probe"
    );
    kt_assert!(controller(n).is_none());
    kt_assert!(controller(usize::MAX).is_none());
    // One distinct published name per controller, each resolvable,
    // each bound to the PCI address it was probed at.
    let mut names: Vec<&str> = Vec::new();
    let mut ctrls: Vec<alloc::sync::Arc<Aqc100Nic>> = Vec::new();
    for (i, addr) in aqc_addrs.iter().enumerate().take(n) {
        let ctrl = match controller(i) {
            Some(c) => c,
            None => return TestResult::Fail("controller(i) None after probe"),
        };
        kt_assert_eq!(
            ctrl.addr,
            *addr,
            "controller(i) bound to the wrong PCI address"
        );
        let name = ctrl.ifname();
        kt_assert!(!name.is_empty(), "published name empty after probe");
        kt_assert!(
            !names.contains(&name),
            "two controllers share one published name"
        );
        kt_assert!(
            narf_net::iface::lookup(name).is_some(),
            "iface not published under its name"
        );
        names.push(name);
        ctrls.push(ctrl);
    }
    // Re-probe keeps the same Arcs (same-function dedup by PCI addr).
    let authority = bootstrap_registry_authority();
    let _ = probe_all_pci(&authority);
    kt_assert_eq!(
        instance_count(),
        n,
        "instance_count changed across re-probe"
    );
    for (i, ctrl) in ctrls.iter().enumerate().take(n) {
        let after = match controller(i) {
            Some(c) => c,
            None => return TestResult::Fail("controller(i) vanished across re-probe"),
        };
        kt_assert!(
            alloc::sync::Arc::as_ptr(&after) == alloc::sync::Arc::as_ptr(ctrl),
            "re-probe replaced controller(i)"
        );
    }
    // Registry adapter borrows the NIC's own rings (first port):
    // querying them must not take the consumer/producer out of the
    // NIC's ring.
    let ring_ptr =
        narf_net::registry().with_interface(names[0], |i| i.rx_ring() as *const _ as usize);
    kt_assert_eq!(
        ring_ptr,
        Some(&ctrls[0].rx_ipc_ring as *const _ as usize),
        "adapter rx_ring is not the NIC's own ring"
    );
    kt_assert!(
        ctrls[0].rx_ipc_ring.lock().is_none(),
        "querying rx_ring took the NIC's RX ring"
    );
    let tx_ptr =
        narf_net::registry().with_interface(names[0], |i| i.tx_ring() as *const _ as usize);
    kt_assert_eq!(
        tx_ptr,
        Some(&ctrls[0].tx_ipc_ring as *const _ as usize),
        "adapter tx_ring is not the NIC's own ring"
    );
    kt_assert!(
        ctrls[0].tx_ipc_ring.lock().is_none(),
        "querying tx_ring took the NIC's TX ring"
    );
    // Send routing: a frame addressed to port i lands in port i's
    // TX slot buffer and no other port's next slot. The frame is
    // distinctive (broadcast dst, locally-administered src, 0xFFFF
    // ethertype) so no background frame can fake it.
    let mut frame = [0u8; 64];
    frame[..6].fill(0xFF);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    frame[12] = 0xFF;
    frame[13] = 0xFF;
    for (i, name) in names.iter().enumerate().take(n) {
        let heads: Vec<u32> = ctrls.iter().map(|c| *c.tx_head.lock()).collect();
        let _ = narf_net::iface::send_on(name, &frame);
        for (j, c) in ctrls.iter().enumerate() {
            let slot = (heads[j] as usize) % RING_LEN;
            let posted = slot_matches_frame(c, slot, &frame);
            if j == i {
                kt_assert!(
                    posted,
                    "send_on did not post the frame to the addressed port's TX ring"
                );
                kt_assert_ne!(
                    *c.tx_head.lock(),
                    heads[j],
                    "send_on left the addressed port's TX head unmoved"
                );
            } else {
                kt_assert!(
                    !posted,
                    "send_on posted the frame to a port other than the addressed one"
                );
            }
        }
    }
    if n >= 2 {
        // Direct cookie dispatch: cookie 1 resolves to the second
        // instance, never the first.
        let heads: Vec<u32> = ctrls.iter().map(|c| *c.tx_head.lock()).collect();
        let _ = aqc100_send_frame(1, &frame, narf_net::TxMeta::plain());
        kt_assert!(
            slot_matches_frame(&ctrls[1], (heads[1] as usize) % RING_LEN, &frame),
            "cookie-1 send did not post to the second controller"
        );
        kt_assert!(
            !slot_matches_frame(&ctrls[0], (heads[0] as usize) % RING_LEN, &frame),
            "cookie-1 send posted to the first controller"
        );
    }
    // Removing one device leaves the other functional: detach port
    // 0, then port 1 (when present) still carries traffic and the
    // detached port's cookie no longer resolves.
    aqc100_detach(0);
    kt_assert_eq!(
        instance_count(),
        n - 1,
        "instance_count did not drop after detach(0)"
    );
    kt_assert!(
        controller(0).is_none(),
        "controller(0) still live after detach(0)"
    );
    kt_assert!(
        with_controller(0, |c| c.mac).is_none(),
        "with_controller(0) still resolves after detach(0)"
    );
    // Detach is idempotent.
    aqc100_detach(0);
    kt_assert_eq!(
        instance_count(),
        n - 1,
        "second detach(0) changed instance_count"
    );
    if n >= 2 {
        let survivor = match controller(1) {
            Some(c) => c,
            None => return TestResult::Fail("controller(1) lost after detach(0)"),
        };
        kt_assert!(
            alloc::sync::Arc::as_ptr(&survivor) == alloc::sync::Arc::as_ptr(&ctrls[1]),
            "detach(0) replaced controller(1)"
        );
        let head = *survivor.tx_head.lock();
        let _ = narf_net::iface::send_on(names[1], &frame);
        kt_assert!(
            slot_matches_frame(&survivor, (head as usize) % RING_LEN, &frame),
            "surviving port stopped transmitting after detach(0)"
        );
        kt_assert!(
            aqc100_send_frame(0, &frame, narf_net::TxMeta::plain()).is_err(),
            "detached cookie 0 still transmits"
        );
    }
    // Hot re-bind: a detached entry does not block re-probe of its
    // address, so a fresh probe reclaims the function (at a new
    // cookie — the vec never shrinks) while the survivor keeps its
    // own cookie and Arc.
    let authority = bootstrap_registry_authority();
    let _ = probe_all_pci(&authority);
    kt_assert_eq!(
        instance_count(),
        n,
        "instance_count did not recover after re-probe"
    );
    if n >= 2 {
        let after = match controller(1) {
            Some(c) => c,
            None => return TestResult::Fail("controller(1) vanished across re-bind"),
        };
        kt_assert!(
            alloc::sync::Arc::as_ptr(&after) == alloc::sync::Arc::as_ptr(&ctrls[1]),
            "re-bind replaced the surviving controller(1)"
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/aqc100",
    smoke_aqc100_multi_instance_cookie_dispatch
);

/// True when the TX slot buffer `slot` of `ctrl` currently holds
/// the first 14 bytes of `frame` — the routing proof for
/// [`smoke_aqc100_multi_instance_cookie_dispatch`]: `transmit`
/// copies the frame into the slot buffer before posting the
/// descriptor, so the bytes land exactly on the instance that was
/// addressed.
fn slot_matches_frame(ctrl: &Aqc100Nic, slot: usize, frame: &[u8]) -> bool {
    for (k, expected) in frame[..14].iter().enumerate() {
        // SAFETY: `slot` is reduced mod `RING_LEN` by the caller, so it
        // indexes a live TX pool buffer; `k < 14`, so the read stays
        // within the frame prefix; the reads are volatile, as in the
        // driver's own receive path.
        let b = unsafe { core::ptr::read_volatile(ctrl.tx_pool[slot].cpu_ptr_at::<u8>(k as u64)) };
        if b != *expected {
            return false;
        }
    }
    true
}
