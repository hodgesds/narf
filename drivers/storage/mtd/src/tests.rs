//! Smokes for the MTD core: partition parsing/bounds over a
//! RAM flash fake with honest NOR semantics (program ANDs,
//! erase resets a block to 0xFF), and the registry shape.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{attach_partitions, registry, MtdDevice, MtdError};

/// RAM flash with NOR semantics. 8 blocks x 4 KiB.
#[derive(Debug)]
struct RamFlash {
    name: String,
    data: IrqSafeSpinLock<Vec<u8>>,
}

impl RamFlash {
    fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            data: IrqSafeSpinLock::new(alloc::vec![0xFF; 8 * 4096]),
        }
    }
}

impl MtdDevice for RamFlash {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> u64 {
        8 * 4096
    }
    fn erase_size(&self) -> u32 {
        4096
    }
    fn write_size(&self) -> u32 {
        1
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<(), MtdError> {
        let data = self.data.lock();
        let off = off as usize;
        if off + buf.len() > data.len() {
            return Err(MtdError::OutOfBounds);
        }
        buf.copy_from_slice(&data[off..off + buf.len()]);
        Ok(())
    }
    fn write(&self, off: u64, buf: &[u8]) -> Result<(), MtdError> {
        let mut data = self.data.lock();
        let off = off as usize;
        if off + buf.len() > data.len() {
            return Err(MtdError::OutOfBounds);
        }
        for (i, b) in buf.iter().enumerate() {
            data[off + i] &= b; // NOR: program only clears bits
        }
        Ok(())
    }
    fn erase(&self, off: u64, len: u64) -> Result<(), MtdError> {
        if off % 4096 != 0 || len % 4096 != 0 {
            return Err(MtdError::BadGeometry);
        }
        let mut data = self.data.lock();
        let (off, len) = (off as usize, len as usize);
        if off + len > data.len() {
            return Err(MtdError::OutOfBounds);
        }
        data[off..off + len].fill(0xFF);
        Ok(())
    }
}

fn child(
    name: &str,
    reg: Option<(u64, u64)>,
    props: &[(&str, &[u8])],
    children: Vec<narf_bus::dt::DtChild>,
) -> narf_bus::dt::DtChild {
    narf_bus::dt::DtChild {
        name: String::from(name),
        compatible: Vec::new(),
        reg,
        props: props
            .iter()
            .map(|(n, v)| (String::from(*n), v.to_vec()))
            .collect(),
        children,
    }
}

fn partitions_node() -> narf_bus::dt::DtChild {
    let empty: &[u8] = &[];
    child(
        "partitions",
        None,
        &[],
        alloc::vec![
            child(
                "partition@0",
                Some((0, 8192)),
                &[("label", b"boot\0"), ("read-only", empty)],
                Vec::new(),
            ),
            child(
                "partition@2000",
                Some((8192, 16384)),
                &[("label", b"rootfs\0")],
                Vec::new(),
            ),
            // Not erase-aligned: attach must skip it.
            child(
                "partition@6000",
                Some((24576, 1000)),
                &[("label", b"odd\0")],
                Vec::new(),
            ),
        ],
    )
}

fn smoke_mtd_partition_bounds_and_readonly() -> TestResult {
    registry::__reset_for_test();
    let base: Arc<dyn MtdDevice> = Arc::new(RamFlash::new("ramflash0"));
    registry::register_unique(base.clone());
    let attached = attach_partitions(&base, &partitions_node());
    if attached != 2 {
        return TestResult::Fail(
            "attach_partitions did not attach exactly the two aligned partitions",
        );
    }
    let Some(boot) = registry::find("ramflash0.boot") else {
        return TestResult::Fail("boot partition not registered");
    };
    if boot.size() != 8192 || boot.erase_size() != 4096 {
        return TestResult::Fail("boot partition geometry mismatch");
    }
    // Read-only partition refuses program + erase.
    if boot.write(0, &[0x00]) != Err(MtdError::ReadOnly)
        || boot.erase(0, 4096) != Err(MtdError::ReadOnly)
    {
        return TestResult::Fail("read-only partition accepted a write/erase");
    }
    let Some(rootfs) = registry::find("ramflash0.rootfs") else {
        return TestResult::Fail("rootfs partition not registered");
    };
    // Partition writes land at the base offset (0x2000).
    if rootfs.write(0, &[0x3C]).is_err() {
        return TestResult::Fail("rootfs write failed");
    }
    let mut byte = [0u8; 1];
    if base.read(8192, &mut byte).is_err() || byte[0] != 0x3C {
        return TestResult::Fail("partition write did not land at the base offset");
    }
    // AND semantics: programming 0x3C then 0xC3 without erase
    // yields 0x00 through the partition, like the base.
    if rootfs.write(0, &[0xC3]).is_err() {
        return TestResult::Fail("rootfs second write failed");
    }
    if rootfs.read(0, &mut byte).is_err() || byte[0] != 0x00 {
        return TestResult::Fail("partition write did not honour NOR AND semantics");
    }
    // Bounds: past the end refuses on read + write; erase
    // alignment is the base driver's contract, surfaced.
    if rootfs.read(16384, &mut byte) != Err(MtdError::OutOfBounds)
        || rootfs.write(16383, &[0x00, 0x00]) != Err(MtdError::OutOfBounds)
        || rootfs.erase(16, 4096) != Err(MtdError::BadGeometry)
    {
        return TestResult::Fail("partition bounds/geometry enforcement mismatch");
    }
    // Erase through the partition resets only its own range.
    if rootfs.erase(0, 4096).is_err() {
        return TestResult::Fail("rootfs erase failed");
    }
    if rootfs.read(0, &mut byte).is_err() || byte[0] != 0xFF {
        return TestResult::Fail("partition erase did not reset its first block");
    }
    registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("storage-mtd", smoke_mtd_partition_bounds_and_readonly);

fn smoke_mtd_registry_dedupes_by_name() -> TestResult {
    registry::__reset_for_test();
    let a: Arc<dyn MtdDevice> = Arc::new(RamFlash::new("dup"));
    let b: Arc<dyn MtdDevice> = Arc::new(RamFlash::new("dup"));
    registry::register_unique(a);
    let again = registry::register_unique(b);
    if registry::count() != 1 || registry::list().len() != 1 {
        return TestResult::Fail("MTD registry did not dedupe by name");
    }
    if again.name() != "dup" {
        return TestResult::Fail("MTD registry returned the wrong device");
    }
    registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("storage-mtd", smoke_mtd_registry_dedupes_by_name);

// ── CFI model + binding smokes (step 6b) ────────────────────────
//
// A modelled CFI chip behind the driver's CfiIo seam: a query
// table (1 MiB device, one erase region of 64 KiB blocks), the
// Intel and AMD command state machines, and honest busy polling
// (status bit 7 / DQ7) — the production command sequences in
// cfi.rs execute against it unchanged.

use crate::cfi::{CfiFlash, CfiIo};

const MODEL_WORDS: usize = 0x8_0000; // 1 MiB as x16 words
const MODEL_BLOCK_WORDS: u64 = 0x8000; // 64 KiB

#[derive(Debug, Clone, Copy, PartialEq)]
enum CfiMode {
    Read,
    Query,
    IntelProg(u64),
    IntelEraseArm(u64),
    IntelBusy {
        cd: u32,
        erase: Option<(u64, u64)>,
    },
    AmdU1,
    AmdCmd {
        erase_setup: bool,
    },
    AmdEraseU1,
    AmdEraseU2,
    AmdProg,
    AmdBusy {
        addr: u64,
        data: u16,
        cd: u32,
        erase: Option<(u64, u64)>,
    },
}

#[derive(Debug)]
struct ModelState {
    cells: alloc::vec::Vec<u16>,
    cmdset: u16,
    mode: CfiMode,
}

#[derive(Debug)]
struct ModelCfi {
    state: IrqSafeSpinLock<ModelState>,
}

impl ModelCfi {
    fn new(cmdset: u16) -> Self {
        Self {
            state: IrqSafeSpinLock::new(ModelState {
                cells: alloc::vec![0xFFFF; MODEL_WORDS],
                cmdset,
                mode: CfiMode::Read,
            }),
        }
    }

    fn query_word(st: &ModelState, word: u64) -> u16 {
        match word {
            0x10 => 0x51, // 'Q'
            0x11 => 0x52, // 'R'
            0x12 => 0x59, // 'Y'
            0x13 => st.cmdset,
            0x27 => 20, // 2^20 = 1 MiB
            0x2C => 0,  // one erase region (count - 1)
            0x2D => 15, // 16 blocks - 1
            0x2E => 0,
            0x2F => 0x00, // block size units LE16 = 256 -> 64 KiB
            0x30 => 0x01,
            _ => 0,
        }
    }

    fn block_range(word: u64) -> (u64, u64) {
        let start = word - word % MODEL_BLOCK_WORDS;
        (start, start + MODEL_BLOCK_WORDS)
    }
}

impl CfiIo for ModelCfi {
    fn read16(&self, off: u64) -> u16 {
        let mut st = self.state.lock();
        let word = off / 2;
        match st.mode {
            CfiMode::Query => Self::query_word(&st, word),
            CfiMode::IntelBusy { cd, erase } => {
                if cd > 0 {
                    st.mode = CfiMode::IntelBusy { cd: cd - 1, erase };
                    0x0000 // status: not ready
                } else {
                    if let Some((lo, hi)) = erase {
                        for w in lo..hi {
                            st.cells[w as usize] = 0xFFFF;
                        }
                        st.mode = CfiMode::IntelBusy { cd: 0, erase: None };
                    }
                    0x0080 // status: ready
                }
            }
            CfiMode::AmdBusy {
                addr,
                data,
                cd,
                erase,
            } => {
                if word == addr {
                    if cd > 0 {
                        st.mode = CfiMode::AmdBusy {
                            addr,
                            data,
                            cd: cd - 1,
                            erase,
                        };
                        data ^ 0x0080 // DQ7 inverted while busy
                    } else {
                        if let Some((lo, hi)) = erase {
                            for w in lo..hi {
                                st.cells[w as usize] = 0xFFFF;
                            }
                        }
                        st.cells[addr as usize]
                    }
                } else {
                    st.cells[word as usize]
                }
            }
            _ => st.cells[word as usize],
        }
    }

    fn write16(&self, off: u64, val: u16) {
        let mut st = self.state.lock();
        let word = off / 2;
        match st.mode {
            CfiMode::Query => {
                st.mode = CfiMode::Read; // any write exits query
            }
            CfiMode::IntelProg(addr) => {
                if word == addr {
                    st.cells[addr as usize] &= val;
                    st.mode = CfiMode::IntelBusy { cd: 2, erase: None };
                }
            }
            CfiMode::IntelEraseArm(addr) => {
                if word == addr && val == 0x00D0 {
                    st.mode = CfiMode::IntelBusy {
                        cd: 3,
                        erase: Some(Self::block_range(addr)),
                    };
                }
            }
            CfiMode::IntelBusy { .. } => {
                if val == 0x00FF || val == 0x00F0 {
                    st.mode = CfiMode::Read;
                }
                // 0x70 (read status) / 0x50 (clear) keep the mode.
            }
            CfiMode::AmdU1 => {
                if word == 0x2AA && val == 0x0055 {
                    st.mode = CfiMode::AmdCmd { erase_setup: false };
                } else {
                    st.mode = CfiMode::Read;
                }
            }
            CfiMode::AmdCmd { erase_setup } => {
                if !erase_setup && word == 0x555 && val == 0x00A0 {
                    st.mode = CfiMode::AmdProg;
                } else if !erase_setup && word == 0x555 && val == 0x0080 {
                    st.mode = CfiMode::AmdEraseU1;
                } else if erase_setup && val == 0x0030 {
                    st.mode = CfiMode::AmdBusy {
                        addr: word,
                        data: 0xFFFF,
                        cd: 2,
                        erase: Some(Self::block_range(word)),
                    };
                } else {
                    st.mode = CfiMode::Read;
                }
            }
            CfiMode::AmdEraseU1 => {
                if word == 0x555 && val == 0x00AA {
                    st.mode = CfiMode::AmdEraseU2;
                } else {
                    st.mode = CfiMode::Read;
                }
            }
            CfiMode::AmdEraseU2 => {
                if word == 0x2AA && val == 0x0055 {
                    st.mode = CfiMode::AmdCmd { erase_setup: true };
                } else {
                    st.mode = CfiMode::Read;
                }
            }
            CfiMode::AmdProg => {
                // The write after the A0 command is the data word
                // at its own address.
                st.cells[word as usize] &= val;
                st.mode = CfiMode::AmdBusy {
                    addr: word,
                    data: val,
                    cd: 2,
                    erase: None,
                };
            }
            CfiMode::AmdBusy { .. } => {
                if val == 0x00FF || val == 0x00F0 {
                    st.mode = CfiMode::Read;
                }
            }
            CfiMode::Read => match (st.cmdset, val) {
                (_, 0x0098) if word == 0x55 => st.mode = CfiMode::Query,
                (1, 0x0040) => st.mode = CfiMode::IntelProg(word),
                (1, 0x0020) => st.mode = CfiMode::IntelEraseArm(word),
                (1, 0x0070) | (1, 0x0050) | (1, 0x00FF) => {}
                (2, 0x00AA) if word == 0x555 => st.mode = CfiMode::AmdU1,
                _ => {}
            },
        }
    }
}

fn cfi_round_trip(cmdset: u16) -> TestResult {
    let model = ModelCfi::new(cmdset);
    let flash = match CfiFlash::identify("model".into(), model, 0x10_0000) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CFI identify failed against the modelled chip"),
    };
    if flash.size() != 0x10_0000 || flash.erase_size() != 0x1_0000 || flash.cmdset() != cmdset {
        return TestResult::Fail("CFI geometry decode mismatch (size/erase/cmdset)");
    }
    // Program + read back, including an unaligned tail byte.
    if flash.write(0, &[0xDE, 0xAD, 0xBE, 0xEF]).is_err() {
        return TestResult::Fail("CFI program failed");
    }
    if flash.write(5, &[0x42]).is_err() {
        return TestResult::Fail("CFI unaligned program failed");
    }
    let mut buf = [0u8; 6];
    if flash.read(0, &mut buf).is_err() || buf != [0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x42] {
        return TestResult::Fail("CFI read-back mismatch (incl. neighbour preservation)");
    }
    // Program-only-clears: writing all-ones changes nothing.
    if flash.write(0, &[0xFF, 0xFF]).is_err() {
        return TestResult::Fail("CFI no-op program failed");
    }
    if flash.read(0, &mut buf[..2]).is_err() || buf[..2] != [0xDE, 0xAD] {
        return TestResult::Fail("CFI program set a bit without erase");
    }
    // Erase restores all-ones in the block; block 1 untouched.
    if flash.write(0x1_0000, &[0x11]).is_err() {
        return TestResult::Fail("CFI block-1 program failed");
    }
    if flash.erase(0, 0x1_0000).is_err() {
        return TestResult::Fail("CFI erase failed");
    }
    if flash.read(0, &mut buf[..2]).is_err() || buf[..2] != [0xFF, 0xFF] {
        return TestResult::Fail("CFI erase did not restore the block");
    }
    if flash.read(0x1_0000, &mut buf[..1]).is_err() || buf[0] != 0x11 {
        return TestResult::Fail("CFI erase clobbered the neighbouring block");
    }
    // Unaligned erase is BadGeometry.
    if flash.erase(0x100, 0x1_0000) != Err(MtdError::BadGeometry) {
        return TestResult::Fail("CFI unaligned erase not refused");
    }
    TestResult::Pass
}

fn smoke_cfi_intel_round_trip() -> TestResult {
    cfi_round_trip(1)
}
kernel_test_in!("storage-mtd", smoke_cfi_intel_round_trip);

fn smoke_cfi_amd_round_trip() -> TestResult {
    cfi_round_trip(2)
}
kernel_test_in!("storage-mtd", smoke_cfi_amd_round_trip);
