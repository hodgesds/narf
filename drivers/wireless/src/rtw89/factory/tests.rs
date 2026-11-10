use super::*;
use alloc::vec::Vec;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
mod offsets {
    include!("golden.rs");
}
struct SourceModel {
    chip: ChipId,
    cut: u8,
    autoload: u16,
    raw: [u8; 1216],
    extra: [u8; 5],
    phycap: [u8; 128],
    reads: Vec<(u16, usize)>,
    fail: Option<usize>,
    pending: Option<usize>,
}
impl SourceModel {
    fn new(chip: ChipId) -> Self {
        let mut raw = [255; 1216];
        let mut cursor = 4;
        // Independent AX sparse records: high-block nibble followed by low
        // block/active-low word enables, then the actual little-endian word.
        for (offset, bytes) in [
            (0x400, [2, 4]),
            (0x402, [6, 8]),
            (0x404, [10, 12]),
            (0x2b8, [255, 0x33]),
            (0x2ca, [5, b'U']),
            (0x2cc, [b'S', 255]),
        ] {
            let block = offset / 8;
            raw[cursor] = (block >> 4) as u8;
            raw[cursor + 1] = ((block & 15) << 4) as u8 | (15 ^ (1 << ((offset % 8) / 2)));
            raw[cursor + 2..cursor + 4].copy_from_slice(&bytes);
            cursor += 4;
        }
        Self {
            chip,
            cut: 1,
            autoload: 32,
            raw,
            extra: [0xaa, 0x1f, 255, 255, 255],
            phycap: core::array::from_fn(|i| i as u8),
            reads: Vec::new(),
            fail: None,
            pending: None,
        }
    }
}
impl Io for SourceModel {
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        assert_eq!(a, 0xa);
        Ok(self.autoload)
    }
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        panic!("unexpected factory byte MMIO")
    }
    fn read32(&mut self, _: u32) -> Result<u32, power::Error> {
        panic!("unexpected factory dword MMIO")
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        panic!("factory source owns DDV writes")
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        panic!("factory source owns DDV writes")
    }
    fn write32(&mut self, _: u32, _: u32) -> Result<(), power::Error> {
        panic!("factory source owns DDV writes")
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        panic!("cut must come from completed power owner")
    }
}
impl Source for SourceModel {
    fn profile(&self) -> (ChipId, u8) {
        (self.chip, self.cut)
    }
    async fn physical(&mut self, start: u16, output: &mut [u8]) -> Result<(), power::Error> {
        if self.pending == Some(self.reads.len()) {
            core::future::pending::<()>().await;
        }
        if self.fail == Some(self.reads.len()) {
            return Err(power::Error::Access);
        }
        self.reads.push((start, output.len()));
        match (start, output.len()) {
            (0, 1216) => output.copy_from_slice(&self.raw),
            (0x5e9, 5) => output.copy_from_slice(&self.extra),
            (0x580, 128) => {
                output.copy_from_slice(&self.phycap);
                output[0x69..0x6e].copy_from_slice(&self.extra);
            }
            // RTL8852C phycap window 0x590..0x5f0 of the same physical map.
            (0x590, 0x60) => {
                output.copy_from_slice(&self.phycap[0x10..0x70]);
                output[0x59..0x5e].copy_from_slice(&self.extra);
            }
            _ => panic!("factory did not read complete physical proof"),
        };
        Ok(())
    }
}
fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut f = pin!(future);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(r) => Some(r),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_factory_snapshot_matches_linux_layout_and_actual_controls() -> TestResult {
    use offsets::*;
    for (rfe, xtal, country) in [
        (A_RFE_TYPE, A_XTAL_K, A_COUNTRY_CODE),
        (B_RFE_TYPE, B_XTAL_K, B_COUNTRY_CODE),
        (C_RFE_TYPE, C_XTAL_K, C_COUNTRY_CODE),
        (N51_RFE_TYPE, N51_XTAL_K, N51_COUNTRY_CODE),
    ] {
        if (rfe, xtal, country) != (0x2ca, 0x2b9, 0x2cb) {
            return TestResult::Fail("AX factory fields differ from original Linux packed types");
        }
    }
    for chip in [
        ChipId::Rtl8852A,
        ChipId::Rtl8852B,
        ChipId::Rtl8852C,
        ChipId::Rtl8851B,
    ] {
        for valid in [false, true] {
            for power_k in [false, true] {
                let mut source = SourceModel::new(chip);
                source.autoload = if valid { 32 } else { 0 };
                source.extra[0] = if power_k { 0xaa } else { 0xff };
                let mut factory = Factory::default();
                if ready(factory.read(&mut source)) != Some(Ok(())) {
                    return TestResult::Fail("actual factory snapshot refused");
                }
                let id = factory.identity().unwrap();
                if id.chip() != chip
                    || id.cut() != 1
                    || id.mac() != [2, 4, 6, 8, 10, 12]
                    || id.xtal() != 0x33
                    || id.country() != *b"US"
                    || id.fuses().enabled()
                    || id.calibration()
                        != (power::Calibration {
                            rfe_type: 5,
                            valid,
                            power_k_valid: chip == ChipId::Rtl8852B && power_k,
                        })
                    || source.reads
                        != [
                            (0, 1216),
                            match chip {
                                ChipId::Rtl8852A | ChipId::Rtl8852B | ChipId::Rtl8851B => {
                                    (0x580, 128)
                                }
                                ChipId::Rtl8852C => (0x590, 0x60),
                                _ => (0x5e9, 5),
                            },
                        ]
                    || factory.a_phycap().is_some() != (chip == ChipId::Rtl8852A)
                    || factory.b_phycap().is_some() != (chip == ChipId::Rtl8852B)
                    || factory.c_phycap().is_some() != (chip == ChipId::Rtl8852C)
                    || factory.n51_phycap().is_some() != (chip == ChipId::Rtl8851B)
                    || factory.logical().unwrap().len()
                        != if chip == ChipId::Rtl8852A { 1536 } else { 2048 }
                {
                    return TestResult::Fail("factory input was defaulted, detached or misdecoded");
                }
                let reads = source.reads.len();
                if ready(factory.read(&mut source)) != Some(Err(Error::Terminal))
                    || source.reads.len() != reads
                {
                    return TestResult::Fail("completed factory snapshot was replayed");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_factory_snapshot_matches_linux_layout_and_actual_controls
);
fn smoke_rtw89_factory_failure_cancel_and_corrected_cut_keep_identity_private() -> TestResult {
    for failed in 0..2 {
        for cancel in [false, true] {
            let mut source = SourceModel::new(ChipId::Rtl8851B);
            if cancel {
                source.pending = Some(failed);
            } else {
                source.fail = Some(failed);
            }
            let mut factory = Factory::default();
            if ready(factory.read(&mut source)) == Some(Ok(()))
                || factory.state() != State::Reading
                || factory.identity().is_some()
                || factory.logical().is_some()
                || factory.a_phycap().is_some()
                || factory.b_phycap().is_some()
                || factory.n51_phycap().is_some()
            {
                return TestResult::Fail("uncertain factory transaction published identity");
            }
            let reads = source.reads.len();
            if ready(factory.read(&mut source)) != Some(Err(Error::Terminal))
                || source.reads.len() != reads
            {
                return TestResult::Fail("uncertain factory transaction replayed");
            }
        }
    }
    let mut source = SourceModel::new(ChipId::Rtl8851B);
    source.extra[1] = 0x2f;
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Err(Error::Unsupported))
        || factory.identity().is_some()
    {
        return TestResult::Fail("changed ECV was detached from corrected physical cut");
    }
    let mut source = SourceModel::new(ChipId::Rtl8852B);
    source.extra[3..].fill(0);
    let mut factory = Factory::default();
    if !matches!(
        ready(factory.read(&mut source)),
        Some(Err(Error::Secure(_)))
    ) || factory.identity().is_some()
    {
        return TestResult::Fail("unknown programmed secure fuses became erased defaults");
    }
    let mut source = SourceModel::new(ChipId::Rtl8852B);
    source.autoload = u16::MAX;
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Err(Error::Register(power::Error::Gone)))
        || !source.reads.is_empty()
    {
        return TestResult::Fail("missing factory device used calibration defaults");
    }
    let mut source = SourceModel::new(ChipId::Rtl8922A);
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Err(Error::Unsupported)) || !source.reads.is_empty()
    {
        return TestResult::Fail("BE used AX factory layout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_factory_failure_cancel_and_corrected_cut_keep_identity_private
);

fn smoke_rtw89_b_phycap_is_actual_complete_and_matches_linux_packed_fields() -> TestResult {
    use offsets::*;
    if [
        B_TSSI_A,
        B_TSSI_B,
        B_THERMAL_A,
        B_THERMAL_B,
        B_GAIN_CCK,
        B_GAIN_OFDM,
        B_GAIN_LOW,
        B_GAIN_MID,
        B_GAIN_HIGH,
        B_TSSI_CCK,
        B_TSSI_MCS2G,
        B_TSSI_MCS5G,
    ] != [
        0x210, 0x23a, 0x2d0, 0x2d1, 0x2d6, 0x2d4, 0x2d8, 0x2da, 0x2dc, 0, 6, 0x12,
    ] {
        return TestResult::Fail("B calibration differs from original Linux packed types");
    }
    let mut source = SourceModel::new(ChipId::Rtl8852B);
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Ok(())) {
        return TestResult::Fail("B full physical PHY-cap snapshot failed");
    }
    let mut expected = source.phycap;
    expected[0x69..0x6e].copy_from_slice(&source.extra);
    if factory.b_phycap() != Some(&expected) {
        return TestResult::Fail("B calibration source substituted a PHY-cap byte");
    }
    let calibration = super::super::factory_b::Calibration::from_factory(&factory).unwrap();
    if calibration.thermal_trim != [0x5f, 0x5c]
        || calibration.pa_bias != [0x5e, 0x5b]
        || calibration.tssi_trim
            != [
                [0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4f],
                [0x2b, 0x2a, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24],
            ]
        || !calibration.trim_programmed
        || !calibration.thermal_programmed
        || !calibration.pa_programmed
        || calibration.gain_comp != [[-5, -6, 0, -7, -8], [0, -1, 0, -2, -3]]
        || !calibration.comp_valid
        || calibration.offset_valid
        || calibration.gain_offset != [[-1; 5]; 2]
        || calibration.tssi_cck != [[-1; 6]; 2]
        || calibration.tssi_mcs != [[-1; 19]; 2]
    {
        return TestResult::Fail("B PHY-cap signed values or validity flags were misdecoded");
    }
    let mut source = SourceModel::new(ChipId::Rtl8852B);
    source.phycap.fill(255);
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Ok(())) {
        return TestResult::Fail(
            "actual erased B PHY-cap map rejected before policy qualification",
        );
    }
    let calibration = super::super::factory_b::Calibration::from_factory(&factory).unwrap();
    if calibration.trim_programmed
        || calibration.thermal_programmed
        || calibration.pa_programmed
        || calibration.comp_valid
        || calibration.tssi_trim != [[0; 8]; 2]
    {
        return TestResult::Fail("B erased interpretation fabricated programmed calibration");
    }
    for cancel in [false, true] {
        let mut source = SourceModel::new(ChipId::Rtl8852B);
        if cancel {
            source.pending = Some(1);
        } else {
            source.fail = Some(1);
        }
        let mut factory = Factory::default();
        if ready(factory.read(&mut source)) == Some(Ok(()))
            || factory.b_phycap().is_some()
            || super::super::factory_b::Calibration::from_factory(&factory).is_some()
        {
            return TestResult::Fail("uncertain B PHY-cap read published trim defaults");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_phycap_is_actual_complete_and_matches_linux_packed_fields
);
fn smoke_rtw89_c_phycap_and_efuse_match_linux_rtw8852c_layout() -> TestResult {
    use super::super::factory_c::{Calibration, GAIN_OFFSET_ADDR};
    // rtw8852c.h `struct rtw8852c_efuse` gain offsets (2G CCK, 2G OFDM,
    // 5G L/M/H, 6G L0..UH1) and the separate 0x590/0x60 PHY-cap window.
    if GAIN_OFFSET_ADDR
        != [
            0x2d6, 0x2d4, 0x2d8, 0x2da, 0x2dc, 0x3a8, 0x3aa, 0x3ac, 0x3ae, 0x3b0, 0x3b2, 0x3b4,
            0x3b6,
        ]
    {
        return TestResult::Fail("C gain-offset layout differs from rtw8852c.h");
    }
    let mut source = SourceModel::new(ChipId::Rtl8852C);
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Ok(())) {
        return TestResult::Fail("C full PHY-cap snapshot failed");
    }
    let mut expected = [0u8; 0x60];
    expected.copy_from_slice(&source.phycap[0x10..0x70]);
    expected[0x59..0x5e].copy_from_slice(&source.extra);
    if factory.c_phycap() != Some(&expected)
        || factory.b_phycap().is_some()
        || super::super::factory_b::Calibration::from_factory(&factory).is_some()
    {
        return TestResult::Fail("C PHY-cap window substituted or crossed into the B owner");
    }
    let Some(c) = Calibration::from_factory(&factory) else {
        return TestResult::Fail("C calibration refused a complete factory snapshot");
    };
    let down = |top: u8, n: usize| -> Vec<i8> { (0..n).map(|i| (top - i as u8) as i8).collect() };
    if c.thermal_trim != [0x5f, 0x5c]
        || c.pa_bias != [0x5e, 0x5b]
        || c.tssi_trim[0][..] != down(0x56, 8)[..]
        || c.tssi_trim[1][..] != down(0x2b, 8)[..]
        || c.tssi_trim_6g[0][..] != down(0x4e, 16)[..]
        || c.tssi_trim_6g[1][..] != down(0x23, 16)[..]
        || !c.trim_programmed
        || !c.thermal_programmed
        || !c.pa_programmed
        || c.thermal_setting(0) != Some(15)
        || c.thermal_setting(1) != Some(6)
        || c.pa_bias_setting(0) != Some((0xe, 0x5))
        || c.pa_bias_setting(1) != Some((0xb, 0x5))
        || c.offset_valid
        || c.gain_offset != [[-1; 13]; 2]
        || c.tssi_cck != [[-1; 6]; 2]
        || c.tssi_mcs != [[-1; 19]; 2]
        || c.tssi_6g_mcs != [[-1; 32]; 2]
    {
        return TestResult::Fail("C PHY-cap/efuse values or validity flags were misdecoded");
    }
    let mut source = SourceModel::new(ChipId::Rtl8852C);
    source.phycap.fill(255);
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Ok(())) {
        return TestResult::Fail("erased C PHY-cap map rejected before policy");
    }
    let c = Calibration::from_factory(&factory).unwrap();
    if c.trim_programmed
        || c.thermal_programmed
        || c.pa_programmed
        || c.tssi_trim != [[0; 8]; 2]
        || c.tssi_trim_6g != [[0; 16]; 2]
        || c.thermal_setting(0).is_some()
        || c.pa_bias_setting(1).is_some()
    {
        return TestResult::Fail("C erased interpretation fabricated programmed calibration");
    }
    for cancel in [false, true] {
        let mut source = SourceModel::new(ChipId::Rtl8852C);
        if cancel {
            source.pending = Some(1);
        } else {
            source.fail = Some(1);
        }
        let mut factory = Factory::default();
        if ready(factory.read(&mut source)) == Some(Ok(()))
            || factory.c_phycap().is_some()
            || Calibration::from_factory(&factory).is_some()
        {
            return TestResult::Fail("uncertain C PHY-cap read published calibration");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_phycap_and_efuse_match_linux_rtw8852c_layout
);

fn smoke_rtw89_n51_phycap_and_efuse_match_linux_rtw8851b_layout() -> TestResult {
    use super::super::factory_51::{
        Calibration, ADC_TD, GAIN_COMP, GAIN_OFFSET_ADDR, PA_BIAS_TRIM, THERMAL, THERMAL_TRIM,
        TSSI_BASE, TSSI_TRIM,
    };
    // rtw8851b.h `struct rtw8851b_efuse` (path_a_tssi 0x210, path_a_therm
    // 0x2d0, rx_gain_* 0x2d4..0x2dc) and rtw8851b.c phycap addresses.
    if (TSSI_BASE, THERMAL, GAIN_OFFSET_ADDR) != (0x210, 0x2d0, [0x2d6, 0x2d4, 0x2d8, 0x2da, 0x2dc])
        || (TSSI_TRIM, THERMAL_TRIM, PA_BIAS_TRIM, ADC_TD) != (0x5d6, 0x5df, 0x5de, 0x5af)
        || GAIN_COMP != [0x5bb, 0x5ba, 0, 0x5b9, 0x5b8]
    {
        return TestResult::Fail("8851B factory layout differs from rtw8851b.{c,h}");
    }
    let mut source = SourceModel::new(ChipId::Rtl8851B);
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Ok(())) {
        return TestResult::Fail("8851B full PHY-cap snapshot failed");
    }
    let mut expected = source.phycap;
    expected[0x69..0x6e].copy_from_slice(&source.extra);
    if factory.n51_phycap() != Some(&expected)
        || factory.b_phycap().is_some()
        || super::super::factory_b::Calibration::from_factory(&factory).is_some()
        || super::super::factory_c::Calibration::from_factory(&factory).is_some()
    {
        return TestResult::Fail("8851B PHY-cap window substituted or crossed into B/C owners");
    }
    let Some(n) = Calibration::from_factory(&factory) else {
        return TestResult::Fail("8851B calibration refused a complete factory snapshot");
    };
    let down = |top: u8| -> [i8; 8] { core::array::from_fn(|i| (top - i as u8) as i8) };
    // Model phycap[i] = i: 0x5df -> 0x5f, 0x5de -> 0x5e, 0x5af -> 0x2f.
    if n.thermal_trim != 0x5f
        || n.pa_bias != 0x5e
        || n.tssi_trim != down(0x56)
        || !n.trim_programmed
        || !n.thermal_programmed
        || !n.pa_programmed
        // __thm_setting(0x5f) = (1 << 3) | (0x1f >> 1) = 0x0f.
        || n.thermal_setting() != Some(0x0f)
        || n.pa_bias_setting() != Some((0xe, 0x5))
        || n.adc_td != 0x0f
        || n.gain_comp != [-5, -6, 0, -7, -8]
        || !n.comp_valid
        || n.offset_valid
        || n.gain_offset != [-1; 5]
        || n.tssi_cck != [-1; 6]
        || n.tssi_mcs != [-1; 19]
        || n.thermal != 255
    {
        return TestResult::Fail("8851B PHY-cap/efuse values or validity flags were misdecoded");
    }
    let mut source = SourceModel::new(ChipId::Rtl8851B);
    source.phycap.fill(255);
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Ok(())) {
        return TestResult::Fail("erased 8851B PHY-cap map rejected before policy");
    }
    let n = Calibration::from_factory(&factory).unwrap();
    if n.trim_programmed
        || n.thermal_programmed
        || n.pa_programmed
        || n.comp_valid
        || n.tssi_trim != [0; 8]
        || n.thermal_setting().is_some()
        || n.pa_bias_setting().is_some()
    {
        return TestResult::Fail("8851B erased interpretation fabricated programmed calibration");
    }
    for cancel in [false, true] {
        let mut source = SourceModel::new(ChipId::Rtl8851B);
        if cancel {
            source.pending = Some(1);
        } else {
            source.fail = Some(1);
        }
        let mut factory = Factory::default();
        if ready(factory.read(&mut source)) == Some(Ok(()))
            || factory.n51_phycap().is_some()
            || Calibration::from_factory(&factory).is_some()
        {
            return TestResult::Fail("uncertain 8851B PHY-cap read published calibration");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_phycap_and_efuse_match_linux_rtw8851b_layout
);

/// Test-only identity of an actual RTL8852C factory snapshot (RFE 5, XTAL
/// 0x33) decoded through `Factory::read` from the C sparse-map model.
pub(in crate::rtw89) fn c_identity() -> Identity {
    let mut source = SourceModel::new(ChipId::Rtl8852C);
    let mut factory = Factory::default();
    narf_scheduler::block_on(factory.read(&mut source)).unwrap();
    factory.identity().unwrap()
}

fn smoke_rtw89_a_phycap_and_efuse_match_linux_rtw8852a_layout() -> TestResult {
    use super::super::factory_a::Calibration;
    use super::{A_PHYCAP_ADDR, A_PHYCAP_SIZE};
    // rtw8852a.c `rtw8852a_chip_info.{phycap_addr,phycap_size}`; the efuse
    // and trim offsets below are rtw8852a.h `struct rtw8852a_efuse`
    // (path_a_tssi 0x210, path_b_tssi 0x23a, path_a_therm 0x2d0,
    // path_b_therm 0x2d1) and rtw8852a.c (tssi_trim {0x5d6, 0x5ab},
    // thermal trim {0x5df, 0x5dc}, PA bias trim {0x5de, 0x5db}).
    if (A_PHYCAP_ADDR, A_PHYCAP_SIZE) != (0x580, 128) {
        return TestResult::Fail("A PHY-cap window differs from rtw8852a_chip_info");
    }
    let mut source = SourceModel::new(ChipId::Rtl8852A);
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Ok(())) {
        return TestResult::Fail("A full PHY-cap snapshot failed");
    }
    let mut expected = source.phycap;
    expected[0x69..0x6e].copy_from_slice(&source.extra);
    if factory.a_phycap() != Some(&expected)
        || factory.b_phycap().is_some()
        || factory.c_phycap().is_some()
        || factory.n51_phycap().is_some()
        || super::super::factory_b::Calibration::from_factory(&factory).is_some()
        || super::super::factory_c::Calibration::from_factory(&factory).is_some()
    {
        return TestResult::Fail("A PHY-cap window substituted or crossed into B/C owners");
    }
    let Some(a) = Calibration::from_factory(&factory) else {
        return TestResult::Fail("A calibration refused a complete factory snapshot");
    };
    // The model leaves the logical TSSI/thermal bytes unset (0); the
    // 0x2b8 record ([255, 0x33]) pins the thermal offsets against a shift.
    if a.thermal_trim != [0x5f, 0x5c]
        || a.pa_bias != [0x5e, 0x5b]
        || a.tssi_trim
            != [
                [0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4f],
                [0x2b, 0x2a, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24],
            ]
        || !a.trim_programmed
        || !a.thermal_programmed
        || !a.pa_programmed
        || a.thermal != [0, 0]
        || a.tssi_cck != [[0; 6]; 2]
        || a.tssi_mcs != [[0; 19]; 2]
    {
        return TestResult::Fail("A PHY-cap/efuse values or validity flags were misdecoded");
    }
    let mut source = SourceModel::new(ChipId::Rtl8852A);
    source.phycap.fill(255);
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Ok(())) {
        return TestResult::Fail("erased A PHY-cap map rejected before policy");
    }
    let a = Calibration::from_factory(&factory).unwrap();
    if a.trim_programmed || a.thermal_programmed || a.pa_programmed || a.tssi_trim != [[0; 8]; 2] {
        return TestResult::Fail("A erased interpretation fabricated programmed calibration");
    }
    for cancel in [false, true] {
        let mut source = SourceModel::new(ChipId::Rtl8852A);
        if cancel {
            source.pending = Some(1);
        } else {
            source.fail = Some(1);
        }
        let mut factory = Factory::default();
        if ready(factory.read(&mut source)) == Some(Ok(()))
            || factory.a_phycap().is_some()
            || Calibration::from_factory(&factory).is_some()
        {
            return TestResult::Fail("uncertain A PHY-cap read published calibration");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_phycap_and_efuse_match_linux_rtw8852a_layout
);
