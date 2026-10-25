use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{object_table, Cap, CapKind, CapSlot, Rights, Write};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
pub(in crate::rtw89) struct Model {
    pub(in crate::rtw89) words: Vec<u32>,
    pub(in crate::rtw89) rf: [Vec<u32>; 2],
    pub(in crate::rtw89) hash: u64,
    pub(in crate::rtw89) count: u32,
    pub(in crate::rtw89) operations: usize,
    pub(in crate::rtw89) fail: Option<usize>,
    pub(in crate::rtw89) ignore: Option<(u32, u32)>,
    pub(in crate::rtw89) pending_delay: bool,
    pub(in crate::rtw89) authority: Cap<BusDeviceCap, Write>,
    pub(in crate::rtw89) now: u64,
    pub(in crate::rtw89) kind: Option<rfk::Kind>,
    pub(in crate::rtw89) cw_timeout: bool,
    pub(in crate::rtw89) nctl_first_timeout: bool,
    pub(in crate::rtw89) nctl_second_timeout: bool,
    pub(in crate::rtw89) correlation: u8,
    pub(in crate::rtw89) dc: [u16; 2],
    pub(in crate::rtw89) digital_gain: u16,
    pub(in crate::rtw89) gain_loss: u8,
    nctl_active: bool,
    pub(in crate::rtw89) nctl_commands: usize,
    pmac_started: bool,
}
impl Model {
    pub(in crate::rtw89) fn new(seed: u32) -> Self {
        let (index, generation) = object_table::register(CapKind::BusDevice);
        // SAFETY: exact private fresh object type/epoch and Write rights.
        let authority = unsafe {
            Cap::mint(CapSlot::new(
                generation,
                index,
                Write::BITS,
                CapKind::BusDevice as u32,
            ))
        };
        Self {
            words: vec![seed; 0x20000 / 4],
            rf: core::array::from_fn(|_| vec![seed & 0xfffff; 0x10100]),
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            fail: None,
            ignore: None,
            pending_delay: false,
            authority,
            now: 0,
            kind: None,
            cw_timeout: false,
            nctl_first_timeout: false,
            nctl_second_timeout: false,
            correlation: 200,
            dc: [0xff6, 20], // actual12-bit -10/+20, Source sign-extends then abs.
            digital_gain: 1500,
            gain_loss: 2,
            nctl_active: false,
            nctl_commands: 0,
            pmac_started: false,
        }
    }
    pub(in crate::rtw89) fn selector(&self, address: u32, mask: u32) -> u32 {
        (self.words[(0x10000 + address) as usize / 4] & mask) >> mask.trailing_zeros()
    }
    fn checked<T>(&mut self, operation: impl FnOnce(&mut Self) -> T) -> Result<T, power::Error> {
        let authority = self.authority;
        crate::rtw88::pci_park::invoke(&authority, || {
            let index = self.operations;
            self.operations += 1;
            if self.fail == Some(index) {
                return Err(power::Error::Access);
            }
            Ok(operation(self))
        })
        .map_err(|_| power::Error::Access)?
    }
    pub(in crate::rtw89) fn record(&mut self, values: &[u32]) {
        self.count += 1;
        for value in values {
            for byte in value.to_le_bytes() {
                self.hash ^= u64::from(byte);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
    }
    pub(in crate::rtw89) fn reset_trace(&mut self) {
        self.hash = 14695981039346656037;
        self.count = 0;
        self.operations = 0;
    }
    fn measured(&self, address: u32) -> u32 {
        let mut value = self.words[address as usize / 4];
        if address < 0x10000 {
            return value;
        }
        let register = address - 0x10000;
        if register == 0x1c18 || register == 0x3c18 {
            let path = u32::from(register == 0x3c18);
            let power = self.selector(R_TXPWR, B_TXPWR_MSK);
            let active = self.pmac_started && self.selector(R_PMAC_TX_PRD, B_PMAC_PTX_EN) != 0;
            value = if active && !self.cw_timeout {
                1 << 16 | if power == 48 { 300 } else { 230 }
            } else {
                0
            };
            if value != 0 {
                value += path * 17;
            }
        }
        // DPK measurements depend on its actual retained selector/NCTL state,
        // rather than the host algorithm supplying a successful measurement.
        if self.kind == Some(rfk::Kind::Dpk) {
            if register == 0xbff8 {
                value = if self.nctl_first_timeout || !self.nctl_active {
                    0
                } else {
                    0x55
                };
            }
            if register == 0x80fc {
                value = match self.selector(0x80d4, 0x3f0000) {
                    3 => {
                        if self.nctl_second_timeout || !self.nctl_active {
                            0
                        } else {
                            0x8000
                        }
                    }
                    0 => u32::from(self.digital_gain) << 16 | u32::from(self.correlation) << 8 | 7,
                    9 => u32::from(self.dc[0]) << 16 | u32::from(self.dc[1]),
                    6 => {
                        if self.selector(0x80bc, 0x4000) != 0 {
                            u32::from(self.gain_loss) << 4
                        } else if self.selector(0x80c0, 0xff000000) == 0 {
                            125 << 16 | 125
                        } else {
                            100 << 16 | 100
                        }
                    }
                    _ => 0,
                };
            }
        }
        value
    }
}
impl power::Io for Model {
    fn read8(&mut self, address: u32) -> Result<u8, power::Error> {
        Ok((self.read32(address & !3)? >> ((address & 3) * 8)) as u8)
    }
    fn read16(&mut self, address: u32) -> Result<u16, power::Error> {
        Ok((self.read32(address & !3)? >> ((address & 2) * 8)) as u16)
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        self.checked(|model| model.measured(address))
    }
    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error> {
        let old = self.read32(address & !3)?;
        let shift = (address & 3) * 8;
        self.write32(
            address & !3,
            old & !(255 << shift) | u32::from(value) << shift,
        )
    }
    fn write16(&mut self, address: u32, value: u16) -> Result<(), power::Error> {
        let old = self.read32(address & !3)?;
        let shift = (address & 2) * 8;
        self.write32(
            address & !3,
            old & !(65535 << shift) | u32::from(value) << shift,
        )
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.checked(|model| {
            let old = model.words[address as usize / 4];
            model.words[address as usize / 4] = if let Some((ignored, mask)) =
                model.ignore.filter(|(ignored, _)| *ignored == address)
            {
                let _ = ignored;
                old & mask | value & !mask
            } else {
                value
            };
            model.record(&[4, address, value]);
            let actual = model.words[address as usize / 4];
            if address == 0x10000 + R_PMAC_TX_PRD && actual & B_PMAC_PTX_EN == 0 {
                model.pmac_started = false;
            }
            if address == 0x10000 + R_PMAC_TX_CTRL
                && old & B_PMAC_TXEN_DIS != 0
                && actual & B_PMAC_TXEN_DIS == 0
                && model.selector(R_PMAC_TX_PRD, B_PMAC_PTX_EN) != 0
            {
                model.pmac_started = true;
            }
            if address == 0x18000 && model.ignore.is_none_or(|(a, _)| a != address) {
                model.nctl_active = value != 0;
                model.nctl_commands += 1;
                // Actual hardware completion updates NCTL_N1 as well as bff8.
                // Keep that status in the shared register backing, so an
                // ignored source clear really retains the previous55 byte.
                if model.nctl_active && !model.nctl_first_timeout {
                    let old = model.words[0x18010 / 4];
                    model.words[0x18010 / 4] = old & !255 | 0x55;
                }
            }
            if address == 0x18010 && actual & 255 == 0 {
                model.nctl_active = false;
            }
        })
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        if self.pending_delay {
            core::future::pending::<()>().await;
        }
        self.now += us;
        self.record(&[8, us as u32, 0]);
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Ok(None)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || ()).map_err(|_| Error::Policy)
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        Ok(self.checked(|model| {
            let mut value = model.rf[path as usize][address as usize];
            if model.kind == Some(rfk::Kind::Dpk) && address == 0x42 {
                value = value & !0x7e | ([31, 35][path as usize] << 1);
            }
            (value & mask) >> mask.trailing_zeros()
        })?)
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.checked(|model| {
            let old = model.rf[path as usize][address as usize];
            model.rf[path as usize][address as usize] =
                old & !mask | value << mask.trailing_zeros() & mask;
            model.record(&[36, u32::from(path), address, mask, value]);
        })?;
        Ok(())
    }
    async fn begin(&mut self, kind: rfk::Kind) -> Result<(), Error> {
        self.admit()?;
        if self.kind.replace(kind).is_some() {
            return Err(Error::Terminal);
        }
        Ok(())
    }
    async fn end(&mut self, kind: rfk::Kind) -> Result<(), Error> {
        self.admit()?;
        if self.kind.take() != Some(kind) {
            return Err(Error::Terminal);
        }
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        self.admit()?;
        self.record(&[56, 0, 0x11223344]);
        Ok(0x11223344)
    }
    async fn resume(&mut self, saved: u32) -> Result<(), Error> {
        self.admit()?;
        self.record(&[60, 0, saved]);
        Ok(())
    }
}
pub(in crate::rtw89) fn calibration(erased: bool) -> Calibration {
    let mut result = Calibration {
        thermal: if erased { [255; 2] } else { [32, 34] },
        tssi_cck: [[0; 6]; 2],
        tssi_mcs: [[0; 19]; 2],
        tssi_trim: [[0; 8]; 2],
        trim_programmed: true,
        thermal_trim: [0; 2],
        thermal_programmed: false,
        pa_bias: [0; 2],
        pa_programmed: false,
        gain_offset: [[0; 5]; 2],
        offset_valid: true,
        gain_comp: [[0; 5]; 2],
        comp_valid: true,
    };
    for path in 0..2 {
        result.tssi_cck[path][0] = [-3, 5][path];
        result.tssi_mcs[path][0] = [-9, 11][path];
        result.tssi_trim[path][0] = [2, -4][path];
        result.gain_comp[path][0] = [7, -5][path];
        result.gain_offset[path][0] = [3, -2][path];
        result.gain_offset[path][1] = [-6, 4][path];
    }
    result
}
pub(in crate::rtw89) fn tracking(custom: bool) -> Tracking {
    if custom {
        Tracking {
            up: core::array::from_fn(|p| core::array::from_fn(|i| [11, 9][p] * 3 + i as i8 - 64)),
            down: core::array::from_fn(|p| core::array::from_fn(|i| [10, 8][p] * 3 + i as i8 - 64)),
        }
    } else {
        Tracking {
            up: [tables::A_P, tables::B_P],
            down: [tables::A_N, tables::B_N],
        }
    }
}
pub(in crate::rtw89) fn complete<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..20_000 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return Some(result);
        }
    }
    None
}
pub(in crate::rtw89) fn fixture() -> (Tssi, Model) {
    fixture_with_seed(0)
}
pub(in crate::rtw89) fn fixture_with_seed(seed: u32) -> (Tssi, Model) {
    let mut owner = Tssi::default();
    let mut model = Model::new(seed);
    // SAFETY: private inert exact initial-profile model and explicit source
    // factory/curve/base fixtures; all measured bytes use current invocation.
    let result = complete(unsafe {
        owner.prepare(&mut model, &calibration(false), &tracking(false), [-30, 46])
    });
    assert_eq!(result, Some(Ok(())));
    (owner, model)
}
fn smoke_rtw89_b_tssi_full_hwtx_matches_frozen_references() -> TestResult {
    for &(seed, erased, custom, count, hash, alignment) in CASES {
        let mut model = Model::new(seed);
        let mut owner = Tssi::default();
        // SAFETY: inert source-matching profile, actual modeled factory/CW
        // measurements and complete current-epoch native access model.
        if complete(unsafe {
            owner.prepare(
                &mut model,
                &calibration(erased),
                &tracking(custom),
                [-30, 46],
            )
        }) != Some(Ok(()))
            || owner.results().is_none_or(|r| {
                r.alignment != alignment
                    || r.cw != [[300, 230], [317, 247]]
                    || r.de != [[-1, -7], [1, 7]]
            })
            || model.count != count
            || model.hash != hash
            || model.kind.is_some()
        {
            return TestResult::Fail(
                "full two-path TSSI/PMAC write trace or signed measurement differs from the frozen reference",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_tssi_full_hwtx_matches_frozen_references
);

fn smoke_rtw89_b_tssi_tracking_bitmap_and_signed_thermal_bounds() -> TestResult {
    let mut bytes = vec![0; 8 + (4 * 3 + 8) * 30];
    bytes[..4].copy_from_slice(&0xfff0u32.to_le_bytes());
    for (index, byte) in bytes[8..].iter_mut().enumerate() {
        *byte = index as u8;
    }
    if Tracking::parse(&bytes).is_err() {
        return TestResult::Fail("exact B tracking bitmap rejected");
    }
    for fault in 0..4 {
        let mut bad = bytes.clone();
        match fault {
            0 => bad[1] &= !4,
            1 => bad[2] = 1,
            2 => {
                bad.pop();
            }
            3 => bad.push(0),
            _ => unreachable!(),
        }
        if Tracking::parse(&bad).is_ok() {
            return TestResult::Fail("malformed present tracking rows selected invented fallback");
        }
    }
    let words = thermal_words(32, &[-128; 30], &[-128; 30]);
    if words != [0x80808080; 16] || thermal_words(255, &[127; 30], &[-128; 30]) != [0; 16] {
        return TestResult::Fail("source signed-byte thermal packing/erased fallback differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_tssi_tracking_bitmap_and_signed_thermal_bounds
);

fn smoke_rtw89_b_full_rx_ab_path_matches_frozen_referencesommon_source() -> TestResult {
    for &(seed, count, hash) in RX_AB_CASES {
        let mut model = Model::new(seed);
        // SAFETY: inert exact B PHY0/channel1/20/RF_AB/rx_nss2 source fixture.
        if unsafe { configure_rx_ab(&mut model, &calibration(false), [-30, 46]) }.is_err()
            || model.count != count
            || model.hash != hash
        {
            return TestResult::Fail(
                "complete initial RXAB/gain/BTG/RF-mode/NSS path differs from the frozen reference",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_full_rx_ab_path_matches_frozen_referencesommon_source
);

fn smoke_rtw89_b_tssi_fail_cancel_revocation_and_ignored_controls_no_completion() -> TestResult {
    let (_, baseline) = fixture();
    for index in [
        0,
        1,
        10,
        100,
        300,
        baseline.operations / 2,
        baseline.operations - 5,
        baseline.operations - 1,
    ] {
        let mut model = Model::new(0);
        model.fail = Some(index);
        let mut owner = Tssi::default();
        // SAFETY: same inert source fixture, with one actual operation rejected.
        if complete(unsafe {
            owner.prepare(&mut model, &calibration(false), &tracking(false), [-30, 46])
        })
        .is_none_or(|r| r.is_ok())
            || owner.results().is_some()
            || owner.state() != State::Calibrating
        {
            return TestResult::Fail(
                "TSSI actual access failure earned calibration or reusable owner",
            );
        }
    }
    for (address, mask) in [
        (R_PMAC_TX_PRD, B_PMAC_PTX_EN),
        (R_PMAC_TX_CTRL, B_PMAC_TXEN_DIS),
        (R_P0_TSSI_AVG, B_P0_TSSI_EN),
        (0x5858, 0x3ff000),
    ] {
        let mut model = Model::new(0);
        model.ignore = Some((0x10000 + address, mask));
        let mut owner = Tssi::default();
        // SAFETY: exact inert profile; ignored real controls cannot complete.
        if complete(unsafe {
            owner.prepare(&mut model, &calibration(false), &tracking(false), [-30, 46])
        })
        .is_none_or(|r| r.is_ok())
            || owner.results().is_some()
        {
            return TestResult::Fail("ignored TSSI/PMAC write granted completion");
        }
    }
    let mut model = Model::new(0);
    model.cw_timeout = true;
    model.pending_delay = true;
    let mut owner = Tssi::default();
    let c = calibration(false);
    let t = tracking(false);
    {
        // SAFETY: exact retained PMAC/CW fixture; cancellation retains its owner.
        let future = unsafe { owner.prepare(&mut model, &c, &t, [-30, 46]) };
        let mut future = pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        if !future.as_mut().poll(&mut cx).is_pending() {
            return TestResult::Fail("TSSI CW wait cancellation fixture");
        }
    }
    let before = model.count;
    // SAFETY: cancelled same one-shot fixture must reject before hardware I/O.
    let replay = complete(unsafe { owner.prepare(&mut model, &c, &t, [-30, 46]) });
    if owner.results().is_some() || replay != Some(Err(Error::Terminal)) || model.count != before {
        return TestResult::Fail("cancelled TSSI one-shot replayed or exposed measurement");
    }
    model.pending_delay = false;
    if stop_pmac(&mut model).is_err() || model.selector(R_PMAC_TX_PRD, B_PMAC_PTX_EN) != 0 {
        return TestResult::Fail("terminal PMAC closure failed");
    }
    let mut model = Model::new(0);
    model.authority.revoke();
    let mut owner = Tssi::default();
    // SAFETY: revoked exact fixture authority rejects all actual operations.
    if complete(unsafe { owner.prepare(&mut model, &c, &t, [-30, 46]) }) != Some(Err(Error::Policy))
        || model.count != 0
        || model.operations != 0
    {
        return TestResult::Fail("revoked TSSI authority entered actual radio program");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_tssi_fail_cancel_revocation_and_ignored_controls_no_completion
);
