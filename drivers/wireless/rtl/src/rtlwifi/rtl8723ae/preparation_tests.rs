// SPDX-License-Identifier: GPL-2.0-or-later
//! Literal RTL8723AE IQK and EFUSE/RF6052 preparation regressions.
use super::{adapter, iqk, phy, tables, tests, txpower, version};
use crate::rtlwifi::{
    firmware_transport::{Error as AccessError, Io},
    prepare::Error,
};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    W(u8, u16, u32),
    Delay(u64),
}
#[derive(Clone, Copy)]
struct Shot {
    x: u16,
    y: u16,
    rx: u16,
    ry: u16,
    flags: u32,
}
struct Model {
    regs: Vec<u8>,
    events: Vec<Event>,
    shots: Vec<Shot>,
    next: usize,
    fail: Option<u16>,
    pause: bool,
}
#[derive(Clone)]
struct Port(Arc<IrqSafeSpinLock<Model>>);
impl Port {
    fn new(shots: Vec<Shot>) -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            regs: vec![0; 0x2000],
            events: Vec::new(),
            shots,
            next: 0,
            fail: None,
            pause: false,
        })))
    }
    fn set32(&self, reg: u16, value: u32) {
        self.0.lock().regs[usize::from(reg)..usize::from(reg) + 4]
            .copy_from_slice(&value.to_le_bytes());
    }
    fn set8(&self, reg: u16, value: u8) {
        self.0.lock().regs[usize::from(reg)] = value;
    }
    fn word(&self, reg: u16) -> u32 {
        let g = self.0.lock();
        u32::from_le_bytes(
            g.regs[usize::from(reg)..usize::from(reg) + 4]
                .try_into()
                .unwrap(),
        )
    }
    fn writes(&self) -> Vec<(u8, u16, u32)> {
        self.0
            .lock()
            .events
            .iter()
            .filter_map(|e| match e {
                Event::W(w, r, v) => Some((*w, *r, *v)),
                _ => None,
            })
            .collect()
    }
    fn write(&self, width: u8, reg: u16, value: u32) -> Result<(), AccessError> {
        let mut g = self.0.lock();
        if g.fail == Some(reg) {
            return Err(AccessError::Access);
        }
        g.events.push(Event::W(width, reg, value));
        let at = usize::from(reg);
        g.regs[at..at + usize::from(width)]
            .copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
        if width == 4 && reg == 0xe48 && value == 0xf800_0000 {
            if let Some(shot) = g.shots.get(g.next).copied() {
                g.next += 1;
                for (r, v) in [
                    (0xe94, u32::from(shot.x) << 16),
                    (0xe9c, u32::from(shot.y) << 16),
                    (0xea4, u32::from(shot.rx) << 16),
                    (0xeac, (u32::from(shot.ry) << 16) | shot.flags),
                ] {
                    g.regs[r..r + 4].copy_from_slice(&v.to_le_bytes());
                }
            }
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl Io for Port {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        Ok(self.0.lock().regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        Ok(self.word(reg))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        self.write(1, reg, u32::from(value))
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), AccessError> {
        self.write(2, reg, u32::from(value))
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        self.write(4, reg, value)
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), AccessError> {
        for (i, v) in bytes.iter().copied().enumerate() {
            self.write8(reg + i as u16, v)?;
        }
        Ok(())
    }
    async fn delay_us(&self, micros: u64) {
        let pause = {
            let mut g = self.0.lock();
            g.events.push(Event::Delay(micros));
            g.pause
        };
        if pause {
            core::future::pending::<()>().await;
        }
    }
}
fn run<F: core::future::Future>(future: F) -> F::Output {
    narf_scheduler::block_on(future)
}

fn iq_port(shots: Vec<Shot>) -> Port {
    let port = Port::new(shots);
    port.set32(0xc80, 0x4000_0000);
    port.set32(0xc14, 0xabcd_0000);
    port.set32(0xca0, 0x00ab_cdef);
    port.set32(0xc94, 0x0123_4567);
    port.set32(0xc4c, 0xe000_0000);
    port.set32(0x040, 0x1122_3364);
    port.set32(0x820, 0x0100_0000);
    port.set8(0x522, 0x55);
    port.set8(0x550, 0x1f);
    port.set8(0x551, 0xff);
    for (i, reg) in iqk::ADDA_REGS.into_iter().enumerate() {
        port.set32(reg, 0xabc0_0000 + i as u32);
    }
    port
}

fn smoke_rtl8723ae_iqk_matrix_restore_and_recovery() -> TestResult {
    let port = iq_port(vec![
        Shot {
            x: 0x100,
            y: 0x10,
            rx: 0x100,
            ry: 0xc3,
            flags: 0,
        },
        Shot {
            x: 0x102,
            y: 0x12,
            rx: 0x102,
            ry: 0xc5,
            flags: 0,
        },
    ]);
    let mut owner = iqk::Owner::new();
    kt_assert!(run(owner.run(&port)).is_ok());
    kt_assert_eq!(owner.phase(), iqk::Phase::Complete);
    let Some(report) = owner.report().copied() else {
        return TestResult::Fail("AE IQK report");
    };
    kt_assert_eq!(report.candidate, 0);
    kt_assert_eq!(report.result[0], [0x100, 0x10, 0x100, 0xc3, 0, 0, 0, 0]);
    kt_assert_eq!(port.word(0xc80), 0x4010_0100);
    kt_assert_eq!(port.word(0xc14), 0xabcd_0d00);
    kt_assert_eq!(port.word(0xca0), 0x30ab_cdef);
    kt_assert_eq!(port.word(0xc4c), 0x4000_0000);
    kt_assert_eq!(port.word(0x040), 0x1122_3364);
    kt_assert_eq!(port.word(0x820), 0x0100_0000);
    kt_assert_eq!(port.0.lock().regs[0x522], 0x55);
    kt_assert_eq!(port.0.lock().regs[0x550], 0x1f);
    kt_assert_eq!(port.0.lock().regs[0x551], 0xff);
    for (i, reg) in iqk::ADDA_REGS.into_iter().enumerate() {
        kt_assert_eq!(port.word(reg), 0xabc0_0000 + i as u32);
    }
    let w = port.writes();
    kt_assert_eq!(w[0], (4, 0x85c, 0x0b1b_25a0));
    kt_assert_eq!(w[1], (4, 0xe6c, 0x0bdb_25a0));
    kt_assert_eq!(port.0.lock().next, 2);
    kt_assert!(w
        .iter()
        .all(|&(_, r, _)| !matches!(r, 0xe50 | 0xe54 | 0xe58 | 0xe5c | 0xe60)));
    let count = w.len();
    for reg in iqk::BB_REGS {
        port.set32(reg, 0);
    }
    kt_assert!(owner.recover(&port).is_ok());
    kt_assert_eq!(port.writes().len(), count + 10);
    for (reg, value) in iqk::BB_REGS.into_iter().zip(report.bb_backup) {
        kt_assert_eq!(port.word(reg), value);
    }
    let count = port.writes().len();
    kt_assert_eq!(run(owner.run(&port)), Err(Error::State));
    kt_assert_eq!(port.writes().len(), count);
    TestResult::Pass
}

fn smoke_rtl8723ae_iqk_candidates_and_terminal() -> TestResult {
    let port = iq_port(vec![
        Shot {
            x: 0x100,
            y: 0x10,
            rx: 0,
            ry: 0,
            flags: 0,
        },
        Shot {
            x: 0x102,
            y: 0x12,
            rx: 0x100,
            ry: 0,
            flags: 0,
        },
        Shot {
            x: 0x200,
            y: 0x32,
            rx: 0x200,
            ry: 0x32,
            flags: 0,
        },
    ]);
    let mut owner = iqk::Owner::new();
    kt_assert!(run(owner.run(&port)).is_ok());
    kt_assert_eq!(owner.report().unwrap().candidate, 3);
    kt_assert_eq!(
        &owner.report().unwrap().result[3][..4],
        &[0x102, 0x12, 0, 0]
    );
    kt_assert_eq!(port.word(0xc80), 0x4012_0102);
    kt_assert_eq!(port.word(0xc14), 0xabcd_0000);
    kt_assert_eq!(port.word(0xca0), 0x00ab_cdef);
    let mut shots = Vec::new();
    for y in [0, 0, 20, 20, 40, 40] {
        shots.push(Shot {
            x: 0x142,
            y,
            rx: 0,
            ry: 0,
            flags: 1 << 28,
        });
    }
    let port = iq_port(shots);
    let mut owner = iqk::Owner::new();
    kt_assert!(run(owner.run(&port)).is_ok());
    kt_assert_eq!(owner.report().unwrap().candidate, 0xff);
    kt_assert_eq!(owner.report().unwrap().e94, 0x100);
    kt_assert_eq!(port.0.lock().next, 6);
    kt_assert!(port.writes().iter().all(|&(_, r, _)| r != 0xc80));
    for pause in [false, true] {
        let port = iq_port(vec![Shot {
            x: 0x100,
            y: 0,
            rx: 0x100,
            ry: 0,
            flags: 0,
        }]);
        {
            let mut g = port.0.lock();
            g.pause = pause;
            if !pause {
                g.fail = Some(0xe48);
            }
        }
        let mut owner = iqk::Owner::new();
        if pause {
            use core::future::Future;
            let mut future = Box::pin(owner.run(&port));
            let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
            kt_assert!(future.as_mut().poll(&mut cx).is_pending());
        } else {
            kt_assert!(run(owner.run(&port)).is_err());
        }
        kt_assert_eq!(owner.phase(), iqk::Phase::Failed);
        let count = port.writes().len();
        kt_assert_eq!(run(owner.run(&port)), Err(Error::State));
        kt_assert_eq!(owner.recover(&port), Err(Error::State));
        kt_assert_eq!(port.writes().len(), count);
    }
    TestResult::Pass
}

fn power_adapter(regulatory: u8) -> Option<adapter::Adapter> {
    let v = tests::version(version::BT_FUNC)?;
    let mut map = tests::provisioned();
    map[0x10..0x13].copy_from_slice(&[0x10, 0x11, 0x12]);
    map[0x16..0x19].copy_from_slice(&[0x20, 0x21, 0x22]);
    map[0x1c..0x1f].copy_from_slice(&[0x2f, 0x91, 0x80]);
    map[0x1f..0x22].copy_from_slice(&[0x43, 0x65, 0x87]);
    map[0x22..0x25].copy_from_slice(&[0x21, 0x43, 0x65]);
    map[0x25..0x28].copy_from_slice(&[0x87, 0xa9, 0xcb]);
    map[0x29] = 0x5a;
    map[0x2a] = 0x1f;
    map[0x2b] = regulatory;
    map[0x66] = 0x21;
    adapter::Adapter::from_hardware(v, adapter::CR9346_AUTOLOAD_OK, 0, &map).ok()
}

fn smoke_rtl8723ae_factory_power_offsets_pg_and_bt() -> TestResult {
    use txpower::{DynamicPower as D, Efuse, Plan};
    let Some(a) = power_adapter(0) else {
        return TestResult::Fail("AE factory power adapter");
    };
    let efuse = Efuse::from_adapter(&a);
    kt_assert_eq!(
        [
            efuse.cck[0][0],
            efuse.cck[0][2],
            efuse.cck[0][3],
            efuse.cck[0][9]
        ],
        [0x10, 0x10, 0x11, 0x12]
    );
    kt_assert_eq!(efuse.cck[1], [0; 14]);
    kt_assert_eq!(efuse.ht40_1s[1], [0; 14]);
    kt_assert_eq!(efuse.ht40_2s[0][0], 0x1f);
    kt_assert_eq!(efuse.ht20_diff[0][0], 0xff);
    kt_assert_eq!(efuse.ht20_diff[1][3], 0xf9);
    kt_assert_eq!(efuse.legacy_ht_txpowerdiff, 5);
    kt_assert_eq!(efuse.tssi, [0x5a, 0]);
    kt_assert!(efuse.apk_thermalmeterignore);
    let pg = phy::PgStore::from_pg(&tables::PHY_REG_PG).unwrap();
    let p = Plan::for_channel(&efuse, &pg, 1, false, false, D::Normal).unwrap();
    kt_assert_eq!(p.cck_words(), [0x1010_1010, 0]);
    kt_assert_eq!(p.ofdm_words()[0], [0x2d2f_2f2f, 0x0e10_1010]);
    kt_assert_eq!(p.ofdm_words()[2], [0x292b_2c2d, 0x0c0e_0f10]);
    kt_assert_eq!(&p.indices()[0][..4], &[16, 16, 16, 0]);
    let scan = Plan::for_channel(&efuse, &pg, 1, false, true, D::Normal).unwrap();
    kt_assert_eq!(scan.cck_words(), [0x3f3f_3f3f; 2]);
    let Some(a) = power_adapter(1) else {
        return TestResult::Fail("AE regulatory 1 adapter");
    };
    let e = Efuse::from_adapter(&a);
    let p = Plan::for_channel(&e, &pg, 6, false, false, D::Normal).unwrap();
    kt_assert_eq!(p.ofdm_words()[0][0], 0x2a2a_2a2a);
    kt_assert_eq!(p.ofdm_words()[2][0], 0x2828_2828);
    let p = Plan::for_channel(&e, &pg, 6, true, false, D::Normal).unwrap();
    kt_assert_eq!(p.ofdm_words()[0][0], 0x2626_2626);
    kt_assert_eq!(p.ofdm_words()[2][0], 0x2121_2121);
    let Some(a) = power_adapter(2) else {
        return TestResult::Fail("AE regulatory 2 adapter");
    };
    let e = Efuse::from_adapter(&a);
    kt_assert_eq!(
        Plan::for_channel(&e, &pg, 1, false, false, D::Normal)
            .unwrap()
            .ofdm_words()[0][0],
        0x2323_2323
    );
    kt_assert_eq!(
        Plan::for_channel(&e, &pg, 1, false, false, D::Bt1)
            .unwrap()
            .ofdm_words()[0][0],
        0x1d1d_1d1d
    );
    kt_assert_eq!(
        Plan::for_channel(&e, &pg, 1, false, false, D::Bt2)
            .unwrap()
            .ofdm_words()[0][0],
        0x1717_1717
    );
    let Some(mut a) = power_adapter(3) else {
        return TestResult::Fail("AE regulatory 3 adapter");
    };
    let e = Efuse::from_adapter(&a);
    let p = Plan::for_channel(&e, &pg, 1, false, false, D::Normal).unwrap();
    kt_assert_eq!(p.ofdm_words()[0], [0x2a2a_2a2a, 0x0c0c_0c0c]);
    kt_assert_eq!(p.ofdm_words()[2], [0x2626_2626, 0x0a0a_0a0a]);
    // Provisioned 0xff is observed data, not the CE default of 0x22.
    a.hwinfo[0x10] = 0xff;
    kt_assert_eq!(Efuse::from_adapter(&a).cck[0][0], 0xff);
    let mut low = efuse;
    low.regulatory = 2;
    low.ht40_1s = [[4; 14]; 2];
    low.ht20_diff = [[0; 14]; 2];
    low.legacy_ht_diff = [[0; 14]; 2];
    let p = Plan::for_channel(&low, &pg, 1, false, false, D::Bt1).unwrap();
    // Source subtracts the whole u32 before 7-bit per-byte clamps;
    // cross-byte unsigned underflow is deliberately preserved here.
    kt_assert_eq!(p.ofdm_words()[0], [0x3f3f_3f3f; 2]);
    kt_assert_eq!(
        Plan::for_channel(&e, &pg, 0, false, false, D::Normal),
        Err(Error::State)
    );
    kt_assert_eq!(
        Plan::for_channel(&e, &pg, 15, false, false, D::Normal),
        Err(Error::State)
    );
    TestResult::Pass
}

fn smoke_rtl8723ae_power_registers_and_terminal() -> TestResult {
    let Some(a) = power_adapter(2) else {
        return TestResult::Fail("AE power adapter");
    };
    let pg = phy::PgStore::from_pg(&tables::PHY_REG_PG).unwrap();
    let plan = txpower::Plan::for_channel(
        &txpower::Efuse::from_adapter(&a),
        &pg,
        1,
        false,
        false,
        txpower::DynamicPower::Normal,
    )
    .unwrap();
    let port = Port::new(Vec::new());
    port.set32(0xe08, 0x1234_5678);
    port.set32(0x86c, 0xaabb_ccdd);
    port.set32(0x838, 0x0102_0304);
    let mut owner = txpower::Owner::new();
    kt_assert!(owner.program(&port, &plan).is_ok());
    kt_assert_eq!(owner.phase(), txpower::Phase::Complete);
    kt_assert_eq!(port.word(0xe08), 0x1234_1078);
    kt_assert_eq!(port.word(0x86c), 0x0010_1000);
    kt_assert_eq!(port.word(0x838), 4);
    let w = port.writes();
    kt_assert_eq!(w.len(), 22);
    kt_assert_eq!(
        &w[10..18],
        &[
            (4, 0xe14, 0x1f1f_1f1f),
            (1, 0xc90, 25),
            (1, 0xc91, 19),
            (1, 0xc92, 13),
            (4, 0x848, 0x0202_0202),
            (1, 0xc98, 0),
            (1, 0xc99, 0),
            (1, 0xc9a, 0),
        ]
    );
    kt_assert!(w
        .iter()
        .all(|&(_, r, _)| !matches!(r, 0x100 | 0x101 | 0x0308..=0x0344)));
    let count = w.len();
    kt_assert_eq!(owner.program(&port, &plan), Err(Error::State));
    kt_assert_eq!(port.writes().len(), count);
    for reg in [0xe14, 0xc91] {
        let port = Port::new(Vec::new());
        port.0.lock().fail = Some(reg);
        let mut owner = txpower::Owner::new();
        kt_assert!(owner.program(&port, &plan).is_err());
        kt_assert_eq!(owner.phase(), txpower::Phase::Failed);
        let count = port.writes().len();
        kt_assert_eq!(owner.program(&port, &plan), Err(Error::State));
        kt_assert_eq!(port.writes().len(), count);
        kt_assert!(port.writes().iter().all(|&(_, r, _)| r != 0x848));
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_iqk_matrix_restore_and_recovery
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_iqk_candidates_and_terminal
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_factory_power_offsets_pg_and_bt
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_power_registers_and_terminal
);
