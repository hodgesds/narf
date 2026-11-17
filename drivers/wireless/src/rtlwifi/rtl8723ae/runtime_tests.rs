// SPDX-License-Identifier: GPL-2.0-or-later
//! Native AE register trajectories from `rtl8723ae/{hw,phy,rf}.c`.
use super::*;
use crate::rtlwifi::{
    firmware_transport::{Error as AccessError, Io},
    prepare::Error,
};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    R8(u16),
    R32(u16),
    W(u8, u16, u32),
    Delay(u64),
    Bytes(u16, usize),
}
struct Model {
    regs: Vec<u8>,
    rf: [Vec<u32>; 2],
    read_addr: [usize; 2],
    events: Vec<Event>,
    llt_busy: bool,
    fail_write: Option<u16>,
    pause_delay: Option<u64>,
    mdio_round: u16,
    mdio_ready_after: u16,
    pages: Vec<Vec<u8>>,
    firmware_checksum: bool,
    firmware_start: bool,
}
#[derive(Clone)]
struct Port(Arc<IrqSafeSpinLock<Model>>);
impl Port {
    fn new() -> Self {
        let mut regs = vec![0; 0x4000];
        regs[0x000a] = 0x20; // EFUSE boot and autoload OK.
        regs[0x00f2] = 1; // normal RTL8723 series: BT_FUNC.
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            regs,
            rf: [vec![0; 256], vec![0; 256]],
            read_addr: [0; 2],
            events: Vec::new(),
            llt_busy: false,
            fail_write: None,
            pause_delay: None,
            mdio_round: 0,
            mdio_ready_after: 1,
            pages: Vec::new(),
            firmware_checksum: true,
            firmware_start: true,
        })))
    }
    fn set8(&self, at: u16, value: u8) {
        self.0.lock().regs[usize::from(at)] = value;
    }
    fn reg32(&self, at: u16) -> u32 {
        let g = self.0.lock();
        u32::from_le_bytes(
            g.regs[usize::from(at)..usize::from(at) + 4]
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
        if g.fail_write == Some(reg) {
            return Err(AccessError::Access);
        }
        let at = usize::from(reg);
        let old = u32::from_le_bytes(g.regs[at..at + 4].try_into().unwrap());
        g.events.push(Event::W(width, reg, value));
        g.regs[at..at + usize::from(width)]
            .copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
        if width == 2 && reg == 0x0358 && value == 0x5e && old & 0xffff == 0x3e {
            g.mdio_round += 1;
            if g.mdio_round >= g.mdio_ready_after {
                g.regs[0x0356..0x0358].copy_from_slice(&0xc290u16.to_le_bytes());
            }
        }
        if width == 4 {
            if matches!(reg, 0x0840 | 0x0844) {
                let path = usize::from(reg == 0x0844);
                g.rf[path][((value >> 20) & 0xff) as usize] = value & 0x000f_ffff;
            }
            if matches!(reg, 0x0824 | 0x082c) && old & (1 << 31) == 0 && value & (1 << 31) != 0 {
                g.read_addr[usize::from(reg == 0x082c)] = ((value >> 23) & 0xff) as usize;
            }
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl Io for Port {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        let mut g = self.0.lock();
        g.events.push(Event::R8(reg));
        Ok(g.regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        let mut g = self.0.lock();
        g.events.push(Event::R32(reg));
        if matches!(reg, 0x08a0 | 0x08b8) {
            return Ok(g.rf[0][g.read_addr[0]]);
        }
        if matches!(reg, 0x08a4 | 0x08bc) {
            return Ok(g.rf[1][g.read_addr[1]]);
        }
        let at = usize::from(reg);
        let value = u32::from_le_bytes(g.regs[at..at + 4].try_into().unwrap());
        if reg == 0x0080 {
            let mut value = value;
            if g.firmware_checksum && !g.pages.is_empty() && value & 1 == 0 {
                value |= 4;
            }
            if g.firmware_start && value & 2 != 0 {
                value |= 0x40;
            }
            return Ok(value);
        }
        Ok(if reg == 0x01e0 && !g.llt_busy {
            value & !(3 << 30)
        } else {
            value
        })
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
        let mut g = self.0.lock();
        g.events.push(Event::Bytes(reg, bytes.len()));
        let page = usize::from(g.regs[0x82] & 7);
        while g.pages.len() <= page {
            g.pages.push(Vec::new());
        }
        let at = usize::from(reg) - 0x1000;
        if g.pages[page].len() < at + bytes.len() {
            g.pages[page].resize(at + bytes.len(), 0);
        }
        g.pages[page][at..at + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    async fn delay_us(&self, micros: u64) {
        let park = {
            let mut g = self.0.lock();
            g.events.push(Event::Delay(micros));
            g.pause_delay == Some(micros)
        };
        if park {
            core::future::pending::<()>().await;
        }
    }
}

fn run<F: core::future::Future>(future: F) -> F::Output {
    narf_scheduler::block_on(future)
}

fn smoke_rtl8723ae_llt_profile_and_refusal() -> TestResult {
    let port = Port::new();
    kt_assert!(llt::init(&port).is_ok());
    let w = port.writes();
    kt_assert_eq!(
        &w[..10],
        &[
            (2, 0x0214, 0),
            (4, 0x0200, 0x80ac_1c29),
            (1, 0x0214, 3),
            (4, 0x0114, 0x27ff_00f6),
            (1, 0x0209, 0xf6),
            (1, 0x0424, 0xf6),
            (1, 0x0425, 0xf6),
            (1, 0x045d, 0xf6),
            (1, 0x0104, 0x11),
            (1, 0x060f, 4),
        ]
    );
    kt_assert_eq!(w.len(), 267);
    kt_assert_eq!(w[10], (4, 0x01e0, 0x4000_0001));
    kt_assert_eq!(w[255], (4, 0x01e0, 0x4000_f5ff));
    kt_assert_eq!(w[256], (4, 0x01e0, 0x4000_f6f7));
    kt_assert_eq!(w[265], (4, 0x01e0, 0x4000_fff6));
    kt_assert_eq!(w[266], (1, 0x0203, 0x80));
    kt_assert!(w.iter().all(|&(_, r, _)| !matches!(r, 0x0100 | 0x0101)));
    let stuck = Port::new();
    stuck.0.lock().llt_busy = true;
    kt_assert_eq!(llt::init(&stuck), Err(AccessError::Deadline));
    kt_assert_eq!(
        stuck
            .0
            .lock()
            .events
            .iter()
            .filter(|e| **e == Event::R32(0x01e0))
            .count(),
        22
    );
    kt_assert_eq!(stuck.writes().len(), 11);
    TestResult::Pass
}

fn smoke_rtl8723ae_bb_rf_source_programs() -> TestResult {
    let port = Port::new();
    port.set8(0x0028, 0x80);
    port.set8(0x0002, 0x40);
    port.set8(0x0025, 0xff);
    port.set8(0x0026, 0xff);
    let Ok(report) = run(phy::bb_config(&port)) else {
        return TestResult::Fail("AE BB configure");
    };
    let events = port.0.lock().events.clone();
    kt_assert_eq!(
        &events[..15],
        &[
            Event::R8(0x28),
            Event::Delay(2),
            Event::W(1, 0x28, 0x82),
            Event::Delay(2),
            Event::W(1, 0x29, 0xff),
            Event::Delay(2),
            Event::R8(2),
            Event::W(1, 2, 0x43),
            Event::R8(0x25),
            Event::W(1, 0x25, 0xbf),
            Event::R8(0x26),
            Event::W(1, 0x26, 0xef),
            Event::W(1, 0x1f, 7),
            Event::W(4, 0x800, 0x8004_0000),
            Event::Delay(1),
        ]
    );
    kt_assert!(!report.cck_high_power);
    kt_assert_eq!(report.pg.pwrgroup_cnt, 7);
    kt_assert_eq!(report.pg.origoffset[0][0], 0x0a0c_0c0c);
    kt_assert_eq!(report.pg.origoffset[0][13], 0x0204_0608);
    let agc: Vec<_> = port
        .writes()
        .into_iter()
        .filter(|&(_, r, _)| r == 0x0c78)
        .collect();
    kt_assert_eq!(agc.len(), 161); // PHY initial value, then 160 AGC rows.
    kt_assert_eq!(agc[0], (4, 0x0c78, 0x0000_001f));
    kt_assert_eq!(agc[1], (4, 0x0c78, 0x7b00_0001));
    // PG rows are software state, never a second TXAGC programming pass.
    kt_assert_eq!(
        port.writes()
            .iter()
            .filter(|&&(_, r, _)| r == 0x0e00)
            .count(),
        1
    );
    let port = Port::new();
    port.0.lock().regs[0x0870] = 0x10;
    kt_assert!(run(phy::rf_config(&port)).is_ok());
    let rf: Vec<_> = port
        .writes()
        .into_iter()
        .filter(|&(_, r, _)| r == 0x0840)
        .collect();
    kt_assert_eq!(rf.len(), 137);
    kt_assert_eq!(
        &rf[..3],
        &[
            (4, 0x0840, 0x0003_0159),
            (4, 0x0840, 0x0013_1284),
            (4, 0x0840, 0x0029_8000)
        ]
    );
    kt_assert_eq!(rf.last(), Some(&(4, 0x0840, 0x0003_0159)));
    kt_assert_eq!(
        port.0
            .lock()
            .events
            .iter()
            .filter(|e| **e == Event::Delay(50_000))
            .count(),
        4
    );
    kt_assert_eq!(port.reg32(0x0870) & 0x10, 0x10);
    TestResult::Pass
}

fn smoke_rtl8723ae_channel_bandwidth_and_umc() -> TestResult {
    let Some(v) = tests::version(version::BT_FUNC | version::VENDOR_ID | (1 << 12)) else {
        return TestResult::Fail("AE UMC version");
    };
    let port = Port::new();
    kt_assert!(run(phy::umc_fixups(&port, v)).is_ok());
    let rf: Vec<_> = port
        .writes()
        .into_iter()
        .filter(|&(_, r, _)| r == 0x0840)
        .collect();
    kt_assert_eq!(
        rf.as_slice(),
        &[
            (4, 0x0840, 0x00c8_94ae),
            (4, 0x0840, 0x00a1_af31),
            (4, 0x0840, 0x0158_f425),
            (4, 0x0840, 0x0264_f200),
            (4, 0x0840, 0x01e4_4053),
            (4, 0x0840, 0x01f8_0201),
        ]
    );
    kt_assert_eq!(
        port.0
            .lock()
            .events
            .iter()
            .filter(|e| **e == Event::Delay(120))
            .count(),
        6
    );
    let mut chnlval = 0xf401;
    kt_assert!(run(phy::set_bw_mode(&port, &mut chnlval, true, 1)).is_ok());
    kt_assert_eq!(chnlval, 0xf001);
    kt_assert_eq!(port.reg32(0x0818) & (3 << 26), 2 << 26);
    kt_assert_eq!(port.0.lock().regs[0x0442], 0x20);
    kt_assert!(run(phy::set_bw_mode(&port, &mut chnlval, false, 0)).is_ok());
    kt_assert_eq!(chnlval, 0xf401);
    kt_assert!(run(phy::sw_chnl_rf(&port, v, &mut chnlval, 6, false)).is_ok());
    kt_assert_eq!(chnlval, 0xf406);
    kt_assert_eq!(port.0.lock().rf[0][0x1a], 0x255);
    kt_assert!(port.0.lock().events.contains(&Event::Delay(10_000)));
    port.0.lock().rf[0][0x1a] = 0xabcde;
    let reads = port
        .0
        .lock()
        .events
        .iter()
        .filter(|e| **e == Event::Delay(120))
        .count();
    kt_assert!(run(phy::sw_chnl_rf(&port, v, &mut chnlval, 7, false)).is_ok());
    kt_assert_eq!(chnlval, 0xf407);
    kt_assert_eq!(port.0.lock().rf[0][0x1a], 0xabcde);
    // Source explicitly queries RF_RX_G1, then its MASKDWORD setter
    // queries it again before writing the saved value back.
    kt_assert_eq!(
        port.0
            .lock()
            .events
            .iter()
            .filter(|e| **e == Event::Delay(120))
            .count(),
        reads + 2
    );
    kt_assert!(run(phy::set_bw_mode(&port, &mut chnlval, true, 2)).is_ok());
    kt_assert_eq!(chnlval, 0xf007);
    kt_assert_eq!(port.reg32(0x0818) & (3 << 26), 1 << 26);
    kt_assert_eq!(port.reg32(0x0a00) & 0x10, 0x10);
    kt_assert_eq!(port.reg32(0x0d00) & 0xc00, 0x800);
    kt_assert_eq!(port.0.lock().regs[0x0442], 0x40);
    let count = port.0.lock().events.len();
    kt_assert_eq!(
        run(phy::sw_chnl_rf(&port, v, &mut chnlval, 15, false)),
        Err(Error::State)
    );
    kt_assert_eq!(
        run(phy::set_bw_mode(&port, &mut chnlval, true, 0)),
        Err(Error::State)
    );
    kt_assert_eq!(port.0.lock().events.len(), count);
    TestResult::Pass
}

async fn prepare_cold(
    owner: &mut init::Owner,
    port: &Port,
    adapter: &adapter::Adapter,
    retry: u16,
) -> Result<(), Error> {
    owner.prepare_mac(port, retry, false).await?;
    owner
        .download_and_configure(port, adapter.version, &[0; 16])
        .await
}

fn smoke_rtl8723ae_parked_cold_owner_and_failure() -> TestResult {
    let Some(v) = tests::version(version::BT_FUNC) else {
        return TestResult::Fail("AE version");
    };
    let Ok(adapter) =
        adapter::Adapter::from_hardware(v, adapter::CR9346_AUTOLOAD_OK, 0, &tests::provisioned())
    else {
        return TestResult::Fail("AE adapter");
    };
    let port = Port::new();
    let mut owner = init::Owner::new();
    port.0.lock().mdio_ready_after = 3;
    let Ok(retries) = run(power::post_flow_with_retries(&port)) else {
        return TestResult::Fail("AE ePHY retry report");
    };
    kt_assert_eq!(retries, 3);
    kt_assert!(run(prepare_cold(&mut owner, &port, &adapter, retries)).is_ok());
    kt_assert_eq!(owner.phase(), init::Phase::TablesReady);
    kt_assert!(owner.tables().is_some());
    kt_assert_eq!(port.reg32(0x0300) >> 24, 0x74);
    kt_assert_eq!(port.reg32(0x0394), 1);
    kt_assert_eq!(port.reg32(0x0458), 0xb972_a841);
    kt_assert!(port
        .writes()
        .iter()
        .all(|&(_, r, _)| !matches!(r, 0x0100 | 0x0101 | 0x0308..=0x0344)));
    let count = port.0.lock().events.len();
    kt_assert_eq!(
        run(prepare_cold(&mut owner, &port, &adapter, 1)),
        Err(Error::State)
    );
    kt_assert_eq!(port.0.lock().events.len(), count);
    for reg in [0x01e0, 0x0840, 0x0680] {
        let port = Port::new();
        port.0.lock().fail_write = Some(reg);
        let mut owner = init::Owner::new();
        kt_assert!(run(prepare_cold(&mut owner, &port, &adapter, 1)).is_err());
        kt_assert_eq!(owner.phase(), init::Phase::Failed);
        let count = port.0.lock().events.len();
        kt_assert_eq!(
            run(prepare_cold(&mut owner, &port, &adapter, 1)),
            Err(Error::State)
        );
        kt_assert_eq!(port.0.lock().events.len(), count);
        kt_assert!(owner.tables().is_none());
    }
    let port = Port::new();
    port.0.lock().pause_delay = Some(2);
    let mut owner = init::Owner::new();
    {
        use core::future::Future;
        let mut future = alloc::boxed::Box::pin(prepare_cold(&mut owner, &port, &adapter, 1));
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        kt_assert!(future.as_mut().poll(&mut cx).is_pending());
    }
    kt_assert_eq!(owner.phase(), init::Phase::Failed);
    let count = port.0.lock().events.len();
    kt_assert_eq!(
        run(prepare_cold(&mut owner, &port, &adapter, 1)),
        Err(Error::State)
    );
    kt_assert_eq!(port.0.lock().events.len(), count);
    // APSD uses the carried ePHY count, reads at least once, and has no
    // timeout error in the source. Every retry yields cooperatively.
    let port = Port::new();
    port.set8(0x0600, 0xc0);
    kt_assert!(run(mac::init_mac(&port, 99)).is_ok());
    kt_assert_eq!(
        port.0
            .lock()
            .events
            .iter()
            .filter(|e| **e == Event::R8(0x0600))
            .count(),
        102
    );
    for retry in [0, 100, u16::MAX] {
        let port = Port::new();
        kt_assert_eq!(run(mac::init_mac(&port, retry)), Err(Error::State));
        kt_assert!(port.0.lock().events.is_empty());
    }
    TestResult::Pass
}

fn smoke_rtl8723ae_lck_source_modes() -> TestResult {
    for continuous in [false, true] {
        let port = Port::new();
        port.set8(0x0d03, if continuous { 0x75 } else { 5 });
        port.0.lock().rf[0][0] = 0x30159;
        port.0.lock().rf[0][0x18] = 0x7406;
        kt_assert!(run(phy::lc_calibrate(&port)).is_ok());
        kt_assert!(port.0.lock().events.contains(&Event::Delay(100_000)));
        kt_assert_eq!(port.0.lock().rf[0][0x18], 0xf406);
        if continuous {
            kt_assert_eq!(port.0.lock().regs[0x0d03], 0x75);
            kt_assert_eq!(port.0.lock().rf[0][0], 0x30159);
        } else {
            kt_assert_eq!(port.0.lock().regs[0x0522], 0);
            let writes = port.writes();
            kt_assert_eq!(writes.first(), Some(&(1, 0x0522, 0xff)));
            kt_assert_eq!(writes.last(), Some(&(1, 0x0522, 0)));
        }
    }
    TestResult::Pass
}

fn firmware_image() -> Vec<u8> {
    let mut bytes = vec![0x5a; 32 + 128];
    bytes[..32].fill(0);
    bytes[0..2].copy_from_slice(&0x2302u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&21u16.to_le_bytes());
    bytes[12..14].copy_from_slice(&128u16.to_le_bytes());
    bytes
}

fn smoke_rtl8723ae_native_cold_firmware_order_and_refusals() -> TestResult {
    use crate::rtlwifi::firmware_transport::{Owner as FirmwareOwner, Stage};
    let port = Port::new();
    let owner = FirmwareOwner::new(port.clone(), DEV_ID);
    let image = firmware_image();
    let Ok(info) = run(owner.initialize(&image)) else {
        return TestResult::Fail("AE native cold firmware");
    };
    kt_assert_eq!(info.version, 21);
    kt_assert_eq!(owner.status().stage, Stage::Ready);
    kt_assert_eq!(
        run(owner.rtl8723ae_cold_phase()),
        Some(init::Phase::TablesReady)
    );
    kt_assert_eq!(port.0.lock().pages[0].as_slice(), &image[32..]);
    let events = port.0.lock().events.clone();
    let pre = events
        .iter()
        .position(|e| *e == Event::W(1, 0x0303, 0x74))
        .unwrap();
    let first_page = events
        .iter()
        .position(|e| matches!(e, Event::Bytes(..)))
        .unwrap();
    let last_page = events
        .iter()
        .rposition(|e| matches!(e, Event::Bytes(..)))
        .unwrap();
    let post = events
        .iter()
        .position(|e| *e == Event::W(1, 0x04ca, 0x0a))
        .unwrap();
    let bb = events
        .iter()
        .position(|e| *e == Event::W(1, 0x0028, 2))
        .unwrap();
    kt_assert!(pre < first_page && last_page < post && post < bb);
    kt_assert!(port.writes().iter().all(|&(w, r, v)| {
        !(matches!(r, 0x0100 | 0x0101) && (w != 1 || v & 0xcf != 0))
            && !matches!(r,0x0308..=0x0344|0x0610..=0x0615)
    }));
    // Existing MAC initialization skips LLT, even though the CR gates
    // are parked before firmware download in this retained path.
    let warm = Port::new();
    warm.set8(0x0100, 0xff);
    let warm_owner = FirmwareOwner::new(warm.clone(), DEV_ID);
    kt_assert!(run(warm_owner.initialize(&image)).is_ok());
    kt_assert!(warm.writes().iter().all(|&(_, r, _)| r != 0x01e0));
    kt_assert_eq!(warm.0.lock().regs[0x0100], 0x30);
    for mode in [0, 0x30] {
        let port = Port::new();
        port.set8(0x000a, mode);
        let owner = FirmwareOwner::new(port.clone(), DEV_ID);
        kt_assert_eq!(run(owner.initialize(&image)), Err(AccessError::Unsupported));
        kt_assert!(port.writes().is_empty());
    }
    for cfg in [0, version::BT_FUNC | version::TRP_VAUX_EN] {
        let port = Port::new();
        port.0.lock().regs[0x00f0..0x00f4].copy_from_slice(&cfg.to_le_bytes());
        let owner = FirmwareOwner::new(port.clone(), DEV_ID);
        kt_assert_eq!(run(owner.initialize(&image)), Err(AccessError::Unsupported));
        kt_assert!(port.writes().is_empty());
    }
    // A live-looking SYS_CFG cannot turn removed dependent registers
    // into a fabricated ROM version, polarity or Bluetooth identity.
    for register in [version::REG_GPIO_OUTSTS, version::REG_MULTI_FUNC_CTRL] {
        let port = Port::new();
        let at = usize::from(register);
        port.0.lock().regs[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let owner = FirmwareOwner::new(port.clone(), DEV_ID);
        kt_assert_eq!(run(owner.initialize(&image)), Err(AccessError::Gone));
        kt_assert_eq!(owner.status().stage, Stage::Failed);
        kt_assert!(port.writes().is_empty());
        kt_assert!(port.0.lock().pages.is_empty());
        kt_assert_eq!(run(owner.rtl8723ae_cold_phase()), None);
    }
    let port = Port::new();
    port.0.lock().fail_write = Some(0x04ca);
    let owner = FirmwareOwner::new(port.clone(), DEV_ID);
    kt_assert_eq!(run(owner.initialize(&image)), Err(AccessError::Access));
    kt_assert_eq!(owner.status().stage, Stage::Failed);
    kt_assert_eq!(run(owner.rtl8723ae_cold_phase()), Some(init::Phase::Failed));
    kt_assert!(!port.0.lock().pages.is_empty());
    let count = port.0.lock().events.len();
    kt_assert_eq!(
        run(owner.initialize(&image)),
        Err(AccessError::AlreadyStarted)
    );
    kt_assert_eq!(port.0.lock().events.len(), count);
    // Firmware cancellation retains the same boxed cold owner, and the
    // Mutex guard releases without reopening the consumed startup attempt.
    let port = Port::new();
    {
        let mut g = port.0.lock();
        g.firmware_start = false;
        g.pause_delay = Some(5_000);
    }
    let owner = FirmwareOwner::new(port.clone(), DEV_ID);
    {
        use core::future::Future;
        let mut future = alloc::boxed::Box::pin(owner.initialize(&image));
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        kt_assert!(future.as_mut().poll(&mut cx).is_pending());
    }
    kt_assert_eq!(owner.status().stage, Stage::Failed);
    kt_assert_eq!(owner.status().error, Some(AccessError::Cancelled));
    kt_assert_eq!(run(owner.rtl8723ae_cold_phase()), Some(init::Phase::Failed));
    let count = port.0.lock().events.len();
    kt_assert_eq!(
        run(owner.initialize(&image)),
        Err(AccessError::AlreadyStarted)
    );
    kt_assert_eq!(port.0.lock().events.len(), count);
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_llt_profile_and_refusal
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_bb_rf_source_programs
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_channel_bandwidth_and_umc
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_parked_cold_owner_and_failure
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_lck_source_modes
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_native_cold_firmware_order_and_refusals
);
