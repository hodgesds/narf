use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use src::Poison as P;

const INDEX: u64 = 0x100;
const DATA: u64 = 0x104;
const DOORBELL: u64 = 0x3f8;
const UMC: u32 = 0x14000;
/// BAR registers plus the RSMU-indirect space behind INDEX/DATA.
#[derive(Default)]
struct Fake {
    regs: BTreeMap<u64, u32>,
    pcie: BTreeMap<u32, u32>,
    index: u32,
    log: Vec<(bool, u32, u32)>,
    gone: bool,
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        match at {
            INDEX => self.index,
            DATA => {
                let v = *self.pcie.get(&self.index).unwrap_or(&0);
                self.log.push((false, self.index, v));
                v
            }
            _ => *self.regs.get(&at).unwrap_or(&0),
        }
    }
    fn write(&mut self, at: u64, v: u32) {
        match at {
            INDEX => self.index = v,
            DATA => {
                self.log.push((true, self.index, v));
                self.pcie.insert(self.index, v);
            }
            // Model RAS_ATHUB_ERR_EVENT_INTERRUPT_CLEAR: write 1 clears status.
            DOORBELL if v & ATHUB_CLEAR != 0 => {
                self.regs.insert(at, v & !(ATHUB_CLEAR | ATHUB_STATUS));
            }
            _ => {
                self.regs.insert(at, v);
            }
        }
    }
}
const LAYOUT: Layout = Layout {
    umc: UMC,
    umcs: 2,
    index: INDEX,
    data: DATA,
    doorbell: DOORBELL,
};
fn cnt(umc: u32, ch: u32) -> u32 {
    (UMC + 0x329 + 0x400 * ch + 0x40000 * umc) * 4
}
fn sel(umc: u32, ch: u32) -> u32 {
    (UMC + 0x328 + 0x400 * ch + 0x40000 * umc) * 4
}
fn engine(caps: Caps) -> Engine<Fake> {
    let policy = Policy::new(caps, true, true);
    let layout = (policy.umc() || policy.fatal_polling()).then_some(LAYOUT);
    Engine::new(Fake::default(), Cap::bootstrap(), layout, policy)
}
fn event(client: u8, source: u8) -> ih::Event {
    ih::Event {
        ih_ring: 0,
        vector: ih::Vector::decode([
            u32::from(client) | (u32::from(source) << 8),
            0,
            0,
            7,
            0,
            0,
            0,
            0,
        ]),
    }
}
const MEM: Caps = Caps {
    mem_ecc: true,
    default_mem_ecc: false,
    sram_ecc: false,
};
const SRAM: Caps = Caps {
    mem_ecc: false,
    default_mem_ecc: false,
    sram_ecc: true,
};
const ALL_POISON: [P; 13] = [
    P::Utcl2,
    P::RlcFed,
    P::CpEcc,
    P::CpFue,
    P::SdmaEcc { instance: 1 },
    P::SdmaSramEcc { instance: 0 },
    P::Shader { fatal: true },
    P::Shader { fatal: false },
    P::Media {
        instance: 0,
        source: 160,
    },
    P::Media {
        instance: 0,
        source: 161,
    },
    P::Media {
        instance: 1,
        source: 162,
    },
    P::Umc,
    P::Athub,
];

fn navi48_ras_vbios_caps_follow_atomfirmware_revisions() -> TestResult {
    let umc = |frev: u8, crev: u8, config: u8, config1: u32| {
        let mut t = vec![0u8; 88];
        (t[2], t[3], t[27]) = (frev, crev, config);
        t[52..56].copy_from_slice(&config1.to_le_bytes());
        t
    };
    for (frev, crev, config, config1, expected) in [
        // v4.0 (discrete GC12): only umc_config1 ENABLE_ECC_CAPABLE counts.
        (4, 0, 0, 0x10000, (true, false)),
        (4, 0, 2, 0, (false, true)),
        (4, 0, 2, 0x10000, (true, true)),
        (4, 0, 0, 0xfffe_ffff, (false, false)),
        // v3.3: either bit; v3.1/v3.2 only the default-enable bit.
        (3, 3, 0, 0x10000, (true, false)),
        (3, 3, 2, 0, (true, true)),
        (3, 1, 2, 0x10000, (true, false)),
        (3, 2, 0, 0x10000, (false, false)),
        // Unsupported revisions report nothing.
        (3, 4, 2, 0x10000, (false, false)),
        (4, 1, 2, 0x10000, (false, false)),
        (2, 0, 2, 0x10000, (false, false)),
    ] {
        assert_eq!(umc_info_ecc(&umc(frev, crev, config, config1)), expected);
    }
    // A truncated v4.0 table has no umc_config1.
    assert_eq!(umc_info_ecc(&umc(4, 0, 0, 0x10000)[..52]), (false, false));
    assert_eq!(umc_info_ecc(&[]), (false, false));
    let fw = |frev: u8, crev: u8, cap: u32| {
        let mut t = vec![0u8; 72];
        (t[2], t[3]) = (frev, crev);
        t[0x10..0x14].copy_from_slice(&cap.to_le_bytes());
        t
    };
    assert_eq!(firmware_capability(&fw(3, 1, 0x201)), 0x201);
    assert_eq!(firmware_capability(&fw(4, 0, 0x200)), 0x200);
    assert_eq!(firmware_capability(&fw(3, 0, 0x200)), 0);
    assert_eq!(firmware_capability(&fw(2, 9, 0x200)), 0);
    assert_eq!(firmware_capability(&fw(3, 1, 0)[..0x12]), 0);
    let caps = Caps::from_tables(Some(&fw(3, 4, 0x200)), Some(&umc(4, 0, 2, 0)));
    assert_eq!(
        caps,
        Caps {
            mem_ecc: false,
            default_mem_ecc: true,
            sram_ecc: true
        }
    );
    assert_eq!(Caps::from_tables(None, None), Caps::default());
    assert_eq!(Caps::from_vbios(&[0; 64]), Caps::default());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ras",
    navi48_ras_vbios_caps_follow_atomfirmware_revisions
);

fn navi48_ras_block_mask_matches_linux_check_supported() -> TestResult {
    use block::*;
    assert_eq!(BLOCK_MASK, 0xfffff);
    assert_eq!(hw_enabled(Caps::default()), 0);
    assert_eq!(hw_enabled(MEM), 1 << UMC | 1 << DF);
    let sram = BLOCK_MASK & !(1 << UMC | 1 << DF | 1 << VCN | 1 << JPEG | 1 << XGMI_WAFL);
    assert_eq!(hw_enabled(SRAM), sram);
    // Literal vectors shared with tests/navi48_ras.c.
    assert_eq!((hw_enabled(MEM), sram), (0x101, 0xe7e7e));
    assert!(sram & (1 << GFX | 1 << SDMA | 1 << MMHUB | 1 << PCIE_BIF | 1 << MMSCH) != 0);
    let both = Caps {
        sram_ecc: true,
        ..MEM
    };
    assert_eq!(hw_enabled(both), sram | 1 << UMC | 1 << DF);
    // A consumer board: no context, nothing enabled.
    let off = Policy::new(Caps::default(), true, true);
    assert!(!off.umc() && !off.fatal_polling() && !off.supported(GFX));
    // SRAM ECC alone enables blocks that have no RAS object on Navi48.
    let sram = Policy::new(SRAM, true, true);
    assert!(sram.supported(GFX) && !sram.umc() && !sram.fatal_polling());
    // UMC RAS needs umc_v8_14_ras; the fatal poll needs nbif_v6_3_1_ras.
    let mem = Policy::new(MEM, true, true);
    assert!(mem.umc() && mem.fatal_polling() && !mem.supported(LAST));
    assert!(!Policy::new(MEM, false, true).umc());
    assert!(!Policy::new(MEM, true, false).fatal_polling());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ras",
    navi48_ras_block_mask_matches_linux_check_supported
);

fn navi48_ras_dispositions_leave_unregistered_poison_unhandled() -> TestResult {
    for caps in [Caps::default(), SRAM, MEM] {
        let policy = Policy::new(caps, true, true);
        for p in ALL_POISON {
            let expected = match p {
                P::Umc if policy.umc() => Disposition::UmcQuery,
                P::Umc => Disposition::Ignored(Ignored::Disabled),
                P::Athub => Disposition::Ignored(Ignored::Polled),
                P::Media { source: 160, .. } => Disposition::Ignored(Ignored::NoRasBlock),
                _ => Disposition::Ignored(Ignored::Unregistered),
            };
            assert_eq!(disposition(policy, p), expected);
        }
    }
    // Disabled RAS: every vector is evidence only, with no register access.
    let mut e = engine(Caps::default());
    assert_eq!(e.layout, None);
    e.arm().unwrap();
    for (i, p) in ALL_POISON.into_iter().enumerate() {
        let iv = event(0x0a, i as u8);
        assert_eq!(e.handle(iv, p), Ok(None));
        assert_eq!(e.status.first_ignored.unwrap().0, event(0x0a, 0));
        assert_eq!(e.status.last_ignored.unwrap().0, iv);
    }
    assert_eq!(e.poll(), Ok(None));
    assert_eq!(e.status.ignored, ALL_POISON.len() as u64);
    assert!(!e.status.fed && e.status.fatal.is_none() && e.status.error.is_none());
    assert!(e.io.log.is_empty() && e.io.regs.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ras",
    navi48_ras_dispositions_leave_unregistered_poison_unhandled
);

fn navi48_ras_umc_query_preserves_counters_before_clearing() -> TestResult {
    let mut e = engine(MEM);
    // Boot counts and an inherited GeccErrCntSel.
    e.io.pcie.insert(cnt(1, 0), 0x0001_0002);
    e.io.pcie.insert(sel(0, 1), 0x3005);
    e.arm().unwrap();
    let boot = e.status.boot.unwrap();
    assert_eq!(
        (boot.event, boot.channels, boot.ce, boot.ue),
        (None, 4, 2, 1)
    );
    assert_eq!(boot.raw[2], 0x0001_0002);
    // Boot counts are logged, not reset: Linux only reads them at late init.
    assert_eq!(e.status.fatal, None);
    for umc in 0..2 {
        for ch in 0..2 {
            assert_eq!(e.io.pcie[&cnt(umc, ch)], 0);
            assert_eq!(e.io.pcie[&sel(umc, ch)] & 0x3000, 0x1000);
        }
    }
    assert_eq!(e.io.pcie[&sel(0, 1)], 0x1005);
    assert_eq!(e.io.regs[&DOORBELL] & ATHUB_DISABLE, 0);
    assert_eq!(e.arm(), Err(Error::Busy));
    // A correctable-only interrupt: FED, counters, no reset.
    e.io.pcie.insert(cnt(0, 1), 3);
    e.io.log.clear();
    let iv = event(0x17, 0);
    assert_eq!(e.handle(iv, P::Umc), Ok(None));
    assert!(e.status.fed);
    assert_eq!(
        (e.status.ce, e.status.ue, e.status.umc_interrupts),
        (3, 0, 1)
    );
    // Every channel is read before any is cleared.
    let first_write = e.io.log.iter().position(|l| l.0).unwrap();
    assert_eq!(first_write, 4);
    // The clears are the only writes (each is posted with a data readback).
    let writes: Vec<_> = e.io.log.iter().filter(|l| l.0).collect();
    assert_eq!(writes.len(), 4);
    assert!(writes.iter().all(|l| l.2 == 0));
    // An uncorrectable count requests the reset once.
    e.io.pcie.insert(cnt(1, 1), 0x0002_0000);
    assert_eq!(e.handle(iv, P::Umc), Ok(Some(Fatal::Umc { ce: 0, ue: 2 })));
    let last = e.status.last_umc.unwrap();
    assert_eq!((last.event, last.raw[3]), (Some(iv), 0x0002_0000));
    e.io.pcie.insert(cnt(0, 0), 0x0001_0000);
    assert_eq!(e.handle(iv, P::Umc), Ok(None));
    assert_eq!(e.status.fatal, Some(Fatal::Umc { ce: 0, ue: 2 }));
    assert_eq!(e.status.ue, 3);
    // The other poison sources stay unhandled even with UMC RAS on.
    assert_eq!(
        e.handle(
            event(0x10, 160),
            P::Media {
                instance: 0,
                source: 160
            }
        ),
        Ok(None)
    );
    assert_eq!(e.status.ignored, 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ras",
    navi48_ras_umc_query_preserves_counters_before_clearing
);

fn navi48_ras_athub_poll_clears_status_and_requests_reset() -> TestResult {
    let mut e = engine(MEM);
    e.io.regs.insert(DOORBELL, ATHUB_DISABLE | 0x10);
    // Nothing is polled before arming.
    assert_eq!(e.poll(), Ok(None));
    e.arm().unwrap();
    assert_eq!(e.io.regs[&DOORBELL], 0x10);
    assert_eq!(e.poll(), Ok(None));
    assert_eq!(e.io.regs[&DOORBELL], 0x10);
    // The ATHUB IV itself is a dummy.
    assert_eq!(e.handle(event(0x03, 0x61), P::Athub), Ok(None));
    assert_eq!(e.status.fatal, None);
    e.io.regs.insert(DOORBELL, 0x10 | ATHUB_STATUS);
    assert_eq!(
        e.poll(),
        Ok(Some(Fatal::Athub {
            raw: 0x10 | ATHUB_STATUS
        }))
    );
    assert_eq!(e.io.regs[&DOORBELL], 0x10);
    assert!(e.status.fed);
    // amdgpu_ras_in_intr: a second event does not reset again.
    e.io.regs.insert(DOORBELL, ATHUB_STATUS);
    assert_eq!(e.poll(), Ok(None));
    assert_eq!(e.io.regs[&DOORBELL], 0);
    // No DF RAS: no polling at all.
    let mut e = engine(SRAM);
    e.arm().unwrap();
    assert_eq!(e.poll(), Ok(None));
    assert!(e.io.regs.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ras",
    navi48_ras_athub_poll_clears_status_and_requests_reset
);

fn navi48_ras_device_loss_and_revocation_fail_closed() -> TestResult {
    let mut e = engine(MEM);
    e.arm().unwrap();
    e.io.gone = true;
    assert_eq!(e.handle(event(0x17, 0), P::Umc), Err(Error::DeviceGone));
    assert_eq!(e.poll(), Err(Error::DeviceGone));
    assert_eq!(e.status.error, Some(Error::DeviceGone));
    assert!(e.status.fed && e.status.fatal.is_none());
    // A UMC vector before arming is refused, not silently dropped.
    let mut e = engine(MEM);
    assert_eq!(e.handle(event(0x17, 0), P::Umc), Err(Error::Busy));
    let cap = Cap::bootstrap();
    let mut e = Engine::new(
        Fake::default(),
        cap,
        Some(LAYOUT),
        Policy::new(MEM, true, true),
    );
    cap.revoke();
    assert_eq!(e.arm(), Err(Error::Revoked));
    assert!(e.io.log.is_empty() && !e.status.armed);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ras",
    navi48_ras_device_loss_and_revocation_fail_closed
);

fn navi48_ras_layout_uses_umc_discovery_and_nbif_631() -> TestResult {
    let mut words = vec![0; 0x80000 / 4];
    let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(&mut words);
    let policy = Policy::new(MEM, true, true);
    // NBIF 7.7.0 has no nbif_v6_3_1_ras.
    assert_eq!(Layout::resolve(&gpu, policy), Err(Error::Unsupported));
    let nbif = gpu
        .ip_blocks
        .iter_mut()
        .find(|b| b.hw_id == ip::HW_ID_NBIF)
        .unwrap();
    (nbif.major, nbif.minor, nbif.revision) = (6, 3, 1);
    nbif.base_addrs[1] = 0x40;
    // DF RAS alone needs no UMC discovery.
    assert!(Layout::resolve(&gpu, Policy::new(MEM, false, true)).is_ok());
    assert_eq!(Layout::resolve(&gpu, policy), Err(Error::Unsupported));
    let mut umc = gpu.ip_blocks[0];
    (umc.hw_id, umc.major, umc.minor, umc.revision) = (ip::HW_ID_UMC, 8, 14, 0);
    umc.base_addrs[0] = UMC;
    for instance in 0..4 {
        gpu.ip_blocks.push(ip::IpBlock { instance, ..umc });
    }
    let l = Layout::resolve(&gpu, policy).unwrap();
    assert_eq!((l.umc, l.umcs), (UMC, 4));
    assert_eq!((l.index, l.data), (0x100, 0x104));
    assert_eq!(l.doorbell, (0xc000 + 0xfe) * 4);
    assert_eq!(
        l.umc_addr(3, 1, GECC_ERR_CNT),
        (UMC + 0x329 + 0x400 + 0xc0000) * 4
    );
    assert_eq!(l.channels().count(), 8);
    for _ in 0..13 {
        gpu.ip_blocks.push(ip::IpBlock { instance: 9, ..umc });
    }
    assert_eq!(Layout::resolve(&gpu, policy), Err(Error::Unsupported));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ras",
    navi48_ras_layout_uses_umc_discovery_and_nbif_631
);

fn rdna4_ras_is_navi48_only_as_linux_asic_supported() -> TestResult {
    use crate::amdgpu_rdna4::{tests::Profile, Rdna4Chip};
    let mut words = vec![0; 0x80000 / 4];
    for profile in Profile::ALL {
        let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(&mut words);
        profile.apply(&mut gpu);
        if asic_supported(&gpu) != (profile.chip() == Rdna4Chip::Navi48) {
            return TestResult::Fail("RAS ASIC support not keyed on MP0 14.0.3");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ras",
    rdna4_ras_is_navi48_only_as_linux_asic_supported
);
