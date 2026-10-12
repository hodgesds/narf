use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    config: [u8; 256],
    reg: u32,
    writes: Vec<(u8, u64, u32)>,
    refuse: Option<(u8, u64)>,
}
impl Io for Fake {
    fn cfg16(&mut self, at: u64) -> u16 {
        u16::from_le_bytes(
            self.config[at as usize..at as usize + 2]
                .try_into()
                .unwrap(),
        )
    }
    fn cfg32(&mut self, at: u64) -> u32 {
        u32::from_le_bytes(
            self.config[at as usize..at as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    fn write16(&mut self, at: u64, value: u16) {
        self.writes.push((2, at, u32::from(value)));
        if self.refuse != Some((2, at)) {
            self.config[at as usize..at as usize + 2].copy_from_slice(&value.to_le_bytes());
        }
    }
    fn write32(&mut self, at: u64, value: u32) {
        self.writes.push((4, at, value));
        if self.refuse != Some((4, at)) {
            self.config[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    fn reg_read(&mut self, at: u64) -> u32 {
        assert_eq!(at, 0x603c4);
        self.reg
    }
    fn reg_write(&mut self, at: u64, value: u32) {
        assert_eq!(at, 0x603c4);
        self.writes.push((0, at, value));
        if self.refuse != Some((0, at)) {
            self.reg = value;
        }
    }
}
fn fixture(address64: bool, masks: bool) -> (Fake, Layout) {
    let mut io = Fake {
        config: [0; 256],
        reg: 0x54321002,
        writes: Vec::new(),
        refuse: None,
    };
    io.config[..4].copy_from_slice(&0x75501002u32.to_le_bytes());
    io.config[4..8].copy_from_slice(&0xf9000007u32.to_le_bytes());
    io.config[0x80] = 5;
    io.config[0x82..0x84].copy_from_slice(
        &(0x26u16 | if address64 { 0x80 } else { 0 } | if masks { 0x100 } else { 0 }).to_le_bytes(),
    );
    let mask = if address64 { 0x90 } else { 0x8c };
    io.config[mask..mask + 4].copy_from_slice(&0xf0f0f0f1u32.to_le_bytes());
    io.config[0xa0] = 0x11;
    (
        io,
        Layout {
            msi: 0x80,
            msix: Some(0xa0),
            nbio: 0x603c4,
            address64,
            masks,
        },
    )
}
fn navi48_msi_programs_one_message_with_masks_and_enable_last() -> TestResult {
    for (wide, masks) in [(false, false), (false, true), (true, false), (true, true)] {
        let (mut io, l) = fixture(wide, masks);
        program(&mut io, l, 63, 7).unwrap();
        assert_eq!(io.cfg32(0x84), 0xfee07000);
        assert_eq!(io.cfg16(if wide { 0x8c } else { 0x88 }), 63);
        if wide {
            assert_eq!(io.cfg32(0x88), 0);
        }
        assert_eq!(io.cfg32(4), 0xf9000407, "PCI Status W1C was modified");
        assert_eq!(io.reg, 0x54321009, "dummy read/nonsnoop encoding");
        assert_eq!(io.cfg16(0x82) & 0x71, 1);
        let enabled = io.cfg16(0x82);
        assert_eq!(io.writes.last().unwrap(), &(2, 0x82, u32::from(enabled)));
        if masks {
            let at = if wide { 0x90 } else { 0x8c };
            let masks: Vec<_> = io
                .writes
                .iter()
                .filter(|w| w.0 == 4 && w.1 == at)
                .map(|w| w.2)
                .collect();
            assert_eq!(masks, vec![0xf0f0f0f1, 0xf0f0f0f0]);
        }
        assert!(!io.writes.iter().any(|w| w.0 == 4 && w.1 == 4));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-msi",
    navi48_msi_programs_one_message_with_masks_and_enable_last
);

fn navi48_msi_refuses_inherited_routes_bad_capabilities_and_cpu_ids() -> TestResult {
    for case in 0..9 {
        let (mut io, mut l) = fixture(true, true);
        match case {
            0 => io.config[0x82] |= 1,
            1 => io.config[0xa3] = 0x80,
            2 => io.config[0] = 0,
            3 => io.config[4] = 0,
            4 => io.config[0x82] |= 0xe,
            5 => l.msi = 0xf0,
            6 => io.config[0x81] = 0x90,
            7 => l.msix = Some(0x8c),
            _ => io.config[0x80] = 0x11,
        }
        assert!(program(&mut io, l, 63, 1).is_err());
        assert!(io.writes.is_empty());
    }
    for (v, apic) in [(47, 1), (240, 1), (255, 1), (63, 256)] {
        let (mut io, l) = fixture(true, true);
        assert_eq!(program(&mut io, l, v, apic), Err(Error::Unsupported));
        assert!(io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-msi",
    navi48_msi_refuses_inherited_routes_bad_capabilities_and_cpu_ids
);

fn navi48_msi_readback_failure_and_revocation_prevent_delivery() -> TestResult {
    for refuse in [(4, 0x84), (2, 0x8c), (0, 0x603c4), (2, 4)] {
        let (mut io, l) = fixture(true, true);
        io.refuse = Some(refuse);
        assert_eq!(program(&mut io, l, 63, 1), Err(Error::Readback));
        assert_eq!(io.cfg16(0x82) & 1, 0);
        assert!(!io
            .writes
            .iter()
            .any(|w| w.0 == 2 && w.1 == 0x82 && w.2 & 1 != 0));
    }
    let (mut io, l) = fixture(true, true);
    let authority = Cap::<BusDeviceCap, Write>::bootstrap();
    authority.revoke();
    assert!(authority.invoke(Op(|| program(&mut io, l, 63, 1))).is_err());
    assert!(io.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-msi",
    navi48_msi_readback_failure_and_revocation_prevent_delivery
);
