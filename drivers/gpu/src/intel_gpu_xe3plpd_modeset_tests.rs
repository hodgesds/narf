//! Display-35 owned modeset fixtures: the display-14 modeset model
//! (`intel_gpu_modeset_xelpg::tests::MtlFake`) presenting Nova Lake-S, with
//! the LT PHY's message bus, P2P status, lane status and MacCLK registers of
//! DDI A answered by the LT PHY model (`intel_gpu_lt_phy::tests::FakeLtMmio`)
//! at their PICA offsets.

use super::*;
use crate::intel_gpu_lt_phy::tests::FakeLtMmio;
use crate::intel_gpu_lt_phy::{
    txy_ctl, LT_PHY_VDR_0_CONFIG, LT_PHY_VDR_1_CONFIG, LT_PHY_VDR_2_CONFIG,
};
use crate::intel_gpu_modeset::PixelFormat;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

/// DDI A's LT-only registers: `PORT_BUF_CTL2`, `PORT_BUF_CTL5`, the lane-0/1
/// M2P control and P2M status, `PORT_CLOCK_CTL` and the P2P status.
fn lt_reg(r: u64) -> bool {
    matches!(
        r,
        0x16fa04
            | 0x16fa34
            | 0x16fa40
            | 0x16fa44
            | 0x16fa48
            | 0x16fa4c
            | 0x16fa60
            | 0x16faa0
            | 0x16faa4
    )
}

/// DDI A's relocated buffer and AUX registers, mapped back to the display-14
/// offsets the modeset model answers at.
fn from_pica(r: u64) -> Option<u64> {
    match r {
        0x16fa00 | 0x16fa08 => Some(r - 0x16fa00 + 0x64004),
        0x16fa10..=0x16fa24 => Some(r - 0x16fa00 + 0x64000),
        _ => None,
    }
}

/// DDI A's display-14 PHY/AUX offsets, which display 35 must never touch.
fn display14_phy(r: u64) -> bool {
    matches!(r, 0x64004..=0x64024 | 0x64040..=0x6404c | 0x640d8 | 0x640dc | 0x640e0)
}

/// The display-20/30/35 resource registers the model keeps in `values`.
fn resource(r: u64) -> bool {
    matches!(
        r,
        0x510a0
            | 0x41100
            | 0x46460
            | 0x45230
            | 0x45234
            | 0x46440
            | 0x46438
            | 0x4438c
            | 0x7003c
            | 0x44464
            | 0x44468
            | 0x4446c
            | 0x45780
            | 0x45784
            | 0x45788
            | 0x45008
            | 0x44fe8
            | 0x44300
            | 0x44304
            | 0x45004
            | 0x71008
            | 0x72008
            | 0x73008
            | 0x43288
            | 0x432c8
            | 0x6fa88
            | 0x60404
    ) || ((0x70000..0x75000).contains(&r)
        && r & 0xfff >= 0x140
        && r & 0xfff <= 0x87c
        && r & 0xff < 0x80)
}

struct Nova {
    mode: crate::intel_gpu_modeset_xelpg::tests::MtlFake,
    lt: FakeLtMmio,
    values: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    strays: RefCell<Vec<u64>>,
    /// `XELPDP_DP_AUX_CH_CTL_POWER_STATUS` follows its request on LT.
    aux_power: Cell<bool>,
}

impl Nova {
    fn new() -> Self {
        Self {
            mode: crate::intel_gpu_modeset_xelpg::tests::MtlFake::new(
                crate::intel_gpu_xelpg::XeLpgPort::A,
            ),
            lt: FakeLtMmio::default(),
            values: RefCell::new(
                [
                    (0x510a0, 35 << 22),
                    (0x45780, 6 | (8 << 16)),
                    (0x45784, 10 | (12 << 16)),
                    (0x45788, 14 | (16 << 16)),
                ]
                .into_iter()
                .collect(),
            ),
            writes: RefCell::new(Vec::new()),
            strays: RefCell::new(Vec::new()),
            aux_power: Cell::new(false),
        }
    }
    fn get(&self, r: u64) -> u32 {
        self.read32(r)
    }
    fn written(&self, r: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == r)
            .map(|(_, v)| *v)
            .collect()
    }
    fn vdr(&self, lane: u8, address: u16) -> Option<u8> {
        self.lt.vdr.borrow().get(&(lane, address)).copied()
    }
    fn fb() -> Framebuffer {
        Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 4096,
            format: PixelFormat::Xrgb8888,
        }
    }
    fn run(&self) -> Result<Mode, ModesetError> {
        modeset(&View(self), &Self::fb(), Some(&Mode::VESA_1024X768_60))
    }
}

impl MmioWindow for Nova {
    fn read32(&self, r: u64) -> u32 {
        if display14_phy(r) {
            self.strays.borrow_mut().push(r);
            return u32::MAX;
        }
        if lt_reg(r) {
            return self.lt.read32(r);
        }
        if let Some(m) = from_pica(r) {
            let v = self.mode.read32(m);
            return if r == 0x16fa10 && self.aux_power.get() {
                v | crate::intel_gpu_aux::XELPDP_AUX_CH_CTL_POWER_STATUS
            } else {
                v
            };
        }
        if resource(r) {
            *self.values.borrow().get(&r).unwrap_or(&0)
        } else if r == 0x46070 {
            let v = self.mode.read32(r);
            v | ((v >> 1) & (1 << 22))
        } else if r == 0x64000 {
            let v = self.mode.read32(r);
            v | ((v >> 1) & (1 << 28))
        } else {
            self.mode.read32(r)
        }
    }
    fn write32(&self, r: u64, v: u32) {
        self.writes.borrow_mut().push((r, v));
        if display14_phy(r) {
            self.strays.borrow_mut().push(r);
            return;
        }
        if lt_reg(r) {
            return self.lt.write32(r, v);
        }
        if let Some(m) = from_pica(r) {
            if r == 0x16fa10 {
                self.aux_power
                    .set(v & crate::intel_gpu_aux::XELPDP_AUX_CH_CTL_POWER_REQUEST != 0);
            }
            return self.mode.write32(m, v);
        }
        if resource(r) {
            let mut value = v;
            if r == 0x45234 && v & (1 << 31) != 0 {
                value &= !(1 << 31)
            }
            if [0x45008, 0x44fe8, 0x44300, 0x44304].contains(&r) && v & (1 << 31) != 0 {
                value |= 1 << 30
            }
            self.values.borrow_mut().insert(r, value);
        } else {
            self.mode.write32(r, v)
        }
    }
}

/// The owned Pipe-A eDP modeset on display 35: the LT PHY's eDP PLL image
/// (HBR2 with the eDP `config[2]` mark) and eDP signal levels, the
/// display-35 CDCLK rung, and no Cx0 or display-14 PHY access.
fn smoke_nvl_owned_modeset_lights_pipe_a_through_the_lt_phy() -> TestResult {
    let io = Nova::new();
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    assert!(io.strays.borrow().is_empty(), "{:x?}", io.strays.borrow());
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::owned_panel_mode(),
        Some(Mode::VESA_1024X768_60)
    );
    // xe3plpd_lt_dp_hbr2 through the eDP table: config[2] = 1.
    assert_eq!(io.vdr(0, LT_PHY_VDR_0_CONFIG), Some(0x93));
    assert_eq!(io.vdr(0, LT_PHY_VDR_1_CONFIG), Some(0x2d));
    assert_eq!(io.vdr(0, LT_PHY_VDR_2_CONFIG), Some(1));
    // The warm panel's PLL is retired (VALFREQ 0), then the link symbol
    // clock of the HBR2 start rate.
    assert_eq!(io.written(0x64030), [0, 540_000]);
    // MacCLK requested and acknowledged on lane 0, forward clock ungated,
    // the MacCLK select and no SSC.
    let clock = io.get(0x16fa60);
    assert_eq!(clock & (3 << 30), 3 << 30, "{clock:#x}");
    assert_eq!(clock & (1 << 10), 1 << 10);
    assert_eq!(clock & (0x1f << 12), 0x8 << 12);
    assert_eq!(clock & 3, 0);
    // Training converged at levels 0/0: every link lane carries the eDP
    // table's entry 0 (swing level 0, main cursor 12).
    for lane in 0..2u8 {
        for tx in 0..2u8 {
            let main = io.vdr(lane, txy_ctl(tx, 3).unwrap());
            assert_eq!(main.map(|v| v & 0x3f), Some(12), "lane {lane} tx {tx}");
        }
    }
    // The D2D link is DDI_BUF_CTL's on display >= 20.
    assert!(io.written(0x64000).iter().any(|v| v & (1 << 29) != 0));
    // CDCLK from an off PLL on the display-35 table: Wa_13012396614's MDCLK
    // select first, the 151.2 MHz rung (ratio 21, waveform 0xa4a4).
    assert_eq!(io.written(0x46000), [0, 0x0200_0000]);
    assert_eq!(io.written(0x46070), [0, 0x15, 0x8000_0015]);
    assert_eq!(io.written(0x46008), [0x8f00_a4a4]);
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&io),
        151_200
    );
    // The MDCLK ratio after the raise in the Xe3P throttle field (16:13):
    // ceil(806.4 / 151.2) = 6, joined.
    assert_eq!(io.get(0x4438c) & (0xf << 13), 5 << 13);
    // The VRR timing generator at fixed refresh, as on display 30.
    assert_eq!(io.written(0x6000c), [767]);
    assert!(!io.written(0x60420).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_modeset",
    smoke_nvl_owned_modeset_lights_pipe_a_through_the_lt_phy
);

/// The entry refuses read-only: a Cx0 view, another display IP, and an
/// armed or secondary CMTG.
fn smoke_nvl_owned_modeset_admission_is_read_only() -> TestResult {
    struct Cx0<'a>(&'a Nova);
    impl MmioWindow for Cx0<'_> {
        fn read32(&self, r: u64) -> u32 {
            self.0.read32(r)
        }
        fn write32(&self, r: u64, v: u32) {
            self.0.write32(r, v)
        }
    }
    let fb = Nova::fb();
    let mode = Mode::VESA_1024X768_60;
    let io = Nova::new();
    assert_eq!(
        modeset(&Cx0(&io), &fb, Some(&mode)),
        Err(ModesetError::UnsupportedGeneration)
    );
    io.values.borrow_mut().insert(0x510a0, 30 << 22);
    assert_eq!(
        modeset(&View(&io), &fb, Some(&mode)),
        Err(ModesetError::UnsupportedGeneration)
    );
    io.values.borrow_mut().insert(0x510a0, 35 << 22);
    io.values.borrow_mut().insert(0x6fa88, 1 << 31);
    assert_eq!(
        modeset(&View(&io), &fb, Some(&mode)),
        Err(ModesetError::DisplayResourceUnavailable)
    );
    io.values.borrow_mut().insert(0x6fa88, 0);
    io.values.borrow_mut().insert(0x60404, 1 << 3);
    assert_eq!(
        modeset(&View(&io), &fb, Some(&mode)),
        Err(ModesetError::DisplayResourceUnavailable)
    );
    assert!(io.writes.borrow().is_empty(), "{:x?}", io.writes.borrow());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_modeset",
    smoke_nvl_owned_modeset_admission_is_read_only
);

/// The in-place takeover reads the panel's EDID before anything else: a
/// sink without one, or an XBGR firmware primary, refuses with only AUX
/// traffic written.
fn smoke_nvl_takeover_refuses_before_destructive_writes() -> TestResult {
    let primary = FirmwarePrimary {
        format: crate::drm::card::PixelFormat::Xrgb8888,
        geometry: crate::intel_gpu_scanout::Geometry {
            width: 1024,
            height: 768,
            pitch: 4096,
        },
        gtt_offset: 0x100_0000,
    };
    let io = Nova::new();
    assert_eq!(
        takeover(&View(&io), &primary),
        Err(ModesetError::EdidUnavailable)
    );
    let aux = |r: u64| (0x16fa10..=0x16fa24).contains(&r);
    assert!(io.writes.borrow().iter().all(|(r, _)| aux(*r)));
    let bgr = FirmwarePrimary {
        format: crate::drm::card::PixelFormat::Xbgr8888,
        ..primary
    };
    let io = Nova::new();
    assert_eq!(
        takeover(&View(&io), &bgr),
        Err(ModesetError::InvalidFramebuffer)
    );
    assert!(io.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_modeset",
    smoke_nvl_takeover_refuses_before_destructive_writes
);
