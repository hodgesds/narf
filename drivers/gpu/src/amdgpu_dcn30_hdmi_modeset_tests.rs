//! End-to-end HDMI 2.0 modesets on the combined Navi22 register model: the
//! SCDC handshake in `enable_link_hdmi`'s place, deep colour through the PHY
//! PLL, encoder and FMT, and YCbCr 4:2:0 through OTG, FMT, OCSC and DPG.
use super::{edid, hf_vsdb, vsdb, DTD_640X480, DTD_720P};
use crate::{
    amdgpu_dcn30_dp::Aux,
    amdgpu_navi22_bios::Tables,
    amdgpu_navi22_display::{Signal, Sink},
    amdgpu_navi22_modeset::{Board, Error as M, Pipeline, Resources},
    amdgpu_navi22_modeset_model::{self as m, d1, d2, d3, Bench, Vram, MARK},
};
use alloc::{sync::Arc, vec, vec::Vec};
use narf_capabilities::Cap;
use narf_kernel_test::{kernel_test_in, TestResult};

/// SCDC transactions in the model log: `SCDC_WRITE | offset` = value.
const SCDC_WRITE: u32 = 0x2000_0000;
const SCDC_READ: u32 = 0x1000_0000;
const BOARD: Board = Board {
    crystal_khz: 100_000,
    channels: 12,
    channel_width_bytes: 2,
};

/// An HDMI 2.0 sink's SCDC on the far end of the DDC, logged in the model.
struct HdmiSink {
    model: Arc<m::Model>,
    regs: [u8; 256],
}
impl Aux for HdmiSink {
    async fn read(&mut self, _: u32, _: &mut [u8]) -> Result<(), M> {
        Err(M::Aux)
    }
    async fn write(&mut self, _: u32, _: &[u8]) -> Result<(), M> {
        Err(M::Aux)
    }
    async fn scdc_read(&mut self, offset: u8) -> Result<u8, M> {
        let v = self.regs[usize::from(offset)];
        self.model.0.lock().log.push(m::Write {
            dword: SCDC_READ | u32::from(offset),
            value: u32::from(v),
        });
        Ok(v)
    }
    async fn scdc_write(&mut self, offset: u8, value: u8) -> Result<(), M> {
        self.regs[usize::from(offset)] = value;
        self.model.0.lock().log.push(m::Write {
            dword: SCDC_WRITE | u32::from(offset),
            value: u32::from(value),
        });
        Ok(())
    }
}

fn run<T>(f: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn pos(log: &[m::Write], from: usize, f: impl Fn(&m::Write) -> bool) -> Option<usize> {
    log[from..].iter().position(f).map(|i| from + i)
}
fn last(log: &[m::Write], dword: u32) -> Option<u32> {
    log.iter().rev().find(|w| w.dword == dword).map(|w| w.value)
}

struct Lit {
    bench: Bench,
    pipeline: Pipeline,
    sink: HdmiSink,
    enabled: usize,
    pipe: u32,
    fe: u32,
    image: Vec<u8>,
}
/// Light `edid` on HDMI transmitter 3 at `max_bpc`.
fn light(edid: Vec<u8>, max_bpc: u8, vram: &Vram) -> Result<Lit, &'static str> {
    let bench = Bench::new();
    bench.set(m::MP1 + 0x274, 1);
    let image = m::vbios(7);
    let connector = m::connector(Signal::Hdmi, 3, 3);
    let route = Resources::new().acquire(&connector).map_err(|_| "route")?;
    // SAFETY: the bench's model owns every register the pipeline reaches.
    let mut pipeline = unsafe { Pipeline::new(&bench.gpu, Cap::bootstrap(), connector, route) }
        .map_err(|_| "pipeline")?;
    let mut sink = HdmiSink {
        model: bench.model.clone(),
        regs: [0; 256],
    };
    sink.regs[1] = 1;
    let target = Sink {
        edid,
        preferred: None,
        hdmi: true,
        dpcd: None,
    };
    let before = crate::amdgpu_navi48_boot::max_bpc();
    crate::amdgpu_navi48_boot::set_max_bpc(max_bpc);
    let result = {
        let tables = Tables::new(&image).map_err(|_| "tables")?;
        let links = [connector];
        // SAFETY: model-backed owners and a heap-backed pool.
        run(unsafe {
            pipeline.enable(
                core::future::ready(Ok(())),
                &vram.pool,
                &tables,
                BOARD,
                &links,
                &target,
                &mut sink,
                crate::amdgpu_navi22_modeset::test_pattern,
            )
        })
    };
    crate::amdgpu_navi48_boot::set_max_bpc(before);
    result.map_err(|_| "enable")?;
    let enabled = bench.writes();
    Ok(Lit {
        bench,
        pipeline,
        sink,
        enabled,
        pipe: u32::from(route.pipe),
        fe: u32::from(route.stream),
        image,
    })
}
fn stop(lit: &mut Lit) -> Result<(), &'static str> {
    let tables = Tables::new(&lit.image).map_err(|_| "tables")?;
    run(lit.pipeline.disable(&tables, &mut lit.sink)).map_err(|_| "disable")
}

fn dcn30_hdmi_modeset_deep_colour_scrambled_with_scdc_in_linux_order() -> TestResult {
    // 640x480 on an HDMI 2.0 sink with DC_36 and LTE_340Mcsc_scramble, at
    // amdgpu.max_bpc=12: 37.755 MHz 12-bpc TMDS, scrambled at the
    // character rate.
    let vram = Vram::new(2 << 20);
    let e = edid(DTD_640X480, &[vsdb(0x38, 68), hf_vsdb(120, 0x88)]);
    let mut lit = match light(e, 12, &vram) {
        Ok(l) => l,
        Err(why) => return TestResult::Fail(why),
    };
    let log = lit.bench.log();
    let (p, f) = (lit.pipe, lit.fe);
    let marker = |slot: u32, i: u32| lit.bench.get(MARK + 16 * slot + i);
    // dcn3_get_pix_clk_dividers: 25.17 MHz x 3/2 in 100 Hz; DCCG 3:2 DTO.
    if marker(m::SLOT_PIXEL_CLOCK, 0) != 377_550 || lit.bench.get(d1(0x40)) & 0x30 != 0x20 {
        return TestResult::Fail("12-bpc pixel clock");
    }
    // dcn3_program_pix_clk → dce112_program_pix_clk leaves color_depth 0:
    // set_pixel_clock_v7's deep_color_ratio (PS byte 9) is RATIO_DIS even at
    // 12 bpc, and miscinfo (byte 7) carries no YUV420 bit (DCN2+ never sets
    // SUPPORT_YCBCR420); only the DCCG resync carries the depth.
    if (marker(m::SLOT_PIXEL_CLOCK, 2) >> 8) & 0xff != 0
        || (marker(m::SLOT_PIXEL_CLOCK, 1) >> 24) & 0x04 != 0
    {
        return TestResult::Fail("SetPixelClock v7 deep_color_ratio / miscinfo");
    }
    // Deep colour 2 + enable, scrambler at the character rate.
    let control = lit.bench.get(d2(0x2093 + f * 0x100));
    if control & 0x3100_0006 != 0x2100_0002 {
        return TestResult::Fail("HDMI_CONTROL");
    }
    // 12 bpc: no dither; full-range clamp; RGB.
    if lit.bench.get(d2(0x1841 + p * 0x5a)) != 0
        || lit.bench.get(d2(0x1845 + p * 0x5a)) != 1
        || lit.bench.get(d3(0x599 + p * 0xd)) != 1
        || lit.bench.get(d3(0x59a + p * 0xd)) != 0x2000
    {
        return TestResult::Fail("12-bpc FMT / sRGB OCSC");
    }
    // enable_link_hdmi order: attributes, InfoFrames, SCDC (Source_Version,
    // TMDS_Config 1), backend <- frontend, transmitter ENABLE, read_scdc_data.
    let attr = pos(&log, 0, |w| w.dword == d2(0x2093 + f * 0x100));
    let source = attr.and_then(|a| pos(&log, a, |w| w.dword == SCDC_WRITE | 2 && w.value == 1));
    let config =
        source.and_then(|a| pos(&log, a, |w| w.dword == SCDC_WRITE | 0x20 && w.value == 1));
    let be = config.and_then(|a| {
        pos(&log, a, |w| {
            w.dword == d2(0x20b0 + 3 * 0x100) && w.value & 1 << (8 + f) != 0
        })
    });
    let tx = be.and_then(|a| {
        pos(&log, a, |w| {
            w.dword == MARK + 16 * m::SLOT_TRANSMITTER && (w.value >> 8) & 0xff == 1
        })
    });
    let status = tx.and_then(|a| pos(&log, a, |w| w.dword == SCDC_READ | 0x20));
    if status.is_none() {
        return TestResult::Fail("SCDC before the transmitter");
    }
    // Teardown: AVMUTE, legacy TMDS_Config 0, then the transmitter DISABLE.
    if let Err(why) = stop(&mut lit) {
        return TestResult::Fail(why);
    }
    let log = lit.bench.log();
    let mute = pos(&log, lit.enabled, |w| {
        w.dword == d2(0x209d + f * 0x100) && w.value & 1 != 0
    });
    let legacy = mute.and_then(|a| pos(&log, a, |w| w.dword == SCDC_WRITE | 0x20 && w.value == 0));
    let off = legacy.and_then(|a| {
        pos(&log, a, |w| {
            w.dword == MARK + 16 * m::SLOT_TRANSMITTER && (w.value >> 8) & 0xff == 0
        })
    });
    if off.is_none() || lit.sink.regs[0x20] != 0 {
        return TestResult::Fail("legacy SCDC on disable");
    }
    if lit.pipeline.hdmi_output().is_none_or(|s| !s.scdc) {
        return TestResult::Fail("retained stream");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_modeset_deep_colour_scrambled_with_scdc_in_linux_order
);

fn dcn30_hdmi_modeset_unscrambled_sink_gets_legacy_tmds_config() -> TestResult {
    // An SCDC sink a warm reboot left scrambled: an 8-bpc 640x480 stream
    // writes TMDS_Config 0 before the transmitter starts.
    let vram = Vram::new(2 << 20);
    let e = edid(DTD_640X480, &[vsdb(0, 68), hf_vsdb(120, 0x80)]);
    let mut lit = match light(e, 8, &vram) {
        Ok(l) => l,
        Err(why) => return TestResult::Fail(why),
    };
    let log = lit.bench.log();
    let config = pos(&log, 0, |w| w.dword == SCDC_WRITE | 0x20 && w.value == 0);
    let tx = config.and_then(|a| {
        pos(&log, a, |w| {
            w.dword == MARK + 16 * m::SLOT_TRANSMITTER && (w.value >> 8) & 0xff == 1
        })
    });
    // SPATIAL8 dither on the 8-bpc stream, no scrambler.
    if tx.is_none()
        || lit.bench.get(d2(0x1841 + lit.pipe * 0x5a)) != 0xc900
        || lit.bench.get(d2(0x2093 + lit.fe * 0x100)) & 0x3100_0006 != 0
    {
        return TestResult::Fail("legacy TMDS_Config before enable");
    }
    if let Err(why) = stop(&mut lit) {
        return TestResult::Fail(why);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_modeset_unscrambled_sink_gets_legacy_tmds_config
);

fn dcn30_hdmi_modeset_ycbcr420_through_otg_fmt_ocsc_and_dpg() -> TestResult {
    // 720p60 that the sink takes only as 4:2:0 (Y420VDB VIC 4): the TMDS
    // pixel clock halves to 37.125 MHz.
    let vram = Vram::new(4 << 20);
    let e = edid(DTD_720P, &[vsdb(0, 68), vec![0x41, 4], vec![0xe2, 14, 4]]);
    let mut lit = match light(e, 8, &vram) {
        Ok(l) => l,
        Err(why) => return TestResult::Fail(why),
    };
    let log = lit.bench.log();
    let (p, f) = (lit.pipe, lit.fe);
    let get = |d| lit.bench.get(d);
    if get(MARK + 16 * m::SLOT_PIXEL_CLOCK) != 371_250 || get(d1(0x40)) & 0x30 != 0 {
        return TestResult::Fail("4:2:0 pixel clock");
    }
    // OTG: two pixels per container, set after the timing, before enable.
    let timing = pos(&log, 0, |w| w.dword == d2(0x1b2a + p * 0x80));
    let div = timing.and_then(|a| {
        pos(&log, a, |w| {
            w.dword == d2(0x1b2e + p * 0x80) && w.value & 3 == 1
        })
    });
    let crtc = div.and_then(|a| {
        pos(&log, a, |w| {
            w.dword == d2(0x1b41 + p * 0x80) && w.value & 1 != 0
        })
    });
    if crtc.is_none() || get(d2(0x1acc + p * 0x10)) & 3 != 2 {
        return TestResult::Fail("4:2:0 OTG");
    }
    // FMT 4:2:0 subsampling, OCSC YCbCr709, DPG black in YUV.
    let dup = |c: u32| (c << 6) << 16 | c << 6;
    if get(d2(0x1840 + p * 0x5a)) & 0x2f_0000 != 0x2a_0000
        || get(d3(0x599 + p * 0xd)) != 1
        || get(d3(0x59a + p * 0xd)) != 0xf345 << 16 | 0xe04
        || last(&log, d2(0x1857 + p * 0x5a)) != Some(dup(0x1f4))
        || last(&log, d2(0x1858 + p * 0x5a)) != Some(dup(0x40))
    {
        return TestResult::Fail("4:2:0 FMT / OCSC / black");
    }
    // AVI: Y = 4:2:0 in PB1, VIC 4.
    let avi = pos(&log, 0, |w| w.dword == d2(0x2069 + f * 0x100));
    let words: Vec<u32> = match avi {
        Some(a) => log[a..a + 3].iter().map(|w| w.value).collect(),
        None => return TestResult::Fail("AVI"),
    };
    if (words[1] >> 13) & 3 != 3 || words[2] & 0xff != 4 {
        return TestResult::Fail("4:2:0 AVI");
    }
    // No SCDC (none declared).
    if log.iter().any(|w| matches!(w.dword >> 28, 1 | 2)) {
        return TestResult::Fail("SCDC without SCDC_Present");
    }
    if let Err(why) = stop(&mut lit) {
        return TestResult::Fail(why);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_modeset_ycbcr420_through_otg_fmt_ocsc_and_dpg
);

/// Unplug teardown (`Pipeline::disable_unplugged`): Linux's
/// `link_set_dpms_off` still sends the legacy TMDS_Config write to an SCDC
/// sink, unchecked, before the transmitter stops; a sink without SCDC gets
/// no DDC traffic.
fn dcn30_hdmi_unplug_teardown_sends_legacy_scdc_only_to_scdc_sinks() -> TestResult {
    for scdc in [true, false] {
        let vram = Vram::new(2 << 20);
        let blocks = if scdc {
            vec![vsdb(0, 68), hf_vsdb(120, 0x80)]
        } else {
            vec![vsdb(0, 68)]
        };
        let mut lit = match light(edid(DTD_640X480, &blocks), 8, &vram) {
            Ok(l) => l,
            Err(why) => return TestResult::Fail(why),
        };
        let from = lit.bench.log().len();
        let tables = Tables::new(&lit.image).unwrap();
        if run(lit.pipeline.disable_unplugged(&tables, &mut lit.sink)).is_err() {
            return TestResult::Fail("unplugged disable");
        }
        let log = lit.bench.log();
        let legacy = pos(&log, from, |w| w.dword == SCDC_WRITE | 0x20 && w.value == 0);
        let off = pos(&log, from, |w| {
            w.dword == MARK + 16 * m::SLOT_TRANSMITTER && (w.value >> 8) & 0xff == 0
        });
        let ddc = log[from..]
            .iter()
            .any(|w| w.dword & (SCDC_WRITE | SCDC_READ) != 0);
        let ok = if scdc {
            legacy.zip(off).is_some_and(|(l, o)| l < o)
        } else {
            !ddc && off.is_some()
        };
        if !ok {
            return TestResult::Fail("legacy SCDC on unplug");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-hdmi",
    dcn30_hdmi_unplug_teardown_sends_legacy_scdc_only_to_scdc_sinks
);
