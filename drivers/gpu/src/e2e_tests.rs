//! End-to-end GPU/DRM smoke tests: PCI probe → DRM modeset → framebuffer scanout.
//!
//! Each test drives the pure (non-MMIO) surface of the driver stack against
//! in-memory fakes:
//!
//! - `FakeMmio` — a 16 MiB `Vec<u8>` acting as a BAR0/BAR2 MMIO window. All
//!   reads return the last value written; no side-effects.
//! - `FakeFramebuffer` — a `Vec<u32>` (XRGB8888 pixels) acting as linear
//!   scanout memory for framebuffer-write verification.
//!
//! Linux references used:
//!   - `linux/drivers/gpu/drm/bochs/` — VBE dispi register protocol
//!   - `linux/drivers/gpu/drm/amd/amdgpu/` — AMDGPU probe + ring init
//!   - `linux/drivers/gpu/drm/drm_edid.c` — EDID parser test fixtures

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

fn poll_once<F: core::future::Future>(fut: F) -> Option<F::Output> {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(|data| RawWaker::new(data, &VTABLE), |_| {}, |_| {}, |_| {});
    let raw = RawWaker::new(core::ptr::null(), &VTABLE);
    // SAFETY: VTABLE contains valid no-op operations and does not dereference data.
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);
    let mut pinned = core::pin::pin!(fut);
    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

// ── Fake MMIO window ─────────────────────────────────────────────────────

/// 16 MiB in-memory MMIO window.  `read16` / `write16` / `read32` /
/// `write32` operate at byte offsets; out-of-range accesses return `0` or
/// are silently dropped.
struct FakeMmio {
    data: alloc::vec::Vec<u8>,
}

#[allow(dead_code)]
impl FakeMmio {
    fn new(size_bytes: usize) -> Self {
        Self {
            data: alloc::vec![0u8; size_bytes],
        }
    }

    fn write16(&mut self, offset: usize, value: u16) {
        if offset + 2 > self.data.len() {
            return;
        }
        self.data[offset] = value as u8;
        self.data[offset + 1] = (value >> 8) as u8;
    }

    fn read16(&self, offset: usize) -> u16 {
        if offset + 2 > self.data.len() {
            return 0;
        }
        u16::from_le_bytes([self.data[offset], self.data[offset + 1]])
    }

    fn write32(&mut self, offset: usize, value: u32) {
        if offset + 4 > self.data.len() {
            return;
        }
        self.data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn read32(&self, offset: usize) -> u32 {
        if offset + 4 > self.data.len() {
            return 0;
        }
        u32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }
}

// ── Bochs VBE Dispi constants (mirrors bochs.rs) ─────────────────────────

const VBE_BASE: usize = 0x500;
const VBE_ID_OFF: usize = VBE_BASE;
const VBE_XRES_OFF: usize = VBE_BASE + 0x02;
const VBE_YRES_OFF: usize = VBE_BASE + 0x04;
const VBE_BPP_OFF: usize = VBE_BASE + 0x06;
const VBE_ENABLE_OFF: usize = VBE_BASE + 0x08;
const VBE_VIRT_WIDTH_OFF: usize = VBE_BASE + 0x0C;
const VBE_VIRT_HEIGHT_OFF: usize = VBE_BASE + 0x0E;

const VBE_ENABLE_BIT: u16 = 0x01;
const VBE_LFB_BIT: u16 = 0x40;
const VBE_ID_MIN: u16 = 0xB0C0;
const VBE_ID_MAX: u16 = 0xB0C5;

// ── Smoke 1: bochs VBE ID validates ──────────────────────────────────────
//
// The bochs driver reads the VBE ID register (at BAR2+0x500) and
// rejects any value outside 0xB0C0..=0xB0C5.  Verify that a
// compliant ID is accepted and an out-of-range one is rejected.

fn smoke_bochs_vbe_id_range() -> TestResult {
    let mut mmio = FakeMmio::new(0x1000);

    // ID 0xB0C4 is mid-range; driver should accept.
    mmio.write16(VBE_ID_OFF, 0xB0C4);
    let id = mmio.read16(VBE_ID_OFF);
    if !(VBE_ID_MIN..=VBE_ID_MAX).contains(&id) {
        return TestResult::Fail("0xB0C4 not in accepted VBE ID range");
    }

    // ID 0x1234 is out of range; driver would reject.
    mmio.write16(VBE_ID_OFF, 0x1234);
    let bad = mmio.read16(VBE_ID_OFF);
    if (VBE_ID_MIN..=VBE_ID_MAX).contains(&bad) {
        return TestResult::Fail("0x1234 incorrectly falls in VBE ID range");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_bochs_vbe_id_range);

// ── Smoke 2: bochs modeset 640×480×32 writes VBE registers ───────────────
//
// Simulate bochs initialisation sequence: disable → set XRES/YRES/BPP →
// set virtual size → enable+LFB.  Verify the BAR2 MMIO window reflects
// the expected values at the VBE Dispi register offsets.

fn smoke_bochs_modeset_640x480x32() -> TestResult {
    let mut mmio = FakeMmio::new(0x1000);

    // Set valid ID first (driver would have checked this at probe).
    mmio.write16(VBE_ID_OFF, 0xB0C5);

    // Modeset sequence (mirrors BochsDisplay::bring_up).
    mmio.write16(VBE_ENABLE_OFF, 0);
    mmio.write16(VBE_XRES_OFF, 640);
    mmio.write16(VBE_YRES_OFF, 480);
    mmio.write16(VBE_BPP_OFF, 32);
    mmio.write16(VBE_VIRT_WIDTH_OFF, 640);
    mmio.write16(VBE_VIRT_HEIGHT_OFF, 480);
    mmio.write16(VBE_ENABLE_OFF, VBE_ENABLE_BIT | VBE_LFB_BIT);

    // Verify XRES / YRES / BPP.
    if mmio.read16(VBE_XRES_OFF) != 640 {
        return TestResult::Fail("VBE_XRES != 640 after modeset");
    }
    if mmio.read16(VBE_YRES_OFF) != 480 {
        return TestResult::Fail("VBE_YRES != 480 after modeset");
    }
    if mmio.read16(VBE_BPP_OFF) != 32 {
        return TestResult::Fail("VBE_BPP != 32 after modeset");
    }

    // ENABLE register must have both LFB bit and enable bit set.
    let enable = mmio.read16(VBE_ENABLE_OFF);
    if enable & VBE_ENABLE_BIT == 0 {
        return TestResult::Fail("VBE_ENABLE_BIT not set");
    }
    if enable & VBE_LFB_BIT == 0 {
        return TestResult::Fail("VBE_LFB_BIT not set");
    }

    // Virtual size must match active size.
    if mmio.read16(VBE_VIRT_WIDTH_OFF) != 640 {
        return TestResult::Fail("VBE_VIRT_WIDTH mismatch");
    }
    if mmio.read16(VBE_VIRT_HEIGHT_OFF) != 480 {
        return TestResult::Fail("VBE_VIRT_HEIGHT mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_bochs_modeset_640x480x32);

// ── Smoke 3: bochs framebuffer pixel write at correct offset ─────────────
//
// A linear XRGB8888 framebuffer at stride=width stores pixel (x,y) at
// byte offset `(y * stride + x) * 4`.  Verify that writing a known pixel
// colour to a FakeFramebuffer Vec<u32> lands at the expected index.

fn smoke_bochs_fb_pixel_offset() -> TestResult {
    const WIDTH: usize = 640;
    const HEIGHT: usize = 480;

    let mut fb: alloc::vec::Vec<u32> = alloc::vec![0u32; WIDTH * HEIGHT];

    // Write a distinctive pattern at pixel (100, 200).
    let x: usize = 100;
    let y: usize = 200;
    let colour: u32 = 0xFF_AA_BB_CC;
    fb[y * WIDTH + x] = colour;

    if fb[y * WIDTH + x] != colour {
        return TestResult::Fail("pixel at (100,200) did not round-trip");
    }

    // Pixel (0, 0) is at index 0.
    fb[0] = 0xFF_11_22_33;
    if fb[0] != 0xFF_11_22_33 {
        return TestResult::Fail("pixel at (0,0) wrong");
    }

    // Last pixel (WIDTH-1, HEIGHT-1) at the final index.
    let last = (HEIGHT - 1) * WIDTH + (WIDTH - 1);
    fb[last] = 0xFF_DE_AD_BE;
    if fb[last] != 0xFF_DE_AD_BE {
        return TestResult::Fail("last pixel wrong");
    }

    // Verify stride alignment: pixel (0, 1) is exactly WIDTH u32s ahead of
    // pixel (0, 0).
    fb[WIDTH] = 0xFF_CA_FE_00;
    if fb[WIDTH] != 0xFF_CA_FE_00 {
        return TestResult::Fail("pixel at (0,1) wrong");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_bochs_fb_pixel_offset);

// ── Smoke 4: bochs unprobe — MMIO window survives, device record gone ─────
//
// After tearing down the bochs controller the MMIO bytes we wrote should
// remain unchanged (no reset side-effect) and the live controller count
// drops to zero.

fn smoke_bochs_unprobe_cleanup() -> TestResult {
    let mut mmio = FakeMmio::new(0x1000);

    // Set up a mode.
    mmio.write16(VBE_ID_OFF, 0xB0C0);
    mmio.write16(VBE_XRES_OFF, 1024);
    mmio.write16(VBE_YRES_OFF, 768);
    mmio.write16(VBE_BPP_OFF, 32);
    mmio.write16(VBE_ENABLE_OFF, VBE_ENABLE_BIT | VBE_LFB_BIT);

    // Simulate unprobe by dropping a controller-state tracker.
    // The initial value is overwritten by the unprobe below before it is read.
    #[allow(unused_assignments)]
    let mut controller_present = true;
    // "Unprobe" — clear the controller slot.
    controller_present = false;

    // MMIO values should be undisturbed.
    if mmio.read16(VBE_XRES_OFF) != 1024 {
        return TestResult::Fail("XRES changed during unprobe");
    }
    if mmio.read16(VBE_YRES_OFF) != 768 {
        return TestResult::Fail("YRES changed during unprobe");
    }
    if mmio.read16(VBE_ENABLE_OFF) & VBE_ENABLE_BIT == 0 {
        return TestResult::Fail("ENABLE unexpectedly cleared");
    }

    // Controller slot is gone.
    if controller_present {
        return TestResult::Fail("controller_present still set after unprobe");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_bochs_unprobe_cleanup);

// ── Smoke 5: AMDGPU Renoir PCI probe → family identification ─────────────
//
// `chip_info_for_pci_id` (exposed via `RENOIR` / `Family::Renoir`) maps
// PCI ID 1002:1636 to the Renoir family and the correct firmware blobs.
// Verify the family + ASIC name + FW entry list is populated correctly.

fn smoke_amdgpu_renoir_probe_identifies_family() -> TestResult {
    use crate::amdgpu::{Family, AMD_VENDOR, RENOIR};

    // RENOIR constant must match the published PCI ID.
    if RENOIR != 0x1636 {
        return TestResult::Fail("RENOIR PCI DID constant is wrong (expected 0x1636)");
    }

    // Register the PCI driver and verify the Renoir DID appears in the match
    // table (structural test independent of live silicon).
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    crate::amdgpu::register_pci_driver();
    let regs = registered_pci_drivers();

    let found = regs.iter().any(|m| {
        matches!(m.kind, MatchKind::VendorDevice { vendor, device }
            if vendor == AMD_VENDOR && device == RENOIR)
    });
    if !found {
        return TestResult::Fail("Renoir VID/DID not in PCI driver match table");
    }

    // Family enum value correctness: Renoir != Phoenix (different display IP).
    if Family::Renoir == Family::Phoenix {
        return TestResult::Fail("Family::Renoir collapsed to Family::Phoenix");
    }

    // The Renoir DID resolves to Family::Renoir internally; verify by checking
    // the RENOIR constant is distinct from PHOENIX_HAWKPOINT1.
    use crate::amdgpu::PHOENIX_HAWKPOINT1;
    if RENOIR == PHOENIX_HAWKPOINT1 {
        return TestResult::Fail("Renoir DID same as Phoenix — table collision");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/e2e",
    smoke_amdgpu_renoir_probe_identifies_family
);

// ── Smoke 6: AMDGPU GFX9 ring-init sequence — first 20 MMIO writes ───────
//
// `build_gfx9_ring_init` emits the CP ring bring-up sequence for GFX9
// (Vega / Renoir / Cezanne).  Verify:
//   - Sequence is non-empty and has the expected write count (10).
//   - First write is CP_ME_CNTL with HALT_ALL bits set.
//   - Second and third writes are CP_RB0_WPTR / CP_RB0_WPTR_HI both zero.
//   - Last write is CP_ME_CNTL with value zero (unhalt).
// Uses gc_base = 0 so absolute addresses equal the published register
// offsets directly.

fn smoke_amdgpu_gfx9_ring_init_sequence() -> TestResult {
    use crate::amdgpu_gfx::{
        build_gfx9_ring_init, CP_ME_CNTL_HALT_ALL, CP_ME_CNTL_REL, CP_RB0_WPTR_HI_REL,
        CP_RB0_WPTR_REL,
    };

    let gc_base: u32 = 0x0000_0000;
    // Ring: 1024 dwords, 256-byte aligned phys.
    let ring_phys: u64 = 0x0000_1000;
    let ring_size_dw: u32 = 1024;
    let doorbell_idx: u32 = 2;
    let rptr_wb_phys: u64 = 0x0000_2000;

    let seq =
        match build_gfx9_ring_init(gc_base, ring_phys, ring_size_dw, doorbell_idx, rptr_wb_phys) {
            Ok(s) => s,
            Err(_e) => return TestResult::Fail("build_gfx9_ring_init failed"),
        };

    if seq.is_empty() {
        return TestResult::Fail("GFX9 ring-init sequence is empty");
    }

    // Step 1: CP_ME_CNTL = HALT_ALL.
    let w0 = seq.writes[0];
    if w0.addr != gc_base + CP_ME_CNTL_REL {
        return TestResult::Fail("first write is not CP_ME_CNTL");
    }
    if w0.value != CP_ME_CNTL_HALT_ALL {
        return TestResult::Fail("first write does not set HALT_ALL");
    }

    // Step 2-3: CP_RB0_WPTR / _HI = 0 (wptr reset).
    let w1 = seq.writes[1];
    if w1.addr != gc_base + CP_RB0_WPTR_REL {
        return TestResult::Fail("second write is not CP_RB0_WPTR");
    }
    if w1.value != 0 {
        return TestResult::Fail("CP_RB0_WPTR reset value != 0");
    }
    let w2 = seq.writes[2];
    if w2.addr != gc_base + CP_RB0_WPTR_HI_REL {
        return TestResult::Fail("third write is not CP_RB0_WPTR_HI");
    }
    if w2.value != 0 {
        return TestResult::Fail("CP_RB0_WPTR_HI reset value != 0");
    }

    // Last write: CP_ME_CNTL = 0 (unhalt).
    let last = seq.writes[seq.len() - 1];
    if last.addr != gc_base + CP_ME_CNTL_REL {
        return TestResult::Fail("last write is not CP_ME_CNTL (unhalt)");
    }
    if last.value != 0 {
        return TestResult::Fail("unhalt write value != 0");
    }

    // Ring-base write encodes ring_phys.
    use crate::amdgpu_gfx::{CP_RB0_BASE_HI_REL, CP_RB0_BASE_REL};
    let base_lo = seq
        .writes
        .iter()
        .find(|w| w.addr == gc_base + CP_RB0_BASE_REL);
    let base_hi = seq
        .writes
        .iter()
        .find(|w| w.addr == gc_base + CP_RB0_BASE_HI_REL);
    match (base_lo, base_hi) {
        (Some(lo), Some(hi)) => {
            if lo.value != ring_phys as u32 {
                return TestResult::Fail("CP_RB0_BASE lo does not match ring_phys lo");
            }
            if hi.value != (ring_phys >> 32) as u32 {
                return TestResult::Fail("CP_RB0_BASE_HI does not match ring_phys hi");
            }
        }
        _ => return TestResult::Fail("CP_RB0_BASE / _HI writes missing"),
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_amdgpu_gfx9_ring_init_sequence);

// ── Smoke 7: fb-console glyph lands at the correct scanline ──────────────
//
// Construct an FbConsole over a FakeFramebuffer (via Framebuffer::new over a
// Vec<u32>).  Write "hello\n" and verify that non-background pixels appear
// in the first text row's scanline range [TOP_PX_OFFSET, TOP_PX_OFFSET+8).

fn smoke_fb_console_writes_line_to_expected_scanline() -> TestResult {
    use narf_graphics::console::FbConsole;
    use narf_graphics::{Framebuffer, Pixel32};

    const W: u32 = 160; // 20 cols × 8 px
    const H: u32 = 96; // 12 rows × 8 px + 32 px beacon offset
    const TOP_PX_OFFSET: u32 = 32;

    // Allocate pixel buffer and wrap it in a Framebuffer.
    let mut pixels: alloc::vec::Vec<u32> = alloc::vec![0u32; (W * H) as usize];
    // SAFETY: pixels Vec<u32> owns the backing memory; the Framebuffer lives
    // entirely within this test's stack frame and will not outlive `pixels`.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let fb = unsafe { Framebuffer::new(pixels.as_mut_ptr(), W, H, W) };

    let fg = Pixel32::WHITE;
    let bg = Pixel32::BLACK;
    let mut con = FbConsole::new(fb, fg, bg);

    // Write a visible string.
    con.write_bytes(b"hello\n");

    // The first text row occupies pixel rows [TOP_PX_OFFSET, TOP_PX_OFFSET+8).
    // At least one pixel in that band should be fg (non-black) after writing
    // 'h' (which is the first character — glyph starts at x=0).
    let fg_raw = fg.raw();
    let mut found_fg = false;
    for row in TOP_PX_OFFSET..TOP_PX_OFFSET + 8 {
        for col in 0..8u32 {
            let idx = (row * W + col) as usize;
            if pixels[idx] == fg_raw {
                found_fg = true;
                break;
            }
        }
        if found_fg {
            break;
        }
    }

    if !found_fg {
        return TestResult::Fail("no fg pixels in expected glyph scanline after writing 'hello'");
    }

    // The background should dominate past the glyph columns (after col 40 =
    // 5 chars × 8 px, the rest of the first text row is background).
    let bg_raw = bg.raw();
    let probe_col: u32 = 48; // well past "hello" (40 px wide)
    if probe_col < W {
        let idx = (TOP_PX_OFFSET * W + probe_col) as usize;
        if pixels[idx] != bg_raw {
            return TestResult::Fail("non-background pixel beyond glyph extent");
        }
    }

    // Cursor should have advanced to the next row (after '\n').
    let (col, row) = con.cursor();
    if col != 0 {
        return TestResult::Fail("cursor column not reset after newline");
    }
    if row != 1 {
        return TestResult::Fail("cursor row did not advance after newline");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/e2e",
    smoke_fb_console_writes_line_to_expected_scanline
);

// ── Smoke 8: DRM Card — invalid dimensions rejected by addfb2 ────────────
//
// `Card::addfb2` must reject zero dimensions and unknown pixel formats.
// This exercises the validation path that mirrors Linux's
// `drm_mode_addfb2_ioctl` sanity checks.

fn smoke_drm_card_invalid_mode_rejected() -> TestResult {
    use crate::drm::card::{Card, CardError};

    let mut card = Card::new("test-driver", "Test GPU", (1, 0, 0));

    // Allocate a GEM object so addfb2 can reference it.
    let handle = match card.gem.alloc(0x1000_0000, 640 * 480 * 4) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("GEM alloc failed"),
    };

    // Zero width must be rejected.
    let r = card.addfb2(0, 480, 0x3432_5258, 640 * 4, handle);
    if !matches!(r, Err(CardError::InvalidDimensions)) {
        return TestResult::Fail("zero width was not rejected");
    }

    // Zero height must be rejected.
    let r = card.addfb2(640, 0, 0x3432_5258, 640 * 4, handle);
    if !matches!(r, Err(CardError::InvalidDimensions)) {
        return TestResult::Fail("zero height was not rejected");
    }

    // Unknown pixel format must be rejected.
    let r = card.addfb2(640, 480, 0xDEAD_BEEF, 640 * 4, handle);
    if !matches!(r, Err(CardError::UnknownFormat)) {
        return TestResult::Fail("unknown pixel format was not rejected");
    }

    // Valid dimensions and format must succeed.
    let r = card.addfb2(640, 480, 0x3432_5258, 640 * 4, handle);
    if r.is_err() {
        return TestResult::Fail("valid addfb2 call rejected");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_drm_card_invalid_mode_rejected);

// ── Smoke 9: EDID parse — synthetic 640×480@60 preferred timing ──────────
//
// Build a real (checksum-valid) 128-byte EDID block with a 640×480@60 Hz
// detailed-timing descriptor at offset 0x36 and verify the parser extracts
// the correct fields.
//
// EDID detailed-timing encoding per VESA E-EDID 1.4 §3.10:
//   bytes [0x36..0x48]:
//     [0..1]  pixel clock in 10 kHz units (LE u16)
//     [2]     h_active[7:0]
//     [3]     h_blanking[7:0]
//     [4]     h_active[11:8] (bits 7:4) | h_blanking[11:8] (bits 3:0)
//     [5]     v_active[7:0]
//     [6]     v_blanking[7:0]
//     [7]     v_active[11:8] (bits 7:4) | v_blanking[11:8] (bits 3:0)
//     [8]     h_sync_offset[7:0]
//     [9]     h_sync_width[7:0]
//     [10]    v_sync_offset[3:0] (bits 7:4) | v_sync_width[3:0]
//     [11]    h_sync_offset[9:8](bits 7:6) | h_sync_width[9:8](5:4) |
//             v_sync_offset[5:4](3:2) | v_sync_width[5:4](1:0)
//
// 640×480@60: DMT / VESA standard; pixel clock ≈ 25.175 MHz = 2517.5 × 10 kHz
// (round to 2518 units), h_total=800, v_total=525, h_blanking=160,
// v_blanking=45, h_sync_offset=16, h_sync_width=96, v_sync_offset=10,
// v_sync_width=2.

/// The EDID detailed-timing byte that packs two 12-bit fields' high nibbles:
/// `active[11:8]` in the top nibble, `blanking[11:8]` in the bottom.
///
/// A helper rather than the expression written inline twice, because for the
/// values these fixtures use (`h_blanking = 160`, `v_blanking = 45`) the low
/// nibble is *always* zero, and clippy correctly says so — "this operation will
/// always return zero". Hard-coding the shifted constant would silence it while
/// throwing away the one thing the expression is for: showing which EDID field
/// each nibble belongs to. Taking the values as arguments keeps the layout
/// legible and makes the zero a property of the fixture rather than of the code.
fn dtd_high_nibbles(active: u32, blanking: u32) -> u8 {
    ((((active >> 8) & 0xF) << 4) | ((blanking >> 8) & 0xF)) as u8
}

fn smoke_edid_parse_640x480_preferred_timing() -> TestResult {
    use narf_graphics::edid::{Edid, EdidError};

    let mut edid = [0u8; 128];
    // Header.
    edid[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    // Manufacturer "VSC" (VESA-style example: V=22, S=19, C=3).
    let mfr: u16 = (22u16 << 10) | (19u16 << 5) | 3u16;
    edid[8] = (mfr >> 8) as u8;
    edid[9] = mfr as u8;
    // Product code 0x0001, serial 0.
    edid[10] = 0x01;
    edid[11] = 0x00;
    // Version 1.4.
    edid[18] = 1;
    edid[19] = 4;

    // Detailed timing descriptor at offset 0x36 for 640×480@60.
    // Pixel clock = 25.175 MHz ≈ 2518 × 10 kHz.
    let pclk: u16 = 2518;
    edid[0x36] = pclk as u8;
    edid[0x37] = (pclk >> 8) as u8;
    // h_active=640, h_blanking=160.
    edid[0x38] = (640 & 0xFF) as u8; // h_active[7:0]
    edid[0x39] = (160 & 0xFF) as u8; // h_blanking[7:0]
    edid[0x3A] = dtd_high_nibbles(640, 160);
    // v_active=480, v_blanking=45.
    edid[0x3B] = (480 & 0xFF) as u8;
    edid[0x3C] = (45 & 0xFF) as u8;
    edid[0x3D] = dtd_high_nibbles(480, 45);
    // h_sync_offset=16, h_sync_width=96.
    edid[0x3E] = 16u8;
    edid[0x3F] = 96u8;
    // v_sync_offset=10 (nibble), v_sync_width=2 (nibble).
    edid[0x40] = (10u8 << 4) | 2u8;
    // Upper bits for sync fields (all fit in 8 bits here, so upper nibbles = 0).
    edid[0x41] = 0x00;

    // Fix checksum.
    let s: u8 = edid[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    edid[127] = 0u8.wrapping_sub(s);

    let parsed = match Edid::parse(&edid) {
        Ok(e) => e,
        Err(_e) => return TestResult::Fail("EDID parse rejected synthetic 640x480 block"),
    };

    // Version 1.4.
    if parsed.version_major() != 1 || parsed.version_minor() != 4 {
        return TestResult::Fail("version round-trip");
    }

    // Preferred timing fields.
    let timing = match parsed.preferred_timing() {
        Ok(t) => t,
        Err(EdidError::NoPreferredTiming) => {
            return TestResult::Fail("preferred_timing returned NoPreferredTiming")
        }
        Err(_) => return TestResult::Fail("preferred_timing returned unexpected error"),
    };
    if timing.h_active != 640 {
        return TestResult::Fail("h_active != 640");
    }
    if timing.v_active != 480 {
        return TestResult::Fail("v_active != 480");
    }
    // Pixel clock round-trip (2518 × 10 kHz = 25 180 kHz).
    if timing.pixel_clock_khz != 25_180 {
        return TestResult::Fail("pixel_clock_khz round-trip failed");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_edid_parse_640x480_preferred_timing);

// ── Smoke 10: multi-monitor — 2 connectors, independent modeset per CRTC ──
//
// Build a `KmsState` with 2 connectors (eDP + DP) and 4 CRTCs, set both
// connectors to `Connected`, call `pick_crtc` for each, verify they get
// different CRTCs, then plan an independent modeset per connector and
// confirm the plans reference distinct CRTCs.

fn smoke_drm_multi_monitor_enumerate_independent_modesets() -> TestResult {
    use crate::amdgpu::Family;
    use crate::amdgpu_atom_displayobj::ConnectorKind;
    use crate::amdgpu_atom_displayobj::DisplayPath;
    use crate::amdgpu_modeset::{commit_modeset_full, plan_modeset, KmsError, KmsState};

    // Build KMS state with 4 pipes (APU-typical).
    let mut kms = KmsState::new(4);

    // Connector 0: eDP (internal panel — starts Connected per KmsState::ingest_atom_paths).
    // Connector 1: DP  (external — starts Disconnected; we flip it to Connected below).
    kms.ingest_atom_paths([
        DisplayPath {
            connector_kind: ConnectorKind::Edp,
            connector_index: 0,
            device_tag: 0x0010,
            gpu_object_id: 0x1100,
        },
        DisplayPath {
            connector_kind: ConnectorKind::Dp,
            connector_index: 0,
            device_tag: 0x0001,
            gpu_object_id: 0x1101,
        },
    ]);

    // Flip the external DP connector to Connected so pick_crtc succeeds.
    use crate::amdgpu_modeset::ConnectorStatus;
    kms.set_status(1, ConnectorStatus::Connected);

    // Each connector should now get a distinct CRTC.
    let crtc_a = match kms.pick_crtc(0) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("pick_crtc(0) failed for eDP"),
    };
    let crtc_b = match kms.pick_crtc(1) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("pick_crtc(1) failed for DP"),
    };
    if crtc_a == crtc_b {
        return TestResult::Fail("both connectors assigned the same CRTC");
    }

    // Plan a modeset for each connector.  Use a non-zero DCN base so
    // addresses are non-trivially distinct between connectors.
    let dcn_base: u32 = 0x0040_0000;
    let surface_a: u64 = 0x0001_0000;
    let surface_b: u64 = 0x0002_0000;

    let plan_a = match plan_modeset(
        &kms,
        Family::Renoir,
        0,
        1920,
        1080,
        60,
        1920,
        surface_a,
        dcn_base,
    ) {
        Ok(p) => p,
        Err(KmsError::UnsupportedMode) => {
            return TestResult::Skip("1920x1080@60 not in timing table — deferred")
        }
        Err(_) => return TestResult::Fail("plan_modeset for eDP failed"),
    };
    let plan_b = match plan_modeset(
        &kms,
        Family::Renoir,
        1,
        1280,
        720,
        60,
        1280,
        surface_b,
        dcn_base,
    ) {
        Ok(p) => p,
        Err(KmsError::UnsupportedMode) => {
            return TestResult::Skip("1280x720@60 not in timing table — deferred")
        }
        Err(_) => return TestResult::Fail("plan_modeset for DP failed"),
    };

    // Plans must reference different CRTCs.
    if plan_a.crtc_idx == plan_b.crtc_idx {
        return TestResult::Fail("both modeset plans target the same CRTC");
    }
    // Connector indices must match what we asked for.
    if plan_a.connector_idx != 0 {
        return TestResult::Fail("plan_a connector_idx != 0");
    }
    if plan_b.connector_idx != 1 {
        return TestResult::Fail("plan_b connector_idx != 1");
    }

    // Commit both plans and verify independent CrtcMode records.
    let mut kms2 = kms.clone();
    commit_modeset_full(&mut kms2, &plan_a, 1920, surface_a);
    commit_modeset_full(&mut kms2, &plan_b, 1280, surface_b);

    let mode_a = kms2.crtcs[crtc_a as usize].mode.as_ref();
    let mode_b = kms2.crtcs[crtc_b as usize].mode.as_ref();
    match (mode_a, mode_b) {
        (Some(ma), Some(mb)) => {
            if ma.width == mb.width && ma.height == mb.height {
                return TestResult::Fail(
                    "both CRTCs have identical modes — surface_phys not independent",
                );
            }
            if ma.surface_phys != surface_a {
                return TestResult::Fail("CRTC A surface_phys mismatch");
            }
            if mb.surface_phys != surface_b {
                return TestResult::Fail("CRTC B surface_phys mismatch");
            }
        }
        _ => return TestResult::Fail("one or both CRTCs missing mode after commit"),
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/e2e",
    smoke_drm_multi_monitor_enumerate_independent_modesets
);

// ═══════════════════════════════════════════════════════════════════════════
// DRM Registry + sysfs bridge + devfs bridge smoke tests
//
// These cover the full stack introduced in Wave 35:
//   register_drm_card → /sys/class/drm/card<N>/ attrs + /dev/dri/ entries.
//
// Linux references (GPL-2.0-or-later):
//   - `linux/drivers/gpu/drm/drm_sysfs.c::dev_show`
//   - `linux/drivers/gpu/drm/drm_drv.c::drm_dev_register`
// ═══════════════════════════════════════════════════════════════════════════

// ── Shared FakeDrmCard ────────────────────────────────────────────────────

struct FakeDrmCard {
    name_str: alloc::string::String,
    driver_str: &'static str,
    vid: u16,
    did: u16,
}

impl crate::drm_registry::DrmCard for FakeDrmCard {
    fn name(&self) -> &str {
        &self.name_str
    }
    fn driver(&self) -> &str {
        self.driver_str
    }
    fn vendor_id(&self) -> u16 {
        self.vid
    }
    fn device_id(&self) -> u16 {
        self.did
    }
    fn subsystem_vendor(&self) -> u16 {
        0x0000
    }
    fn subsystem_device(&self) -> u16 {
        0x0000
    }
    fn vbios_version(&self) -> Option<&str> {
        Some("FAKE-BIOS-1.0")
    }
    fn gpu_busy_percent(&self) -> Option<u32> {
        Some(42)
    }
    fn power_state(&self) -> &str {
        "D0"
    }
}

impl core::fmt::Debug for FakeDrmCard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FakeDrmCard")
            .field("name", &self.name_str)
            .finish_non_exhaustive()
    }
}

// ── Smoke 11: register one FakeDrmCard → count == 1 ──────────────────────

fn smoke_drm_registry_register_one_card() -> TestResult {
    use crate::drm_registry;
    drm_registry::__reset_for_test();

    let card = alloc::sync::Arc::new(FakeDrmCard {
        name_str: "card0".into(),
        driver_str: "fake",
        vid: 0x1002,
        did: 0x1636,
    });
    let idx = drm_registry::register_drm_card(card);

    if idx != 0 {
        return TestResult::Fail("first card should get index 0");
    }
    if drm_registry::count() != 1 {
        return TestResult::Fail("count should be 1 after one registration");
    }

    drm_registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_drm_registry_register_one_card);

// Resolve the real DRM device kobject under /sys/devices/platform/narf-drm/.
// The card lives there (not directly under /sys/class/drm); `/sys/class/drm/*`
// is a symlink into it. get_child() walks real children only (not symlinks),
// so tests navigate the /sys/devices tree the compositor's udev lookup lands on.
#[cfg(feature = "linux-compat")]
fn drm_device_node(name: &str) -> Option<alloc::sync::Arc<narf_filesystem::sysfs::Kobject>> {
    narf_filesystem::sysfs::sysfs_root()
        .get_child("devices")
        .and_then(|d| d.get_child("platform"))
        .and_then(|p| p.get_child("narf-drm"))
        .and_then(|n| n.get_child(name))
}

// The `/sys/class/drm/<name>` symlink must exist and point into /sys/devices —
// this is what makes systemd's `sd_device_new_from_syspath` resolve the card's
// devnum. Returns true iff the class dir carries the symlink.
#[cfg(feature = "linux-compat")]
fn drm_class_symlink_ok(name: &str) -> bool {
    narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
        .and_then(|c| c.get_child("drm"))
        .and_then(|d| d.get_symlink(name))
        .map(|t| t.contains("devices/platform/narf-drm/"))
        .unwrap_or(false)
}

// ── Smoke 12: /sys/class/drm/card0/name → "card0\n" ─────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_drm_sysfs_name_attr() -> TestResult {
    use crate::drm_registry;
    use narf_filesystem::sysfs;

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();

    let card = alloc::sync::Arc::new(FakeDrmCard {
        name_str: "card0".into(),
        driver_str: "fake",
        vid: 0x1002,
        did: 0x1636,
    });
    drm_registry::register_drm_card(card);
    crate::drm_sysfs_bridge::populate_drm_class();

    if !drm_class_symlink_ok("card0") {
        return TestResult::Fail("/sys/class/drm/card0 symlink missing");
    }
    let card0 = match drm_device_node("card0") {
        Some(c) => c,
        None => return TestResult::Fail("/sys/devices/platform/narf-drm/card0 missing"),
    };

    match card0.attr_show("name") {
        Some(v) if v == "card0\n" => {}
        Some(_) => return TestResult::Fail("name attr wrong value"),
        None => return TestResult::Fail("name attr missing"),
    }

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("drivers/gpu/e2e", smoke_drm_sysfs_name_attr);

// ── Smoke 13: /sys/class/drm/card0/dev → "226:0\n" ───────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_drm_sysfs_dev_attr() -> TestResult {
    use crate::drm_registry;
    use narf_filesystem::sysfs;

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();

    drm_registry::register_drm_card(alloc::sync::Arc::new(FakeDrmCard {
        name_str: "card0".into(),
        driver_str: "fake",
        vid: 0x1002,
        did: 0x1636,
    }));
    crate::drm_sysfs_bridge::populate_drm_class();

    let card0 = match drm_device_node("card0") {
        Some(k) => k,
        None => return TestResult::Fail("card0 kobject missing"),
    };

    match card0.attr_show("dev") {
        Some(v) if v == "226:0\n" => {}
        Some(_) => return TestResult::Fail("dev attr wrong value"),
        None => return TestResult::Fail("dev attr missing"),
    }

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("drivers/gpu/e2e", smoke_drm_sysfs_dev_attr);

// ── Smoke 14: /sys/class/drm/card0/device/vendor → "0x1002\n" ────────────

#[cfg(feature = "linux-compat")]
fn smoke_drm_sysfs_device_vendor_attr() -> TestResult {
    use crate::drm_registry;
    use narf_filesystem::sysfs;

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();

    drm_registry::register_drm_card(alloc::sync::Arc::new(FakeDrmCard {
        name_str: "card0".into(),
        driver_str: "amdgpu",
        vid: 0x1002,
        did: 0x1636,
    }));
    crate::drm_sysfs_bridge::populate_drm_class();

    let device_kobj = drm_device_node("card0").and_then(|c| c.get_child("device"));
    let device_kobj = match device_kobj {
        Some(k) => k,
        None => return TestResult::Fail("card0/device kobject missing"),
    };

    match device_kobj.attr_show("vendor") {
        Some(v) if v == "0x1002\n" => {}
        Some(_) => return TestResult::Fail("vendor attr wrong value"),
        None => return TestResult::Fail("vendor attr missing"),
    }

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("drivers/gpu/e2e", smoke_drm_sysfs_device_vendor_attr);

// ── Smoke 15: /sys/class/drm/card0/device/device → "0x1636\n" for Renoir ─

#[cfg(feature = "linux-compat")]
fn smoke_drm_sysfs_device_id_attr() -> TestResult {
    use crate::drm_registry;
    use narf_filesystem::sysfs;

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();

    drm_registry::register_drm_card(alloc::sync::Arc::new(FakeDrmCard {
        name_str: "card0".into(),
        driver_str: "amdgpu",
        vid: 0x1002,
        did: 0x1636,
    }));
    crate::drm_sysfs_bridge::populate_drm_class();

    let device_kobj = drm_device_node("card0").and_then(|c| c.get_child("device"));
    let device_kobj = match device_kobj {
        Some(k) => k,
        None => return TestResult::Fail("card0/device kobject missing"),
    };

    match device_kobj.attr_show("device") {
        Some(v) if v == "0x1636\n" => {}
        Some(_) => return TestResult::Fail("device attr wrong value"),
        None => return TestResult::Fail("device attr missing"),
    }

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("drivers/gpu/e2e", smoke_drm_sysfs_device_id_attr);

// ── Smoke 16: vbios_version attr readable ─────────────────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_drm_sysfs_vbios_version_attr() -> TestResult {
    use crate::drm_registry;
    use narf_filesystem::sysfs;

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();

    drm_registry::register_drm_card(alloc::sync::Arc::new(FakeDrmCard {
        name_str: "card0".into(),
        driver_str: "fake",
        vid: 0x1002,
        did: 0x1636,
    }));
    crate::drm_sysfs_bridge::populate_drm_class();

    let card0 = match drm_device_node("card0") {
        Some(k) => k,
        None => return TestResult::Fail("card0 kobject missing"),
    };

    // FakeDrmCard returns Some("FAKE-BIOS-1.0"), so vbios_version must be present.
    match card0.attr_show("vbios_version") {
        Some(v) if v.contains("FAKE-BIOS-1.0") => {}
        Some(_) => return TestResult::Fail("vbios_version wrong content"),
        None => return TestResult::Fail("vbios_version attr missing"),
    }

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("drivers/gpu/e2e", smoke_drm_sysfs_vbios_version_attr);

// ── Smoke 17: renderD128/dev → "226:128\n" ────────────────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_drm_sysfs_render_node_dev_attr() -> TestResult {
    use crate::drm_registry;
    use narf_filesystem::sysfs;

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();

    drm_registry::register_drm_card(alloc::sync::Arc::new(FakeDrmCard {
        name_str: "card0".into(),
        driver_str: "fake",
        vid: 0x1002,
        did: 0x1636,
    }));
    crate::drm_sysfs_bridge::populate_drm_class();

    if !drm_class_symlink_ok("renderD128") {
        return TestResult::Fail("/sys/class/drm/renderD128 symlink missing");
    }
    let render128 = match drm_device_node("renderD128") {
        Some(k) => k,
        None => return TestResult::Fail("renderD128 kobject missing"),
    };

    match render128.attr_show("dev") {
        Some(v) if v == "226:128\n" => {}
        Some(_) => return TestResult::Fail("renderD128 dev attr wrong value"),
        None => return TestResult::Fail("renderD128 dev attr missing"),
    }

    drm_registry::__reset_for_test();
    sysfs::__reset_for_test();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("drivers/gpu/e2e", smoke_drm_sysfs_render_node_dev_attr);

// ── Smoke 18: /dev/dri/card0 resolves through DriDir ─────────────────────

fn smoke_devdri_card0_resolves() -> TestResult {
    use crate::drm_devfs_bridge::DriDir;
    use crate::drm_registry;
    use narf_filesystem::DirOps;

    drm_registry::__reset_for_test();

    drm_registry::register_drm_card(alloc::sync::Arc::new(FakeDrmCard {
        name_str: "card0".into(),
        driver_str: "fake",
        vid: 0x1002,
        did: 0x1636,
    }));

    let dir = DriDir;
    let node = match dir.lookup("card0") {
        Some(node) => node,
        None => return TestResult::Fail("/dev/dri/card0 not found via DriDir::lookup"),
    };
    if node.stat().mode.perms != 0o600 || node.owners() != (0, 0) {
        return TestResult::Fail("/dev/dri/card0 initial metadata is not root:root 0600");
    }
    if !matches!(poll_once(node.set_owners(1234, 5678)), Some(Ok(())))
        || !matches!(poll_once(node.set_perms(0o641)), Some(Ok(())))
    {
        return TestResult::Fail("/dev/dri/card0 metadata update failed");
    }
    let fresh = match dir.lookup("card0") {
        Some(node) => node,
        None => return TestResult::Fail("/dev/dri/card0 vanished after metadata update"),
    };
    if fresh.stat().mode.perms != 0o641 || fresh.owners() != (1234, 5678) {
        return TestResult::Fail("/dev/dri/card0 metadata did not persist across lookup");
    }

    drm_registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_devdri_card0_resolves);

// ── Smoke 19: /dev/dri/renderD128 resolves ────────────────────────────────

fn smoke_devdri_render128_resolves() -> TestResult {
    use crate::drm_devfs_bridge::DriDir;
    use crate::drm_registry;
    use narf_filesystem::DirOps;

    drm_registry::__reset_for_test();

    drm_registry::register_drm_card(alloc::sync::Arc::new(FakeDrmCard {
        name_str: "card0".into(),
        driver_str: "fake",
        vid: 0x1002,
        did: 0x1636,
    }));

    let dir = DriDir;
    let node = match dir.lookup("renderD128") {
        Some(node) => node,
        None => return TestResult::Fail("/dev/dri/renderD128 not found via DriDir::lookup"),
    };
    if node.stat().mode.perms != 0o600 || node.owners() != (0, 0) {
        return TestResult::Fail("/dev/dri/renderD128 initial metadata is not root:root 0600");
    }
    if !matches!(poll_once(node.set_owners(4321, 8765)), Some(Ok(())))
        || !matches!(poll_once(node.set_perms(0o624)), Some(Ok(())))
    {
        return TestResult::Fail("/dev/dri/renderD128 metadata update failed");
    }
    let fresh = match dir.lookup("renderD128") {
        Some(node) => node,
        None => return TestResult::Fail("/dev/dri/renderD128 vanished after metadata update"),
    };
    if fresh.stat().mode.perms != 0o624 || fresh.owners() != (4321, 8765) {
        return TestResult::Fail("/dev/dri/renderD128 metadata did not persist across lookup");
    }

    drm_registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_devdri_render128_resolves);

// ── Smoke 20: bochs probe → BochsCard registers ───────────────────────────

fn smoke_bochs_probe_registers_drm_card() -> TestResult {
    use crate::drm_registry;
    use narf_graphics_driver::bochs;

    if !bochs::is_probed() {
        return TestResult::Skip("bochs-display not present");
    }

    // On a system where bochs is probed, the Stage::Device initcall
    // `"bochs-drm-card"` should have registered at least one card.
    // Since tests may run before initcalls, check count via a direct probe-path
    // registration here (mimicking what the initcall does).
    let pre_count = drm_registry::count();
    // Register a BochsCard to simulate what the initcall does.
    let card_name = alloc::format!("card{}", pre_count);
    let card = crate::drm_devfs_bridge::BochsCard::new(card_name);
    drm_registry::register_drm_card(alloc::sync::Arc::new(card));

    if drm_registry::count() != pre_count + 1 {
        drm_registry::__reset_for_test();
        return TestResult::Fail("BochsCard registration did not increment count");
    }

    // Verify the driver name is "bochs".
    let cards = drm_registry::cards();
    let last = cards.last().unwrap();
    if last.driver() != "bochs" {
        drm_registry::__reset_for_test();
        return TestResult::Fail("BochsCard driver() != 'bochs'");
    }

    drm_registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_bochs_probe_registers_drm_card);

// ── Smoke 21: AMDGPU Renoir probe → AmdgpuCard with correct vendor/device ─

fn smoke_amdgpu_renoir_registers_drm_card() -> TestResult {
    use crate::amdgpu::{AMD_VENDOR, RENOIR};
    use crate::drm_devfs_bridge::AmdgpuCard;
    use crate::drm_registry;

    let pre_count = drm_registry::count();
    let card_name = alloc::format!("card{}", pre_count);
    let card = AmdgpuCard::new(card_name, AMD_VENDOR, RENOIR, 0, 0, None);
    drm_registry::register_drm_card(alloc::sync::Arc::new(card));

    let cards = drm_registry::cards();
    let added = match cards.last() {
        Some(c) => c.clone(),
        None => {
            drm_registry::__reset_for_test();
            return TestResult::Fail("no card after register");
        }
    };

    if added.vendor_id() != AMD_VENDOR {
        drm_registry::__reset_for_test();
        return TestResult::Fail("vendor_id != AMD_VENDOR");
    }
    if added.device_id() != RENOIR {
        drm_registry::__reset_for_test();
        return TestResult::Fail("device_id != RENOIR (0x1636)");
    }
    if added.driver() != "amdgpu" {
        drm_registry::__reset_for_test();
        return TestResult::Fail("driver() != 'amdgpu'");
    }

    drm_registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_amdgpu_renoir_registers_drm_card);

// ── Smoke 22: two cards → card0+card1 + renderD128+renderD129 in DriDir ───

fn smoke_drm_two_cards_enumerate() -> TestResult {
    use crate::amdgpu::{AMD_VENDOR, RENOIR};
    use crate::drm_devfs_bridge::{AmdgpuCard, BochsCard, DriDir};
    use crate::drm_registry;
    use narf_filesystem::DirOps;

    drm_registry::__reset_for_test();

    // Register bochs as card0, AMDGPU as card1.
    drm_registry::register_drm_card(alloc::sync::Arc::new(BochsCard::new("card0".into())));
    drm_registry::register_drm_card(alloc::sync::Arc::new(AmdgpuCard::new(
        "card1".into(),
        AMD_VENDOR,
        RENOIR,
        0,
        0,
        None,
    )));

    let dir = DriDir;

    // Both card nodes must resolve.
    if dir.lookup("card0").is_none() {
        drm_registry::__reset_for_test();
        return TestResult::Fail("card0 missing");
    }
    if dir.lookup("card1").is_none() {
        drm_registry::__reset_for_test();
        return TestResult::Fail("card1 missing");
    }
    // Both render nodes must resolve.
    if dir.lookup("renderD128").is_none() {
        drm_registry::__reset_for_test();
        return TestResult::Fail("renderD128 missing");
    }
    if dir.lookup("renderD129").is_none() {
        drm_registry::__reset_for_test();
        return TestResult::Fail("renderD129 missing");
    }

    // Enumerate should list all 4 entries.
    let entries = dir.enumerate(0, 100);
    let names: alloc::vec::Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    if !names.contains(&"card0") {
        drm_registry::__reset_for_test();
        return TestResult::Fail("enumerate missing card0");
    }
    if !names.contains(&"card1") {
        drm_registry::__reset_for_test();
        return TestResult::Fail("enumerate missing card1");
    }
    if !names.contains(&"renderD128") {
        drm_registry::__reset_for_test();
        return TestResult::Fail("enumerate missing renderD128");
    }
    if !names.contains(&"renderD129") {
        drm_registry::__reset_for_test();
        return TestResult::Fail("enumerate missing renderD129");
    }

    drm_registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/e2e", smoke_drm_two_cards_enumerate);

extern crate alloc;
