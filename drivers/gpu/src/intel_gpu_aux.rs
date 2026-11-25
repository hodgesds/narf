//! Intel DDI AUX channel MMIO transport — Gen12 (TGL/ADL/RPL).
//!
//! Bridges the vendor-neutral [`dp_aux`] framing layer to the Intel
//! `DDI_AUX_CTL` / `DDI_AUX_DATA` register block. The encoded wire
//! bytes from `dp_aux::encode_request` go into `DDI_AUX_DATA_*`;
//! the controller drives them out, captures the reply, and we
//! decode it via `dp_aux::decode_response`.
//!
//! Reference: **Tiger Lake PRM Vol. 12 §"DDI_AUX_CTL"** and
//! §"DDI_AUX_DATA". Cross-checked against Linux
//! `drivers/gpu/drm/i915/display/intel_dp_aux.c::intel_dp_aux_xfer`
//! (GPL-2.0-or-later — compatible with NARF's post-2026-05-20
//! relicense).
//!
//! ## Register block
//!
//! `DDI_AUX_CTL_*` sits at MMIO offset `0x64010` for DDI A,
//! `0x64110` for DDI B, etc. (each port is +0x100). The data
//! payload lives in five consecutive 32-bit data registers at
//! offset `+0x14` through `+0x24`, giving up to 20 bytes (the
//! 4-byte AUX header + 16-byte payload that the DP spec caps
//! every transaction at).
//!
//! ## Transaction shape
//!
//! 1. Pack request bytes (already in wire format from
//!    `dp_aux::encode_request`) into the AUX_DATA dwords —
//!    big-endian, since AUX is byte-oriented but the registers
//!    are little-endian dwords. `byte0..3` -> `data[0][31:0]`
//!    with `byte0` in `[31:24]` and `byte3` in `[7:0]`.
//! 2. Write `DDI_AUX_CTL` with the SEND bit, message-size field,
//!    normal sync length (32 pulses) and fast-wake sync length (18).
//! 3. Poll SEND_BUSY for clear (transaction complete) or
//!    `done`/`time-out-error`/`receive-error` flags.
//! 4. Reply byte count is published in `MSGSIZE` field of
//!    DDI_AUX_CTL after completion; read that many bytes back
//!    from the AUX_DATA dwords and hand them to
//!    `dp_aux::decode_response`.
//!
//! ## Retries
//!
//! DP-spec retry on `DEFER` is handled by the [`dp_aux`] layer
//! (it expects the transport to bubble the status up). The MMIO
//! transport here only does a low-level hardware retry on AUX
//! protocol errors (timeout / receive error), capped at 3
//! attempts — matches i915 behavior.

use core::sync::atomic::{compiler_fence, Ordering};

// Every Intel AUX user, including independently retained backlight and KMS
// PSR owners, shares this physical transport exclusion. Try-lock refuses a
// concurrent/reentrant caller without spinning behind a polled transaction.
// Keep the encoded request here across hardware retries.
static AUX_TRANSACTION: narf_lib::mutex::Mutex<[u8; 20]> = narf_lib::mutex::Mutex::new([0; 20]);

use crate::dp_aux::{
    decode_response, encode_request, AuxChannel, AuxError, AuxRequest, AuxResponse,
};
use crate::intel_gpu_ddi::Ddi;

/// `DDI_AUX_CTL` offset relative to the DDI port base.
pub const DDI_AUX_CTL_OFFSET: u64 = 0x0010;
/// `DDI_AUX_DATA_<port>_<n>` base offset. Five dwords (0x14, 0x18,
/// 0x1C, 0x20, 0x24) carrying up to 20 bytes.
pub const DDI_AUX_DATA_OFFSET: u64 = 0x0014;
/// Number of AUX_DATA dwords per port. 5 dwords × 4 bytes = 20
/// bytes — the DP-spec maximum AUX transaction (4-byte header +
/// 16-byte payload).
pub const DDI_AUX_DATA_DWORDS: usize = 5;

// ── DDI_AUX_CTL bit fields (PRM Vol. 12 §"DDI_AUX_CTL") ──────────

/// `[31]` — Send Busy. Write 1 to issue the transaction; reads 0
/// when the controller has finished sending and either received a
/// reply or timed out.
pub const AUX_CTL_SEND_BUSY: u32 = 1 << 31;
/// `[30]` — Done. RW1C; set when the transaction completed
/// (regardless of ack/nack). Clear by writing 1 before issuing a
/// new transaction. Some platforms also clear it on a SEND_BUSY
/// write; clearing explicitly avoids latched stale values.
pub const AUX_CTL_DONE: u32 = 1 << 30;
/// `[29]` — Interrupt on Done. We poll, so leave clear.
pub const AUX_CTL_INTERRUPT_ON_DONE: u32 = 1 << 29;
/// `[27:26]` selects the maximum hardware timeout, 4 ms on ICL and later.
pub const AUX_CTL_TIMEOUT_MAX: u32 = 0b11 << 26;
/// Historical name for the maximum timeout encoding (1.6 ms on SKL–GLK).
pub const AUX_CTL_TIMEOUT_1600US: u32 = AUX_CTL_TIMEOUT_MAX;
/// `[28]` — Time-Out Error. RW1C. Set on AUX time-out (no reply
/// within the configured window).
pub const AUX_CTL_TIMEOUT_ERROR: u32 = 1 << 28;
/// `[25]` — Receive Error. RW1C. Set on framing / parity error in
/// the reply.
pub const AUX_CTL_RECEIVE_ERROR: u32 = 1 << 25;
/// `[24:20]` — Message Size. Number of valid bytes in
/// AUX_DATA (output for sends, valid byte count of reply on
/// receive). Five bits: a maximum-size transaction is a
/// 20-byte send and a 17-byte reply (status + 16 payload),
/// neither of which a 4-bit field could represent. Layout
/// cross-checked against i915 `intel_dp_aux_regs.h`
/// (`DP_AUX_CH_CTL_MESSAGE_SIZE_MASK = REG_GENMASK(24, 20)`,
/// `TIME_OUT_ERROR = REG_BIT(28)`, `RECEIVE_ERROR =
/// REG_BIT(25)`); the earlier 4-bit mask silently truncated
/// every reply longer than 15 bytes to `len & 0xF`, so the
/// 16-byte DPCD caps read (17-byte reply) decoded as a
/// 1-byte reply and failed `ShortReply` — every DP connect
/// died in `read_caps`.
pub const AUX_CTL_MSGSIZE_SHIFT: u32 = 20;
pub const AUX_CTL_MSGSIZE_MASK: u32 = 0x1F << AUX_CTL_MSGSIZE_SHIFT;

// Raw constants exported by earlier drivers. None is a Gen12 timing field.
#[deprecated(note = "pre-SKL field, reserved on Gen12")]
pub const AUX_CTL_PRECHARGE_16: u32 = 0b1000 << 16;
#[deprecated(note = "overlaps message size, use the SKL+ sync fields")]
pub const AUX_CTL_SYNC_PULSES_32: u32 = 32 << 16;
#[deprecated(note = "sets TBT_IO on Gen12, use the SKL+ sync fields")]
pub const AUX_CTL_BITCLK_DIVIDER_DEFAULT: u32 = 2222;

/// Control-word profile for one AUX transport. Both use SKL+ sync fields.
/// Xe-LPDP also preserves the channel power request across transfers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuxCtlProfile {
    /// Gen12 native AUX on an eDP, DisplayPort or USB-C DP Alt Mode route.
    Gen12,
    /// Xe-LPDP (MTL) control word; `tbt_io` selects the TBT AUX IO.
    XeLpdp {
        /// `DP_AUX_CH_CTL_TBT_IO` (bit 11): set only in TBT-alt mode.
        tbt_io: bool,
    },
}

/// `XELPDP_DP_AUX_CH_CTL_POWER_REQUEST` (bit 19, MTL+).
pub const XELPDP_AUX_CH_CTL_POWER_REQUEST: u32 = 1 << 19;
/// `XELPDP_DP_AUX_CH_CTL_POWER_STATUS` (bit 18, MTL+).
pub const XELPDP_AUX_CH_CTL_POWER_STATUS: u32 = 1 << 18;
/// `DP_AUX_CH_CTL_TBT_IO` (bit 11, ICL+).
pub const AUX_CTL_TBT_IO: u32 = 1 << 11;
/// `DP_AUX_CH_CTL_AUX_AKSV_SELECT` (bit 15): the controller sends the
/// hardware HDCP Aksv after the request header in place of the data
/// registers (`intel_dp_aux_xfer_flags`).
pub const AUX_CTL_AKSV_SELECT: u32 = 1 << 15;
/// `DP_AUX_HDCP_AKSV`, the DPCD address whose native writes carry
/// [`AUX_CTL_AKSV_SELECT`].
pub const DP_AUX_HDCP_AKSV: u32 = 0x68007;
/// `DP_AUX_CH_CTL_FW_SYNC_PULSE_SKL(c)` field (bits 9:5) holds c - 1.
const fn aux_fw_sync_pulse_skl(count: u32) -> u32 {
    ((count - 1) & 0x1F) << 5
}
/// `DP_AUX_CH_CTL_SYNC_PULSE_SKL(c)` field (bits 4:0) holds c - 1.
const fn aux_sync_pulse_skl(count: u32) -> u32 {
    (count - 1) & 0x1F
}
// skl_get_aux_send_ctl with the normal 16 + 16 sync pulses and the
// default 10 + 8 fast-wake pulses. The polled driver leaves IRQs disabled.
const fn native_aux_send_ctl(send_bytes: u32) -> u32 {
    AUX_CTL_SEND_BUSY
        | AUX_CTL_DONE
        | AUX_CTL_TIMEOUT_ERROR
        | AUX_CTL_TIMEOUT_MAX
        | AUX_CTL_RECEIVE_ERROR
        | ((send_bytes << AUX_CTL_MSGSIZE_SHIFT) & AUX_CTL_MSGSIZE_MASK)
        | aux_fw_sync_pulse_skl(18)
        | aux_sync_pulse_skl(32)
}

/// Build the Xe-LPDP send word while keeping the channel power request asserted.
pub const fn xelpdp_aux_send_ctl(send_bytes: u32, tbt_io: bool) -> u32 {
    native_aux_send_ctl(send_bytes)
        | XELPDP_AUX_CH_CTL_POWER_REQUEST
        | if tbt_io { AUX_CTL_TBT_IO } else { 0 }
}

/// Maximum hardware-retry attempts on TIMEOUT / RECEIVE error.
/// Beyond 3 we surface the error to the caller; DEFER-status
/// retries are handled by the dp_aux layer above.
const HW_RETRIES: u32 = 3;

/// MMIO transport implementing the `AuxChannel` trait for an Intel
/// DDI port. Holds a borrowed handle to the BAR0 MMIO window plus
/// the port selector — does not own state across transactions.
pub struct IntelAux<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    ddi: Ddi,
    /// Absolute BAR0 offset of this port's AUX register block
    /// (the CTL register sits at `base + DDI_AUX_CTL_OFFSET`).
    /// On Gen12 this is `ddi.base()`; Xe-LPG ports have their
    /// own AUX bases (#1016) and construct via
    /// [`IntelAux::with_base`].
    base: u64,
    /// Control-word encoding (Gen12 unless built by [`IntelAux::xelpdp`]).
    profile: AuxCtlProfile,
    /// The Gen9 `DC_off` well every transfer holds (`intel_dp_aux_xfer`'s
    /// AUX power domain; AUX_A-D are Gen9 `dc_off` domains): the production
    /// service, inert unless `narf.intel.gen9_dc=1` installed it on a Gen9
    /// display, or a fixture's own ([`IntelAux::with_gen9_dc`]).
    gen9_dc: &'a dyn crate::intel_gpu_gen9_dc_states::Gen9DcOff,
    /// The display-35 `DC_off` well every transfer on an LT-PHY window
    /// holds: `xe3plpd_pwdoms_dc_off` lists every AUX channel, and
    /// `intel_dp_aux_xfer` holds the channel's AUX domain across the
    /// transfer. The production service, inert unless the Nova Lake-S
    /// route installed it, or a fixture's own ([`IntelAux::with_dc_off`]).
    dc_off: &'a dyn crate::intel_gpu_dc_states::DcOff,
}

impl<'a, M: MmioWindow + ?Sized> core::fmt::Debug for IntelAux<'a, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelAux").field("ddi", &self.ddi).finish()
    }
}

/// The display source an external session programs, from the exact owned
/// PCI mapping: the Gen12 family, or the Gen11 or Gen9 sub-platform (Gen9
/// with the DDI SKU family its buffer tables select on).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceFamily {
    Gen12(crate::intel_gpu_gt::Gen12Platform),
    Gen11(crate::intel_gpu_gt::Gen11Platform),
    Gen9 {
        platform: crate::intel_gpu_gt::Gen9Platform,
        sku: crate::intel_gpu_gen9_ddi::SkuFamily,
    },
}

impl SourceFamily {
    /// The family `mmio` reports, `None` when it reports none (a session
    /// must then refuse).
    pub fn of<M: MmioWindow + ?Sized>(mmio: &M) -> Option<Self> {
        mmio.gen12_display_family()
            .map(Self::Gen12)
            .or_else(|| mmio.gen11_display_platform().map(Self::Gen11))
            .or_else(|| {
                mmio.gen9_display_platform()
                    .map(|(platform, sku)| Self::Gen9 { platform, sku })
            })
    }

    /// The Gen12 family, for the Gen12-only paths (VRR, the external stop
    /// proof).
    pub const fn gen12(self) -> Option<crate::intel_gpu_gt::Gen12Platform> {
        match self {
            Self::Gen12(family) => Some(family),
            _ => None,
        }
    }
}

/// Minimal MMIO-window interface the transport needs. Lets us
/// inject mocks in tests without depending on the kernel's real
/// `Bar0` type. Real callers wrap `narf_drivers_pci`'s mapped BAR
/// in an adapter that implements this.
pub trait MmioWindow {
    /// Immutable source-family metadata for this exact owned PCI mapping.
    /// Physical adapters derive it from the known PCI-ID table, never broad
    /// Generation::AlderLake. None permits diagnostics, but source-dependent
    /// external activation must refuse. This is not current MMIO authority.
    fn gen12_display_family(&self) -> Option<crate::intel_gpu_gt::Gen12Platform> {
        None
    }
    /// The Gen11 sub-platform of this exact owned PCI mapping, from the
    /// PCI-ID table like `gen12_display_family`; `None` on every other
    /// source.
    fn gen11_display_platform(&self) -> Option<crate::intel_gpu_gt::Gen11Platform> {
        None
    }
    /// The Gen9 sub-platform and DDI SKU family (`sku_family_for_did`) of
    /// this exact owned PCI mapping; `None` on every other source.
    fn gen9_display_platform(
        &self,
    ) -> Option<(
        crate::intel_gpu_gt::Gen9Platform,
        crate::intel_gpu_gen9_ddi::SkuFamily,
    )> {
        None
    }
    /// The C20 HDMI `tx[1]` word for this exact owned PCI mapping
    /// (`intel_gpu_xelpg_hdmi::c20_hdmi_tx_cfg1`), when its platform fact
    /// is known; `None` keeps the C20 HDMI clocks table-only.
    fn c20_hdmi_tx_cfg1(&self) -> Option<u16> {
        None
    }
    /// Whether this exact owned PCI mapping is a Tiger Lake UY
    /// (GT2) part (`intel_gpu_gen12_combo_phy::is_tgl_uy`): on
    /// such parts the combo-PHY table selection uses the UY HBR2
    /// table above 270 MHz (Linux `tgl_get_combo_buf_trans_dp`,
    /// `display->platform.tigerlake_uy`). Physical adapters derive
    /// it from the PCI device ID, like `gen12_display_family`;
    /// the default is false (the standard TGL table). Wrappers
    /// between a physical adapter and the modeset forward it.
    fn tgl_uy(&self) -> bool {
        false
    }
    /// Observed native ISA-bridge identity selects this source HPD bank.
    /// Family metadata alone never synthesizes a south-display controller.
    fn gen12_hpd_profile(&self) -> Option<crate::intel_gpu_dp::HpdProfile> {
        None
    }
    /// Current authority for mask registers where all-ones is a valid value.
    fn display_access_ok(&self) -> bool {
        true
    }
    /// Whether this window drives display-30 (Xe3_LPD) Cx0 PHYs:
    /// `intel_cx0_phy.c::__intel_cx0_{read,write}_once` reset the message
    /// bus after every completed transaction only on display < 30, and
    /// `intel_cx0_phy_regs.h::XELPDP_DDI_CLOCK_SELECT_MASK` widens to 16:12
    /// on display >= 30. Only the Panther Lake display view
    /// (`intel_gpu_xe3lpd::PortView`) answers `true`; every wrapper that
    /// sits between it and the PHY code forwards it.
    fn cx0_xe3(&self) -> bool {
        false
    }
    /// Whether DDI B's Cx0 PHY is a C20 (`intel_encoder_is_c10phy` false
    /// for PHY B): Panther Lake 30.00 only. Meteor and Lunar Lake put a C10
    /// behind PHY B, and so does Wildcat Lake (`phy <= PHY_B`). Only the
    /// Panther Lake external view answers `true`; every wrapper between it
    /// and the PHY code forwards it.
    fn cx0_c20_port_b(&self) -> bool {
        false
    }
    /// Whether this exact source platform has Linux's LT PHY. This is a
    /// platform fact, not a display-version test: current Linux defines
    /// `HAS_LT_PHY(display)` as `platform.novalake`, while display-30
    /// Panther/Wildcat Lake still use C10/C20.
    fn has_lt_phy(&self) -> bool {
        false
    }
    /// Read a 32-bit register at byte offset `off` within the
    /// MMIO window.
    fn read32(&self, off: u64) -> u32;
    /// Write a 32-bit register at byte offset `off`.
    fn write32(&self, off: u64, val: u32);
}

impl<'a, M: MmioWindow + ?Sized> IntelAux<'a, M> {
    /// Create a transport for `ddi` over the BAR0 window `mmio`.
    pub fn new(mmio: &'a M, ddi: Ddi) -> Self {
        Self {
            base: ddi.base(),
            mmio,
            ddi,
            profile: AuxCtlProfile::Gen12,
            gen9_dc: &crate::intel_gpu_gen9_dc_states::ServiceDcOff,
            dc_off: &crate::intel_gpu_dc_states::Xe3pLpdDcOff,
        }
    }

    /// Hold `dc` as the display-35 `DC_off` well across each transfer on
    /// an LT-PHY window instead of the production service.
    pub fn with_dc_off(mut self, dc: &'a dyn crate::intel_gpu_dc_states::DcOff) -> Self {
        self.dc_off = dc;
        self
    }

    /// Hold `dc` as the Gen9 `DC_off` well across each transfer instead of
    /// the production service.
    pub fn with_gen9_dc(mut self, dc: &'a dyn crate::intel_gpu_gen9_dc_states::Gen9DcOff) -> Self {
        self.gen9_dc = dc;
        self
    }

    /// Create a display-14 (Xe-LPG/MTL) transport over an explicit AUX
    /// register base, non-TBT IO.
    ///
    /// Xe-LPG ports do not share the Gen12 DDI register stride: their
    /// AUX blocks sit at per-port absolute offsets (see
    /// `intel_gpu_xelpg::XeLpgPort::aux_base`). Every caller of this
    /// constructor is a display-14 port, so it writes the
    /// [`AuxCtlProfile::XeLpdp`] control word: the channel's
    /// `XELPDP_DP_AUX_CH_CTL_POWER_REQUEST` (bit 19, raised by
    /// `xelpdp_aux_power_well_enable`) is preserved on every write, as
    /// `intel_dp_aux.c::skl_get_aux_send_ctl` does for DISPLAY_VER >= 14.
    /// Gen12 callers use [`IntelAux::new`] for native AUX.
    pub fn with_base(mmio: &'a M, base: u64) -> Self {
        Self::xelpdp(mmio, base, false)
    }

    /// Create an Xe-LPDP (MTL) transport over an explicit AUX base with
    /// the source control-word encoding ([`AuxCtlProfile::XeLpdp`]). The
    /// caller owns the port's AUX power request
    /// (`intel_gpu_xelpg_tc::aux_power_enable`); every control write here
    /// keeps it asserted.
    pub fn xelpdp(mmio: &'a M, base: u64, tbt_io: bool) -> Self {
        Self {
            mmio,
            ddi: Ddi::A,
            base,
            profile: AuxCtlProfile::XeLpdp { tbt_io },
            gen9_dc: &crate::intel_gpu_gen9_dc_states::ServiceDcOff,
            dc_off: &crate::intel_gpu_dc_states::Xe3pLpdDcOff,
        }
    }

    /// The control-word profile this transport writes.
    pub fn profile(&self) -> AuxCtlProfile {
        self.profile
    }

    /// Absolute MMIO offset of this port's `DDI_AUX_CTL`.
    fn aux_ctl_off(&self) -> u64 {
        self.base + DDI_AUX_CTL_OFFSET
    }

    /// Absolute MMIO offset of `DDI_AUX_DATA[n]` for this port.
    fn aux_data_off(&self, n: usize) -> u64 {
        self.base + DDI_AUX_DATA_OFFSET + (n as u64) * 4
    }

    /// Pack a wire-format AUX request into the AUX_DATA dwords.
    /// Byte 0 lands in the high byte of `DATA[0]`; consecutive
    /// bytes fill toward the low byte of `DATA[4]`.
    fn write_data(&self, wire: &[u8]) {
        // Per i915 / PRM: AUX_DATA is laid out big-endian within
        // each 32-bit register — byte 0 is bits [31:24] of
        // DATA[0]; byte 3 is bits [7:0] of DATA[0]; byte 4 starts
        // DATA[1] in [31:24]; and so on.
        for (i, dword) in wire.chunks(4).enumerate() {
            if i >= DDI_AUX_DATA_DWORDS {
                break;
            }
            let mut v: u32 = 0;
            for (b, &byte) in dword.iter().enumerate() {
                v |= (byte as u32) << (24 - 8 * b);
            }
            self.mmio.write32(self.aux_data_off(i), v);
        }
    }

    /// Read `n` reply bytes from the AUX_DATA dwords back into
    /// `buf`. Uses the same big-endian byte order as
    /// `write_data`. Returns the number of bytes actually copied
    /// (capped at `buf.len()`).
    fn read_data(&self, n: usize, buf: &mut [u8]) -> usize {
        let want = n.min(buf.len());
        let mut got = 0;
        for i in 0..DDI_AUX_DATA_DWORDS {
            if got >= want {
                break;
            }
            let v = self.mmio.read32(self.aux_data_off(i));
            for b in 0..4 {
                if got >= want {
                    break;
                }
                buf[got] = ((v >> (24 - 8 * b)) & 0xFF) as u8;
                got += 1;
            }
        }
        got
    }

    /// Spin until SEND_BUSY clears or 5 ms has elapsed. Returns
    /// the final DDI_AUX_CTL value. The software deadline gives the
    /// controller time to report its 4 ms hardware timeout.
    ///
    /// We can't use `narf_time::Deadline` here because it would
    /// allocate; instead spin on a bounded RDTSC budget. The
    /// caller-visible "timeout" status comes from the
    /// AUX_CTL.TIMEOUT_ERROR bit, not from this spin's expiry.
    fn wait_send_complete(&self, ctl_initial: u32) -> u32 {
        // 5 ms, converted through the calibrated fixed-point scale —
        // so it is 5 ms at the ACTUAL TSC rate rather than at a
        // truncated integer GHz (which on a 3.293 GHz part read back
        // as 3 and shortened every such budget by ~9%).
        let budget = narf_time::wall::ns_to_cycles(5_000_000);
        let start = narf_time::now_cycles();
        let mut ctl = ctl_initial;
        while ctl & AUX_CTL_SEND_BUSY != 0 {
            // read_poll_timeout: sample expiry before the read, so the read
            // that ends a timed-out wait follows the deadline. A transfer
            // done by then is returned, not reported as still busy.
            let expired = narf_time::now_cycles().wrapping_sub(start) > budget;
            core::hint::spin_loop();
            ctl = self.mmio.read32(self.aux_ctl_off());
            if expired {
                break;
            }
        }
        ctl
    }

    /// Issue one request and return the byte count in the reply registers.
    /// `flags` joins the send control word (`aux_send_ctl_flags`).
    fn xfer_once(&self, wire: &[u8], flags: u32) -> Result<usize, AuxError> {
        if wire.len() > 20 {
            return Err(AuxError::TooLong);
        }
        // Clear any latched done/error bits from a prior transaction.
        // RW1C — write the bits we want cleared (don't clear SEND_BUSY).
        // Xe-LPDP keeps its AUX power request asserted on every write.
        let keep = match self.profile {
            AuxCtlProfile::Gen12 => 0,
            AuxCtlProfile::XeLpdp { .. } => XELPDP_AUX_CH_CTL_POWER_REQUEST,
        };
        self.mmio.write32(
            self.aux_ctl_off(),
            AUX_CTL_DONE | AUX_CTL_TIMEOUT_ERROR | AUX_CTL_RECEIVE_ERROR | keep,
        );

        self.write_data(wire);
        compiler_fence(Ordering::SeqCst);

        // Compose the control register: send + msgsize + timing.
        let ctl = match self.profile {
            AuxCtlProfile::Gen12 => native_aux_send_ctl(wire.len() as u32),
            AuxCtlProfile::XeLpdp { tbt_io } => xelpdp_aux_send_ctl(wire.len() as u32, tbt_io),
        } | flags;
        self.mmio.write32(self.aux_ctl_off(), ctl);

        // Poll for completion.
        let final_ctl = self.wait_send_complete(ctl);

        if final_ctl & AUX_CTL_TIMEOUT_ERROR != 0 {
            return Err(AuxError::ShortReply);
        }
        if final_ctl & AUX_CTL_RECEIVE_ERROR != 0 {
            return Err(AuxError::UnknownStatus);
        }
        if final_ctl & AUX_CTL_SEND_BUSY != 0 {
            // Spin expired without DONE — hardware really stuck.
            return Err(AuxError::ShortReply);
        }

        let reply_total = ((final_ctl & AUX_CTL_MSGSIZE_MASK) >> AUX_CTL_MSGSIZE_SHIFT) as usize;
        // One status byte and at most 16 payload bytes.
        if reply_total == 0 {
            return Err(AuxError::ShortReply);
        }
        if reply_total > 17 {
            return Err(AuxError::TooLong);
        }
        Ok(reply_total)
    }
}

impl<'a, M: MmioWindow + ?Sized> AuxChannel for IntelAux<'a, M> {
    fn transact<'b>(
        &mut self,
        req: &AuxRequest<'_>,
        reply_buf: &'b mut [u8],
    ) -> Result<AuxResponse<'b>, AuxError> {
        let mut wire = AUX_TRANSACTION.try_lock().ok_or(AuxError::Deferred)?;
        // Gen9: exit DC5/DC6 before the first AUX register access and hold
        // DC_off to the end of the transfer; re-entry is deferred after it.
        // A refused exit touches nothing. Inert on every other display.
        let _dc = crate::intel_gpu_gen9_dc_states::hold(
            self.gen9_dc,
            self.mmio,
            crate::intel_gpu_gen9_dc_states::Gen9DcUser::Aux,
        )
        .map_err(|_| AuxError::Deferred)?;
        // Display 35 (the LT-PHY windows): every AUX channel is a DC_off
        // domain. Exit DC6 before the first AUX register access and defer
        // re-entry after the transfer; a refused exit touches nothing.
        let _dc35 = if self.mmio.has_lt_phy() {
            Some(
                crate::intel_gpu_dc_states::hold(
                    self.dc_off,
                    self.mmio,
                    crate::intel_gpu_dc_states::DcUser::Aux,
                )
                .map_err(|_| AuxError::Deferred)?,
            )
        } else {
            None
        };
        let inherited = self.mmio.read32(self.aux_ctl_off());
        if inherited == u32::MAX {
            return Err(AuxError::ShortReply);
        }
        // A firmware/foreign request has no NARF reply owner. Never overwrite
        // its DATA or clear its completion while SEND_BUSY remains asserted.
        if inherited & AUX_CTL_SEND_BUSY != 0 {
            return Err(AuxError::Deferred);
        }
        // Encode the request into the on-wire 3..20 byte frame (3 =
        // an I²C address-only request).
        let n = encode_request(req, &mut wire[..])?;

        // Expected reply payload length: NATIVE/I2C reads return
        // `req.data.len()` bytes; writes return 0.
        let is_read = matches!(
            req.cmd,
            crate::dp_aux::AuxCommand::NativeRead
                | crate::dp_aux::AuxCommand::I2cRead
                | crate::dp_aux::AuxCommand::I2cReadMot
        );
        let expected_payload = if is_read { req.data.len() } else { 0 };
        // intel_dp_aux_xfer_flags: a native write of the HDCP Aksv lets
        // the hardware supply its bytes.
        let flags = if req.cmd == crate::dp_aux::AuxCommand::NativeWrite
            && req.address == DP_AUX_HDCP_AKSV
        {
            AUX_CTL_AKSV_SELECT
        } else {
            0
        };

        // Hardware retry on protocol error (TIMEOUT / RECEIVE).
        // The dp_aux layer above handles DEFER-status retries —
        // those are not protocol errors, they're sink-level
        // backoff requests carried in the status nibble.
        let mut attempt = 1;
        let raw_len = loop {
            match self.xfer_once(&wire[..n], flags) {
                Ok(got) => break got,
                Err(err) if attempt == HW_RETRIES => return Err(err),
                Err(_) => attempt += 1,
            }
        };
        if reply_buf.len() < raw_len {
            return Err(AuxError::TooLong);
        }
        self.read_data(raw_len, reply_buf);
        // Hand the raw reply (status nibble in high half of byte 0,
        // then payload) to the dp_aux decoder. The decoder enforces
        // length + status invariants.
        // NACK/DEFER replies carry only the status byte, including for a
        // read requesting payload. Classify that status before enforcing the
        // ACK payload length; otherwise normal DEFER becomes ShortReply and
        // a missing optional DPCD interface cannot be identified as NACK.
        let raw = &reply_buf[..raw_len];
        if raw[0] & 0xf0 != 0 {
            return decode_response(raw, 0);
        }
        decode_response(raw, expected_payload)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! AUX transport smokes (lane 1, #1010). Before this lane the
    //! module header claimed these lived in `crate::tests`; they
    //! did not exist anywhere. The mock below records writes and
    //! serves scripted reads keyed by offset.

    extern crate alloc;

    use super::*;
    use crate::dp_aux::{AuxCommand, AuxRequest, AuxStatus};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Debug, Default)]
    pub struct MockMmio {
        pub writes: RefCell<Vec<(u64, u32)>>,
        pub reads: RefCell<Vec<(u64, u32)>>,
    }

    impl MockMmio {
        pub fn set_read(&self, off: u64, val: u32) {
            self.reads.borrow_mut().push((off, val));
        }
        pub fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
    }

    impl MmioWindow for MockMmio {
        fn read32(&self, off: u64) -> u32 {
            let mut v = 0u32;
            for (o, val) in self.reads.borrow().iter() {
                if *o == off {
                    v = *val;
                }
            }
            v
        }
        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
        }
    }

    fn ctl_off() -> u64 {
        Ddi::A.base() + DDI_AUX_CTL_OFFSET
    }

    fn smoke_aux_shared_exclusion_busy_and_inaccessible_never_overwrite() -> TestResult {
        let mmio = MockMmio::default();
        let mut aux = IntelAux::new(&mmio, Ddi::A);
        let request = AuxRequest {
            cmd: AuxCommand::NativeRead,
            address: 0x700,
            data: &[0],
        };
        let mut reply = [0; 2];
        let held = AUX_TRANSACTION.try_lock().unwrap();
        assert!(matches!(
            aux.transact(&request, &mut reply),
            Err(AuxError::Deferred)
        ));
        assert!(mmio.writes.borrow().is_empty());
        drop(held);
        mmio.set_read(ctl_off(), AUX_CTL_SEND_BUSY);
        assert!(matches!(
            aux.transact(&request, &mut reply),
            Err(AuxError::Deferred)
        ));
        assert!(mmio.writes.borrow().is_empty());
        mmio.set_read(ctl_off(), u32::MAX);
        assert!(matches!(
            aux.transact(&request, &mut reply),
            Err(AuxError::ShortReply)
        ));
        assert!(mmio.writes.borrow().is_empty());
        mmio.set_read(ctl_off(), AUX_CTL_DONE | (1 << AUX_CTL_MSGSIZE_SHIFT));
        mmio.set_read(Ddi::A.base() + DDI_AUX_DATA_OFFSET, 0x2000_0000);
        assert!(matches!(
            aux.transact(&request, &mut reply),
            Err(AuxError::Deferred)
        ));
        mmio.set_read(Ddi::A.base() + DDI_AUX_DATA_OFFSET, 0x1000_0000);
        assert!(matches!(
            aux.transact(&request, &mut reply),
            Err(AuxError::Nacked)
        ));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_aux",
        smoke_aux_shared_exclusion_busy_and_inaccessible_never_overwrite
    );

    fn smoke_aux_wire_packing_is_big_endian() -> TestResult {
        let mmio = MockMmio::default();
        let aux = IntelAux::new(&mmio, Ddi::A);
        aux.write_data(&[0x10, 0x00, 0xAB, 0xCD, 0x42]);
        let d0 = mmio.writes_to(Ddi::A.base() + DDI_AUX_DATA_OFFSET);
        let d1 = mmio.writes_to(Ddi::A.base() + DDI_AUX_DATA_OFFSET + 4);
        if d0 != alloc::vec![0x1000_ABCD] {
            return TestResult::Fail("first wire dword must pack bytes big-endian");
        }
        if d1 != alloc::vec![0x4200_0000] {
            return TestResult::Fail("fifth byte must start DATA[1] in the high byte");
        }
        // Round-trip through read_data.
        let mmio2 = MockMmio::default();
        mmio2.set_read(Ddi::A.base() + DDI_AUX_DATA_OFFSET, 0x1000_ABCD);
        mmio2.set_read(Ddi::A.base() + DDI_AUX_DATA_OFFSET + 4, 0x4200_0000);
        let aux2 = IntelAux::new(&mmio2, Ddi::A);
        let mut buf = [0u8; 5];
        if aux2.read_data(5, &mut buf) != 5 || buf != [0x10, 0x00, 0xAB, 0xCD, 0x42] {
            return TestResult::Fail("AUX data read-back round-trip failed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_aux",
        smoke_aux_wire_packing_is_big_endian
    );

    fn smoke_aux_ctl_composition_and_success() -> TestResult {
        let mmio = MockMmio::default();
        // Reply: DONE set, SEND_BUSY clear, MSGSIZE = 1 (status byte only).
        mmio.set_read(ctl_off(), AUX_CTL_DONE | (1 << AUX_CTL_MSGSIZE_SHIFT));
        mmio.set_read(Ddi::A.base() + DDI_AUX_DATA_OFFSET, 0);
        let mut aux = IntelAux::new(&mmio, Ddi::A);
        let req = AuxRequest {
            cmd: AuxCommand::NativeWrite,
            address: 0x100,
            data: &[0x55],
        };
        let mut reply = [0u8; 17];
        match aux.transact(&req, &mut reply) {
            Ok(resp) if resp.status == AuxStatus::Ack => {}
            _ => return TestResult::Fail("native write with ACK status must succeed"),
        }
        // Exactly one SEND write, carrying SEND_BUSY + the wire
        // length (4-byte header + 1 payload byte = 5) in MSGSIZE.
        let sends: Vec<u32> = mmio
            .writes_to(ctl_off())
            .into_iter()
            .filter(|w| w & AUX_CTL_SEND_BUSY != 0)
            .collect();
        if sends.len() != 1 {
            return TestResult::Fail("expected exactly one SEND_BUSY write");
        }
        if (sends[0] & AUX_CTL_MSGSIZE_MASK) >> AUX_CTL_MSGSIZE_SHIFT != 5 {
            return TestResult::Fail("MSGSIZE must carry the wire length");
        }
        if sends[0] & AUX_CTL_TIMEOUT_MAX != AUX_CTL_TIMEOUT_MAX {
            return TestResult::Fail("CTL must select the maximum timeout");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_aux",
        smoke_aux_ctl_composition_and_success
    );

    fn smoke_dpcd_read_requests_full_length() -> TestResult {
        // Regression pin for the #1092 found defect: `dpcd_read`
        // built its request with an empty data slice, so the
        // wire LEN field encoded 0 (a 1-byte request) and the
        // transport expected a 0-byte payload — every multi-byte
        // DPCD read over this transport failed decode. The
        // request must carry the caller's buffer as the length
        // placeholder: a 2-byte read at 0x202 must put
        // LEN = 1 in the frame's fourth byte.
        use crate::dp_aux::AuxChannel as _;
        let mmio = MockMmio::default();
        // Reply: DONE, MSGSIZE = 3 (status + 2 payload bytes);
        // DATA0 carries status 0x00 then payload AB CD.
        mmio.set_read(ctl_off(), AUX_CTL_DONE | (3 << AUX_CTL_MSGSIZE_SHIFT));
        mmio.set_read(Ddi::A.base() + DDI_AUX_DATA_OFFSET, 0x00AB_CD00);
        let mut aux = IntelAux::new(&mmio, Ddi::A);
        let mut buf = [0u8; 2];
        match aux.dpcd_read(0x202, &mut buf) {
            Ok(()) => {}
            Err(_) => return TestResult::Fail("2-byte dpcd_read must succeed over the transport"),
        }
        if buf != [0xAB, 0xCD] {
            return TestResult::Fail("dpcd_read payload must land in the caller buffer");
        }
        // The frame written to AUX_DATA[0]: cmd 0x9, addr
        // 0x000202, LEN 0x01 — big-endian packed.
        let d0 = mmio.writes_to(Ddi::A.base() + DDI_AUX_DATA_OFFSET);
        if d0 != alloc::vec![0x9002_0201] {
            return TestResult::Fail("wire frame must encode the requested length (LEN = n-1)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_aux",
        smoke_dpcd_read_requests_full_length
    );

    fn smoke_aux_msgsize_field_is_five_bits() -> TestResult {
        // Regression pin for the #1114 fix round: DDI_AUX_CTL's
        // Message Size field is five bits [24:20] (i915
        // `intel_dp_aux_regs.h`: REG_GENMASK(24, 20)). Defined
        // as four bits it truncated a 17-byte reply — status +
        // the 16-byte DPCD caps block — to 1 byte, and every
        // DP connect failed ShortReply in `read_caps`. A
        // 16-byte DPCD read must round-trip all 16 payload
        // bytes over the transport.
        use crate::dp_aux::AuxChannel as _;
        let mmio = MockMmio::default();
        mmio.set_read(ctl_off(), AUX_CTL_DONE | (17 << AUX_CTL_MSGSIZE_SHIFT));
        // Reply bytes: status 0x00, then payload 0x10..=0x1F,
        // big-endian across the five DATA dwords.
        let mut payload = [0u8; 16];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = 0x10 + i as u8;
        }
        let mut reply = [0u8; 20];
        reply[1..17].copy_from_slice(&payload);
        for (i, dword) in reply.chunks(4).enumerate() {
            let v = u32::from_be_bytes([dword[0], dword[1], dword[2], dword[3]]);
            mmio.set_read(Ddi::A.base() + DDI_AUX_DATA_OFFSET + (i as u64) * 4, v);
        }
        let mut aux = IntelAux::new(&mmio, Ddi::A);
        let mut buf = [0u8; 16];
        match aux.dpcd_read(0x000, &mut buf) {
            Ok(()) => {}
            Err(_) => return TestResult::Fail("16-byte dpcd_read must succeed over the transport"),
        }
        if buf != payload {
            return TestResult::Fail("16-byte reply must not truncate");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_aux",
        smoke_aux_msgsize_field_is_five_bits
    );

    fn smoke_aux_full_burst_read_round_trips() -> TestResult {
        // A full-burst read — 16 payload bytes, the DP AUX cap
        // and exactly the burst `dp_edid` uses per EDID chunk —
        // completes with a 17-byte reply (status + payload).
        // The controller publishes that count in MSGSIZE; 17
        // needs the field's fifth bit ([24:20]). With a 4-bit
        // field the count truncated to 1 and bit 24 read back
        // as a spurious error flag, so every full-burst read
        // failed after the hardware-retry budget — the defect
        // that took down the modeset full-run smokes (#1131).
        use crate::dp_aux::AuxChannel as _;
        let mmio = MockMmio::default();
        mmio.set_read(ctl_off(), AUX_CTL_DONE | (17 << AUX_CTL_MSGSIZE_SHIFT));
        // Reply bytes: status 0x00 (ACK), then payload
        // 0x10..=0x1F, packed big-endian into the DATA dwords.
        for i in 0..DDI_AUX_DATA_DWORDS {
            let mut v = 0u32;
            for b in 0..4 {
                let idx = i * 4 + b;
                let byte = if idx == 0 { 0x00 } else { 0x0F + idx as u8 };
                v |= (byte as u32) << (24 - 8 * b);
            }
            mmio.set_read(Ddi::A.base() + DDI_AUX_DATA_OFFSET + (i as u64) * 4, v);
        }
        let mut aux = IntelAux::new(&mmio, Ddi::A);
        let mut buf = [0u8; 16];
        match aux.dpcd_read(0x000, &mut buf) {
            Ok(()) => {}
            Err(_) => return TestResult::Fail("16-byte dpcd_read must succeed over the transport"),
        }
        if buf != core::array::from_fn::<u8, 16, _>(|i| 0x10 + i as u8) {
            return TestResult::Fail("full-burst payload must round-trip intact");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_aux",
        smoke_aux_full_burst_read_round_trips
    );

    fn smoke_aux_timeout_retries_exactly_three_times() -> TestResult {
        let mmio = MockMmio::default();
        // Every completion read reports TIMEOUT_ERROR (SEND_BUSY clear).
        mmio.set_read(ctl_off(), AUX_CTL_DONE | AUX_CTL_TIMEOUT_ERROR);
        let mut aux = IntelAux::new(&mmio, Ddi::A);
        // For reads, `data` is a length placeholder: the frame
        // carries the requested byte count, not contents.
        let req = AuxRequest {
            cmd: AuxCommand::NativeRead,
            address: 0x000,
            data: &[0u8; 1],
        };
        let mut reply = [0u8; 17];
        match aux.transact(&req, &mut reply) {
            Err(AuxError::ShortReply) => {}
            _ => return TestResult::Fail("timeout error must surface as ShortReply"),
        }
        let sends = mmio
            .writes_to(ctl_off())
            .into_iter()
            .filter(|w| w & AUX_CTL_SEND_BUSY != 0)
            .count();
        if sends != 3 {
            return TestResult::Fail("HW retry budget must be exactly 3 attempts");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_aux",
        smoke_aux_timeout_retries_exactly_three_times
    );

    fn smoke_gen12_native_aux_send_word() -> TestResult {
        let payload = [0; 16];
        let mut reply = [0; 17];
        for (ddi, ctl) in [
            (Ddi::A, 0x64010),
            (Ddi::B, 0x64110),
            (Ddi::C, 0x64210),
            (Ddi::D, 0x64310),
            (Ddi::E, 0x64410),
            (Ddi::F, 0x64510),
            (Ddi::G, 0x64610),
            (Ddi::H, 0x64710),
            (Ddi::I, 0x64810),
        ] {
            for (cmd, len, send, recv) in [
                (AuxCommand::I2cWrite, 0, 3, 1),
                (AuxCommand::NativeRead, 16, 4, 17),
                (AuxCommand::NativeWrite, 1, 5, 1),
                (AuxCommand::NativeWrite, 16, 20, 1),
            ] {
                let mmio = MockMmio::default();
                mmio.set_read(ctl, AUX_CTL_DONE | (recv << 20));
                let req = AuxRequest {
                    cmd,
                    address: 0x50,
                    data: &payload[..len],
                };
                let mut aux = IntelAux::new(&mmio, ddi);
                if aux.transact(&req, &mut reply).is_err() {
                    return TestResult::Fail("Gen12 native AUX transfer failed");
                }
                // i915 skl_get_aux_send_ctl, polled, native IO. Exact word
                // also checks that neither TBT_IO nor POWER_REQUEST is set.
                if mmio.writes_to(ctl) != [0x5200_0000, 0xde00_023f | (send << 20)] {
                    return TestResult::Fail("Gen12 native AUX control register or timing");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_aux",
        smoke_gen12_native_aux_send_word
    );

    fn smoke_aux_xelpdp_profile_preserves_power_request() -> TestResult {
        let req = AuxRequest {
            cmd: AuxCommand::NativeWrite,
            address: 0x600,
            data: &[1],
        };
        let mut reply = [0u8; 17];
        let mmio = MockMmio::default();
        if IntelAux::with_base(&mmio, 0x6_4000).profile()
            != (AuxCtlProfile::XeLpdp { tbt_io: false })
        {
            return TestResult::Fail("display-14 base transport must preserve AUX power");
        }
        // Xe-LPDP TC1 (0x16f210): every write keeps POWER_REQUEST, the
        // send word is skl_get_aux_send_ctl with fw-sync 18 / sync 32,
        // and TBT_IO is only set for a TBT-alt route.
        let base = 0x16_F200;
        for tbt in [false, true] {
            let mtl = MockMmio::default();
            mtl.set_read(base + 0x10, AUX_CTL_DONE | (1 << AUX_CTL_MSGSIZE_SHIFT));
            let mut aux = IntelAux::xelpdp(&mtl, base, tbt);
            if aux.transact(&req, &mut reply).is_err() {
                return TestResult::Fail("Xe-LPDP transport must succeed on ACK");
            }
            let writes = mtl.writes_to(base + 0x10);
            if writes.len() != 2
                || writes
                    .iter()
                    .any(|w| w & XELPDP_AUX_CH_CTL_POWER_REQUEST == 0)
            {
                return TestResult::Fail("Xe-LPDP writes must preserve the AUX power request");
            }
            let expected = AUX_CTL_SEND_BUSY
                | AUX_CTL_DONE
                | AUX_CTL_TIMEOUT_ERROR
                | (0b11 << 26)
                | AUX_CTL_RECEIVE_ERROR
                | (5 << 20)
                | (17 << 5)
                | 31
                | (1 << 19)
                | if tbt { 1 << 11 } else { 0 };
            if writes[1] != expected || xelpdp_aux_send_ctl(5, tbt) != expected {
                return TestResult::Fail("Xe-LPDP send word must match skl_get_aux_send_ctl");
            }
            if writes[1] & (1 << 29) != 0 {
                return TestResult::Fail("polled transport must not request the done interrupt");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_aux",
        smoke_aux_xelpdp_profile_preserves_power_request
    );
}
