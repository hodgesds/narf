//! VCN 4.0 indirect SRAM restore program (`vcn_v4_0.c`), after the static
//! native fence proof.
//!
//! The DPG program replays `vcn_v4_0_start_dpg_mode` (with
//! `vcn_v4_0_mc_resume_dpg_mode`, indirect) through the PSP-loaded SRAM:
//! clock-gating disable, VCPU bring-up, LMI/MPC setup, cache windows (the
//! PSP patches the firmware/stack placeholders against its retained TMR),
//! VCPU release, LMI enable, optional RAS, master-interrupt enable. The
//! ring itself is then set up by direct MMIO, exactly as Linux does after
//! the SRAM load.
use super::*;

// `SOC15_DPG_MODE_OFFSET` (`amdgpu_vcn.h`): VCN_VID_SOC_ADDRESS_2_0,
// VCN1_VID_SOC_ADDRESS_3_0, VCN_AON_SOC_ADDRESS_2_0, VCN1_AON_SOC_ADDRESS_3_0
// with VCN_VID_IP_ADDRESS_2_0 / VCN_AON_IP_ADDRESS_2_0. The AON_2_0 (0x1f800)
// and IP (0x0 / 0x30000) values are in `amdgpu_vcn.h`; the full table is
// the one NARF's Navi22 VCN3 owner grounded against the same macro.
const DPG_SOC: [u32; 4] = [0x1fa00, 0x48200, 0x1f800, 0x48000];
const DPG_IP: [u32; 2] = [0, 0x30000];
/// `SOC15_DPG_MODE_OFFSET`: the VCN-internal dword offset of the register
/// at BAR byte address `address` (the discovery base plus the register).
/// Video ranges span 0x2600 bytes, always-on ranges 0x600; video wins.
pub(super) fn offset(base: u64, reg: u32) -> u32 {
    let a = (base as u32 + reg * 4) & 0xf_ffff;
    let ranges = [
        (DPG_SOC[0], 0x2600, DPG_IP[0]),
        (DPG_SOC[2], 0x600, DPG_IP[1]),
        (DPG_SOC[1], 0x2600, DPG_IP[0]),
        (DPG_SOC[3], 0x600, DPG_IP[1]),
    ];
    let internal = ranges
        .iter()
        .find(|&&(soc, len, _)| (soc..soc + len).contains(&a))
        .map_or(a, |&(soc, _, ip)| a - soc + ip);
    internal >> 2
}
/// DPG fence tag. Distinct from Navi48's 0xd09f0001: the tag is arbitrary
/// firmware-written proof data, and a per-generation value keeps the two
/// owners' proofs distinguishable in shared traces.
const DPG_PROBE_TAG: u32 = 0xd09f_0004;

impl<I: Io> Engine<I> {
    fn dpg_words(&self, ras: bool) -> Result<alloc::vec::Vec<u32>, Error> {
        let mut words = alloc::vec::Vec::with_capacity(64);
        let mut put = |reg, value| words.extend_from_slice(&[offset(self.layout.vcn, reg), value]);
        // vcn_v4_0_disable_clock_gating_dpg_mode(sram_sel 0): CGC_CTRL is a
        // full write (DYN 0, DLY_TIMER 1, OFF_DELAY 4, mode bits 0), gate
        // off, SUVD gate on, SUVD control off.
        put(CGC_CTRL, CGC_CTRL_VALUE);
        put(CGC_GATE, 0);
        put(SUVD_CGC_GATE, 1);
        put(SUVD_CGC_CTRL, 0);
        // Enable VCPU clock (held in reset), disable master interrupt.
        let vcpu = VCPU_PRB_TIMEOUT | VCPU_CLOCK;
        put(VCPU, vcpu | VCPU_RESET);
        put(MASTINT, 0);
        put(LMI, LMI_DPG);
        put(MPC_CNTL, 0x2 << 3); // REPLACEMENT_MODE 2
        put(MUXA0, 0x40c_2040); // 1<<6|2<<12|3<<18|4<<24
        put(MUXB0, 0x40c_2040);
        put(MUX, 0x88); // 0<<0|1<<3|2<<6
                        // vcn_v4_0_mc_resume_dpg_mode, indirect: PSP patches the firmware
                        // BAR/size and stack BAR; never substitute a host firmware address
                        // into this script.
        for (i, (address, size)) in [
            (0, 0),
            (0, STACK_BYTES as u32),
            (self.memory.address() + STACK_BYTES, CONTEXT_BYTES as u32),
        ]
        .into_iter()
        .enumerate()
        {
            put(CACHE_LO[i], address as u32);
            put(CACHE_LO[i] + 1, (address >> 32) as u32);
            put(CACHE_OFFSET[i], 0);
            put(CACHE_SIZE[i], size);
        }
        let shared = self.memory.address() + SHARED;
        put(NC_LO, shared as u32);
        put(NC_LO + 1, (shared >> 32) as u32);
        put(NC_OFFSET, 0);
        put(NC_SIZE, 4096);
        put(ADDR_CONFIG, self.addr_config.ok_or(Error::Invalid)?);
        put(VCPU, vcpu);
        put(LMI2, LMI2_DPG);
        if ras {
            // vcn_v4_0_enable_ras, indirect.
            put(RAS_CNTL, RAS_VALUE);
            put(SYS_INT_EN, RAS_SYS_INT_EN);
        }
        put(MASTINT, MASTINT_VCPU_EN);
        Ok(words)
    }
    /// `vcn_v4_0_start_dpg_mode` (indirect): power the block into DPG mode,
    /// load the SRAM program, then set up the ring by direct MMIO.
    async fn restore_dpg(&mut self, sram: &mut impl Sram, ras: bool) -> Result<(), Error> {
        // Disable register anti-hang mechanism.
        self.set(POWER_STATUS, POWER_STATUS_MASK, 1)?;
        // Enable dynamic power gating mode.
        self.set(
            POWER_STATUS,
            POWER_PG_MODE | POWER_PG_EN,
            POWER_PG_MODE | POWER_PG_EN,
        )?;
        let words = self.dpg_words(ras)?;
        self.access(|_, _| Ok(()))?;
        sram.load(&words).await?;
        self.access(|_, _| Ok(()))?;
        let ring = self.memory.address() + RING;
        self.set(RB_LO, u32::MAX, ring as u32)?;
        self.set(RB_HI, u32::MAX, (ring >> 32) as u32)?;
        self.set(RB_SIZE, u32::MAX, RING_SIZE_DW)?;
        self.set(RB_ENABLE, RB1, 0)?;
        self.shared_mode(FW_QUEUE_RING_RESET, FW_QUEUE_RING_RESET)?;
        self.set(RPTR, u32::MAX, 0)?;
        self.set(WPTR, u32::MAX, 0)?;
        self.wptr = 0;
        self.set(RB_ENABLE, RB1, RB1)?;
        self.shared_mode(FW_QUEUE_RING_RESET | FW_QUEUE_DPG_HOLD_OFF, 0)?;
        self.set(DB_CTRL, 0x4fff_fffc, DOORBELL << 2 | 1 << 30)?;
        self.dpg_probe().await
    }
    async fn dpg_probe(&mut self) -> Result<(), Error> {
        // A separate word proves execution after every SRAM restore without
        // changing the client sequence or its retained completion word.
        let map = self.memory.mapping();
        let probe = self.memory.address() + FENCE + 16;
        self.access(|io, l| {
            io.memory_write(map, FENCE + 16, 0);
            io.memory_write(map, FENCE + 20, 0);
            flush(io, l)
        })?;
        let next = self.emit(&[3, probe as u32, (probe >> 32) as u32, DPG_PROBE_TAG, 4, 1])?;
        for _ in 0..2000 {
            let done = self.access(|io, l| {
                flush(io, l)?;
                Ok(io.memory_read(map, FENCE + 16) == DPG_PROBE_TAG)
            })?;
            if done && self.reg(RPTR)? == next {
                return self.access(|io, l| {
                    io.memory_write(map, FENCE + 16, 0);
                    io.memory_write(map, FENCE + 20, 0);
                    flush(io, l)
                });
            }
            self.io.delay(50).await;
        }
        Err(Error::Timeout)
    }
    /// `vcn_v4_0_pause_dpg_mode` (pause): wait for power status 1, request
    /// the pause, wait for the ACK, then wait for power status 2
    /// (`UVD_PGFSM_CONFIG__UVDM_UVDU_PWR_ON`).
    pub(super) async fn pause_dpg(&mut self) -> Result<(), Error> {
        self.wait(POWER_STATUS, POWER_STATUS_MASK, 1).await?;
        self.dpg_pause_request(true)?;
        self.wait(DPG_PAUSE, DPG_PAUSE_ACK, DPG_PAUSE_ACK).await?;
        self.wait(POWER_STATUS, POWER_STATUS_MASK, 0x2).await
    }
    pub(super) fn dpg_pause_request(&mut self, pause: bool) -> Result<(), Error> {
        // ACK is read-only. Do not write a sampled ACK back as a request.
        self.access(|io, l| {
            let at = l.vcn + u64::from(DPG_PAUSE) * 4;
            let old = checked(io.read(at))?;
            io.write(at, (old & !0xc) | if pause { DPG_PAUSE_REQ } else { 0 });
            Ok(())
        })
    }
    /// `vcn_v4_0_stop_dpg_mode`.
    pub(super) async fn stop_dpg(&mut self) -> Result<(), Error> {
        self.pause_dpg().await?;
        // Wait for power status to be 1.
        self.wait(POWER_STATUS, POWER_STATUS_MASK, 1).await?;
        // Wait for read ptr to be equal to write ptr.
        let wptr = self.reg(WPTR)?;
        self.wait(RPTR, u32::MAX, wptr).await?;
        self.wait(POWER_STATUS, POWER_STATUS_MASK, 1).await?;
        // Disable dynamic power gating mode.
        self.set(POWER_STATUS, POWER_PG_MODE, 0)?;
        self.reg(STATUS)?;
        Ok(())
    }
    /// Upgrade a started, drained engine to DPG restore.
    pub(super) async fn enable_dpg(
        &mut self,
        sram: &mut impl Sram,
        ras: bool,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::Ready | State::Verified) {
            return Err(Error::Busy);
        }
        if self.dpg {
            return Ok(());
        }
        self.state = State::Starting;
        let result = self.restore_dpg(sram, ras).await;
        self.state = match result {
            Ok(()) => State::Ready,
            Err(e) => State::Failed(e),
        };
        if result.is_ok() {
            self.dpg = true;
        }
        result
    }
}
