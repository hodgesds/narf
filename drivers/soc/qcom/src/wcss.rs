//! Q6 WCSS remoteproc (IPQ8074 / IPQ6018 / IPQ5018 Hexagon WiFi
//! subsystem).
//!
//! Linux `drivers/remoteproc/qcom_q6v5_wcss.c`, the `WCSS_IPQ8074`
//! (`q6v5_wcss_ipq8074_ops`) path: the image is placed with
//! `qcom_mdt_load_no_init` (mainline does not route IPQ WCSS through
//! TrustZone PAS) and the Q6 is brought out of reset by the host:
//!
//! - **start** (`q6v5_wcss_start` + `q6v5_wcss_reset`): deassert
//!   `wcss_reset` and `wcss_q6_reset`, program the TCSR "Lithium" clock
//!   gating and bus arbitration (`halt_nc + TCSR_GLOBAL_CFG0/1`), write
//!   `boot_addr >> 4` to `Q6SS_RST_EVB`, then the QDSP6SS power sequence
//!   (XO CBCR on → BHS on → LDO bypass → clamps off → memory banks one at
//!   a time → core out of reset → core clock → run), and wait ≤ 5 s for
//!   the SMP2P `ready` interrupt.
//! - **stop** (`q6v5_wcss_stop`): SMP2P `stop` request (force-stop), WCSS
//!   power-down (AXI halt of the WCSS port, SSCAON handshake, assert
//!   `wcss_aon_reset`, assert `wcss_reset`) and Q6 power-down (AXI halt of
//!   the Q6 port, clock off, clamps on, memory banks off, BHS off, assert
//!   `wcss_reset` + `wcss_q6_reset`).
//!
//! Register windows: `qdsp6` (`reg-names`), `rmb`, and the TCSR syscon
//! named by `qcom,halt-regs = <&tcsr q6 wcss nc>`.

use crate::gcc::ResetLine;
use crate::io::{poll_reg, Delay, RegIo};
use crate::mdt::{Mdt, SegmentSource};
use crate::q6v5::{Q6v5, START_TIMEOUT_MS, STOP_TIMEOUT_MS};
use crate::rproc::{Carveout, RprocError, RprocState, StopState};

// Q6SS register offsets.
pub const Q6SS_RESET_REG: u32 = 0x014;
pub const Q6SS_GFMUX_CTL_REG: u32 = 0x020;
pub const Q6SS_PWR_CTL_REG: u32 = 0x030;
pub const Q6SS_MEM_PWR_CTL: u32 = 0x0b0;
pub const Q6SS_RST_EVB: u32 = 0x010;
pub const Q6SS_BHS_STATUS: u32 = 0x078;
/// `Q6SS_XO_CBCR` is `GENMASK(5, 3)` used as an offset in Linux.
pub const Q6SS_XO_CBCR: u32 = 0x38;
// AXI halt register offsets (within each halt block).
pub const AXI_HALTREQ_REG: u32 = 0x0;
pub const AXI_HALTACK_REG: u32 = 0x4;
pub const AXI_IDLE_REG: u32 = 0x8;
pub const HALT_ACK_TIMEOUT_MS: u32 = 100;
// Q6SS_RESET bits.
pub const Q6SS_STOP_CORE: u32 = 1 << 0;
pub const Q6SS_CORE_ARES: u32 = 1 << 1;
pub const Q6SS_BUS_ARES_ENABLE: u32 = 1 << 2;
// Q6SS_GFMUX_CTL.
pub const Q6SS_CLK_ENABLE: u32 = 1 << 1;
// Q6SS_PWR_CTL.
pub const Q6SS_L2DATA_STBY_N: u32 = 1 << 18;
pub const Q6SS_SLP_RET_N: u32 = 1 << 19;
pub const Q6SS_CLAMP_IO: u32 = 1 << 20;
pub const QDSS_BHS_ON: u32 = 1 << 21;
pub const Q6SS_CLAMP_WL: u32 = 1 << 21;
pub const Q6SS_CLAMP_QMC_MEM: u32 = 1 << 22;
pub const Q6SS_BHS_ON: u32 = 1 << 24;
pub const Q6SS_LDO_BYP: u32 = 1 << 25;
pub const HALT_CHECK_MAX_LOOPS: u32 = 200;
// TCSR / RMB.
pub const TCSR_GLOBAL_CFG0: u32 = 0x0;
pub const TCSR_GLOBAL_CFG1: u32 = 0x4;
pub const SSCAON_CONFIG: u32 = 0x8;
pub const SSCAON_STATUS: u32 = 0xc;
pub const BHS_EN_REST_ACK: u32 = 1 << 0;
pub const SSCAON_ENABLE: u32 = 1 << 13;
pub const SSCAON_BUS_EN: u32 = 1 << 15;
pub const SSCAON_BUS_MUX_MASK: u32 = 0x7 << 16;
pub const MEM_BANKS: u32 = 19;
pub const TCSR_WCSS_CLK_MASK: u32 = 0x1f;
pub const TCSR_WCSS_CLK_ENABLE: u32 = 0x14;
/// `WCSS_CRASH_REASON` SMEM item.
pub const WCSS_CRASH_REASON: u32 = 421;
/// `wcss_ipq8074_res_init.firmware_name`.
pub const IPQ8074_FIRMWARE: &str = "IPQ8074/q6_fw.mdt";

/// The three register windows.
#[derive(Debug)]
pub struct WcssRegs<R: RegIo> {
    /// `reg-names = "qdsp6"`.
    pub qdsp6: R,
    /// `reg-names = "rmb"`.
    pub rmb: R,
    /// The `qcom,halt-regs` TCSR syscon.
    pub tcsr: R,
    pub halt_q6: u32,
    pub halt_wcss: u32,
    pub halt_nc: u32,
}

/// The GCC reset lines (`reset-names`).
#[derive(Clone, Copy)]
pub struct WcssResets<'a> {
    pub aon: &'a (dyn ResetLine + Sync),
    pub wcss: &'a (dyn ResetLine + Sync),
    pub q6: &'a (dyn ResetLine + Sync),
}

impl core::fmt::Debug for WcssResets<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WcssResets")
    }
}

/// One Q6 WCSS instance.
#[derive(Debug)]
pub struct Q6Wcss<R: RegIo> {
    pub regs: WcssRegs<R>,
    /// Leaked at [`Self::new`]: GIC handlers hold `&'static` to it
    /// (`irq::Q6Irqs::bind_gic`) for the remoteproc's lifetime.
    pub q6: &'static Q6v5,
    boot_addr: Option<u32>,
    mem_reloc: u64,
    state: RprocState,
    /// `wcss_data.requires_force_stop` (true for IPQ8074).
    pub requires_force_stop: bool,
}

impl<R: RegIo> Q6Wcss<R> {
    pub fn new(regs: WcssRegs<R>) -> Self {
        Self {
            regs,
            q6: alloc::boxed::Box::leak(alloc::boxed::Box::new(Q6v5::new())),
            boot_addr: None,
            mem_reloc: 0,
            state: RprocState::Offline,
            requires_force_stop: true,
        }
    }

    pub fn state(&self) -> RprocState {
        self.state
    }
    pub fn boot_addr(&self) -> Option<u32> {
        self.boot_addr
    }
    pub fn mem_reloc(&self) -> u64 {
        self.mem_reloc
    }

    /// `q6v5_wcss_load` (`qcom_mdt_load_no_init`) + `rproc_elf_get_boot_addr`.
    pub fn load(
        &mut self,
        fw_name: &str,
        mdt: &[u8],
        src: &(dyn SegmentSource + Sync),
        carveout: &mut Carveout<'_>,
    ) -> Result<(), RprocError> {
        let m = Mdt::parse(mdt)?;
        self.mem_reloc = m.load(fw_name, src, carveout.mem, carveout.phys)?;
        self.boot_addr = Some(m.entry());
        Ok(())
    }

    /// `q6v5_wcss_reset`.
    async fn reset_seq<D: Delay + ?Sized>(&self, delay: &D) -> Result<(), RprocError> {
        let q = &self.regs.qdsp6;
        let v = q.read32(Q6SS_RESET_REG) | Q6SS_CORE_ARES | Q6SS_BUS_ARES_ENABLE | Q6SS_STOP_CORE;
        q.write32(Q6SS_RESET_REG, v);
        let v = q.read32(Q6SS_XO_CBCR) | 1;
        q.write32(Q6SS_XO_CBCR, v);
        poll_reg(
            q,
            delay,
            Q6SS_XO_CBCR,
            |v| v & (1 << 31) == 0,
            1,
            HALT_CHECK_MAX_LOOPS,
        )
        .await
        .map_err(|_| RprocError::XoClockTimeout)?;
        let mut v = q.read32(Q6SS_PWR_CTL_REG) | Q6SS_BHS_ON;
        q.write32(Q6SS_PWR_CTL_REG, v);
        delay.sleep_us(1).await;
        v |= Q6SS_LDO_BYP;
        q.write32(Q6SS_PWR_CTL_REG, v);
        let mut v = q.read32(Q6SS_PWR_CTL_REG) & !Q6SS_CLAMP_QMC_MEM;
        q.write32(Q6SS_PWR_CTL_REG, v);
        v |= Q6SS_L2DATA_STBY_N | Q6SS_SLP_RET_N;
        q.write32(Q6SS_PWR_CTL_REG, v);
        let mut m = q.read32(Q6SS_MEM_PWR_CTL);
        for i in (0..=MEM_BANKS).rev() {
            m |= 1 << i;
            q.write32(Q6SS_MEM_PWR_CTL, m);
            m |= q.read32(Q6SS_MEM_PWR_CTL);
            delay.sleep_us(1).await;
        }
        let mut v = q.read32(Q6SS_PWR_CTL_REG) & !Q6SS_CLAMP_WL;
        q.write32(Q6SS_PWR_CTL_REG, v);
        v &= !Q6SS_CLAMP_IO;
        q.write32(Q6SS_PWR_CTL_REG, v);
        let v = q.read32(Q6SS_RESET_REG) & !Q6SS_CORE_ARES;
        q.write32(Q6SS_RESET_REG, v);
        let v = q.read32(Q6SS_GFMUX_CTL_REG) | Q6SS_CLK_ENABLE;
        q.write32(Q6SS_GFMUX_CTL_REG, v);
        let v = q.read32(Q6SS_RESET_REG) & !Q6SS_STOP_CORE;
        q.write32(Q6SS_RESET_REG, v);
        Ok(())
    }

    /// `q6v5_wcss_start`. `pump` services the SMP2P edge while waiting
    /// for `ready` (see [`crate::q6v5`]).
    pub async fn start<D: Delay + ?Sized>(
        &mut self,
        resets: WcssResets<'_>,
        delay: &D,
        pump: &mut (dyn FnMut(&Q6v5) + Send),
    ) -> Result<(), RprocError> {
        let boot_addr = self.boot_addr.ok_or(RprocError::BadState(self.state))?;
        self.q6.prepare();
        resets.wcss.deassert();
        resets.q6.deassert();
        let t = &self.regs.tcsr;
        t.update32(
            self.regs.halt_nc + TCSR_GLOBAL_CFG0,
            TCSR_WCSS_CLK_MASK,
            TCSR_WCSS_CLK_ENABLE,
        );
        t.update32(self.regs.halt_nc + TCSR_GLOBAL_CFG1, 1, 0);
        self.regs.qdsp6.write32(Q6SS_RST_EVB, boot_addr >> 4);
        let r = match self.reset_seq(delay).await {
            Ok(()) => self
                .q6
                .wait_for_start(delay, START_TIMEOUT_MS, pump)
                .await
                .map_err(RprocError::from),
            Err(e) => Err(e),
        };
        match r {
            Ok(()) => {
                self.state = RprocState::Running;
                Ok(())
            }
            Err(e @ (RprocError::XoClockTimeout | RprocError::Handshake(_))) => {
                // Linux only unwinds the resets when q6v5_wcss_reset fails;
                // a ready timeout leaves them for rproc's recovery. Unwind
                // both so a retry starts from reset.
                resets.q6.assert();
                resets.wcss.assert();
                self.q6.unprepare();
                self.state = RprocState::Offline;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// `q6v5_wcss_halt_axi_port`. Returns `false` if the port did not
    /// report idle (Linux logs "port failed halt" and carries on).
    async fn halt_axi_port<D: Delay + ?Sized>(&self, offset: u32, delay: &D) -> bool {
        let t = &self.regs.tcsr;
        if t.read32(offset + AXI_IDLE_REG) != 0 {
            return true;
        }
        t.write32(offset + AXI_HALTREQ_REG, 1);
        let _ = poll_reg(
            t,
            delay,
            offset + AXI_HALTACK_REG,
            |v| v != 0,
            1000,
            HALT_ACK_TIMEOUT_MS * 1000,
        )
        .await;
        let idle = t.read32(offset + AXI_IDLE_REG) != 0;
        t.write32(offset + AXI_HALTREQ_REG, 0);
        idle
    }

    /// `q6v5_wcss_powerdown`.
    async fn wcss_powerdown<D: Delay + ?Sized>(
        &self,
        resets: WcssResets<'_>,
        delay: &D,
    ) -> Result<(), RprocError> {
        self.halt_axi_port(self.regs.halt_wcss, delay).await;
        let r = &self.regs.rmb;
        let mut v = r.read32(SSCAON_CONFIG) | SSCAON_ENABLE;
        r.write32(SSCAON_CONFIG, v);
        v |= SSCAON_BUS_EN;
        v &= !SSCAON_BUS_MUX_MASK;
        r.write32(SSCAON_CONFIG, v);
        v |= 1 << 1;
        r.write32(SSCAON_CONFIG, v);
        poll_reg(
            r,
            delay,
            SSCAON_STATUS,
            |v| v & 0xffff == 0x400,
            1000,
            HALT_CHECK_MAX_LOOPS,
        )
        .await
        .map_err(RprocError::SscaonTimeout)?;
        resets.aon.assert();
        let v = r.read32(SSCAON_CONFIG) & !SSCAON_ENABLE;
        r.write32(SSCAON_CONFIG, v);
        resets.wcss.assert();
        Ok(())
    }

    /// `q6v5_q6_powerdown`.
    async fn q6_powerdown<D: Delay + ?Sized>(
        &self,
        resets: WcssResets<'_>,
        delay: &D,
    ) -> Result<(), RprocError> {
        self.halt_axi_port(self.regs.halt_q6, delay).await;
        let q = &self.regs.qdsp6;
        let v = q.read32(Q6SS_GFMUX_CTL_REG) & !Q6SS_CLK_ENABLE;
        q.write32(Q6SS_GFMUX_CTL_REG, v);
        let mut v = q.read32(Q6SS_PWR_CTL_REG) | Q6SS_CLAMP_IO;
        q.write32(Q6SS_PWR_CTL_REG, v);
        v |= QDSS_BHS_ON;
        q.write32(Q6SS_PWR_CTL_REG, v);
        v &= !Q6SS_L2DATA_STBY_N;
        q.write32(Q6SS_PWR_CTL_REG, v);
        v &= !Q6SS_SLP_RET_N;
        q.write32(Q6SS_PWR_CTL_REG, v);
        for i in 0..20 {
            let m = q.read32(Q6SS_MEM_PWR_CTL) & !(1 << i);
            q.write32(Q6SS_MEM_PWR_CTL, m);
            delay.sleep_us(1000).await;
        }
        let mut v = q.read32(Q6SS_PWR_CTL_REG) | Q6SS_CLAMP_QMC_MEM;
        q.write32(Q6SS_PWR_CTL_REG, v);
        v &= !Q6SS_BHS_ON;
        q.write32(Q6SS_PWR_CTL_REG, v);
        delay.sleep_us(1).await;
        poll_reg(
            q,
            delay,
            Q6SS_BHS_STATUS,
            |v| v & BHS_EN_REST_ACK == 0,
            1000,
            HALT_CHECK_MAX_LOOPS,
        )
        .await
        .map_err(RprocError::BhsTimeout)?;
        resets.wcss.assert();
        resets.q6.assert();
        Ok(())
    }

    /// `q6v5_wcss_stop`.
    pub async fn stop<D: Delay + ?Sized>(
        &mut self,
        resets: WcssResets<'_>,
        stop: &(dyn StopState + Sync),
        delay: &D,
        pump: &mut (dyn FnMut(&Q6v5) + Send),
    ) -> Result<(), RprocError> {
        if self.state == RprocState::Offline {
            return Err(RprocError::BadState(self.state));
        }
        if self.requires_force_stop {
            // qcom_q6v5_request_stop: skip the SMP2P dance unless running.
            if self.state == RprocState::Running {
                stop.set_stop(true);
                let r = self.q6.wait_for_stop(delay, STOP_TIMEOUT_MS, pump).await;
                stop.set_stop(false);
                r?;
            } else {
                self.q6.mark_stopped();
            }
        }
        self.wcss_powerdown(resets, delay).await?;
        self.q6_powerdown(resets, delay).await?;
        self.q6.unprepare();
        self.state = RprocState::Offline;
        Ok(())
    }

    /// Record a crash reported by the remote (`rproc_report_crash`).
    pub fn note_crash(&mut self) {
        if self.q6.crash().is_some() {
            self.state = RprocState::Crashed;
        }
    }
}
