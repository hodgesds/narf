//! Qualcomm Secure Channel Manager (SCM) over the SMC calling convention.
//!
//! Linux `drivers/firmware/qcom/qcom_scm.c` + `qcom_scm-smc.c`. A call is
//! an SMCCC SiP call: `x0` = `ARM_SMCCC_CALL_VAL(type, conv, SIP,
//! svc << 8 | cmd)`, `x1` = arginfo (`QCOM_SCM_ARGS`), `x2..x5` = the first
//! four arguments, `x6` = 0 (the "QCOM_A6" quirk/session word). On return
//! `x0` is the status, `x1..x3` the results.
//!
//! Implemented: convention probe (`__get_convention`: ARM64, then ARM32,
//! via `QCOM_SCM_INFO_IS_CALL_AVAIL`), `INTERRUPTED` re-issue with the
//! returned `x6`, the `-EBUSY` retry (20 × 30 ms, sleeping), error remap,
//! `is_call_available`, and the PIL/PAS calls the remoteproc loaders need:
//! `pas_supported`, `pas_init_image`, `pas_mem_setup`,
//! `pas_auth_and_reset`, `pas_shutdown`.
//!
//! Not implemented, each refused with a precise [`ScmError`]:
//! - the legacy (pre-SMCCC) convention — no supported SoC uses it;
//! - more than four arguments (needs the `qcom_tzmem` indirect argument
//!   buffer) — no PAS call needs it;
//! - `QCOM_SCM_WAITQ_SLEEP` (firmware-side wait queues completed by an
//!   SCM interrupt) — SC7280/IPQ firmware does not return it for PAS.

use crate::io::Delay;

/// SMCCC owning entity for Qualcomm SCM calls.
pub const OWNER_SIP: u32 = 2;

pub const SVC_BOOT: u32 = 0x01;
pub const SVC_PIL: u32 = 0x02;
pub const PIL_PAS_INIT_IMAGE: u32 = 0x01;
pub const PIL_PAS_MEM_SETUP: u32 = 0x02;
pub const PIL_PAS_AUTH_AND_RESET: u32 = 0x05;
pub const PIL_PAS_SHUTDOWN: u32 = 0x06;
pub const PIL_PAS_IS_SUPPORTED: u32 = 0x07;
pub const SVC_INFO: u32 = 0x06;
pub const INFO_IS_CALL_AVAIL: u32 = 0x01;

/// Firmware status codes (`qcom_scm.h`).
pub const SCM_V2_EBUSY: i64 = -12;
pub const SCM_ENOMEM: i64 = -5;
pub const SCM_EOPNOTSUPP: i64 = -4;
pub const SCM_EINVAL_ADDR: i64 = -3;
pub const SCM_EINVAL_ARG: i64 = -2;
pub const SCM_ERROR: i64 = -1;
pub const SCM_INTERRUPTED: i64 = 1;
pub const SCM_WAITQ_SLEEP: i64 = 2;

const EBUSY_WAIT_MS: u32 = 30;
const EBUSY_MAX_RETRY: u32 = 20;
/// Bound on back-to-back `INTERRUPTED` re-issues before giving up (Linux
/// loops without bound; a stuck monitor must not wedge the caller).
const INTERRUPTED_MAX: u32 = 1024;

/// `QCOM_SCM_ARGS` argument kinds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ArgType {
    Val = 0,
    Ro = 1,
    Rw = 2,
    BufVal = 3,
}

/// `QCOM_SCM_ARGS(num, types...)`.
pub const fn arginfo(num: u32, types: &[ArgType]) -> u32 {
    let mut v = num & 0xf;
    let mut i = 0;
    while i < types.len() && i < 10 {
        v |= (types[i] as u32 & 0x3) << (4 + 2 * i);
        i += 1;
    }
    v
}

/// `SCM_SMC_FNID(svc, cmd)`.
pub const fn smc_fnid(svc: u32, cmd: u32) -> u32 {
    ((svc & 0xff) << 8) | (cmd & 0xff)
}

/// `ARM_SMCCC_CALL_VAL(type, conv, owner, fnid)` (SMCCC §2.5).
pub const fn call_val(fast: bool, smc64: bool, owner: u32, fnid: u32) -> u64 {
    ((if fast { 1u32 << 31 } else { 0 })
        | (if smc64 { 1 << 30 } else { 0 })
        | ((owner & 0x3f) << 24)
        | (fnid & 0xffff)) as u64
}

/// The secure-monitor trap. [`ArchSmc`] is the real one; tests install a
/// fake monitor.
pub trait SmcConduit {
    /// Issue the call with `regs` = `x0..x7`; on return `regs` holds the
    /// monitor's `x0..x7`.
    fn smc(&self, regs: &mut [u64; 8]);
}

/// `smc #0` through `narf_arch::aarch64::smccc` (aarch64); on other
/// architectures every call reports SMCCC `NOT_SUPPORTED` (-1).
#[derive(Copy, Clone, Debug, Default)]
pub struct ArchSmc;

impl SmcConduit for ArchSmc {
    fn smc(&self, regs: &mut [u64; 8]) {
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: the SCM instance is created only for a DT `qcom,scm`
            // node, i.e. a platform whose secure monitor implements the
            // SiP service; argument buffers are owned by the caller for
            // the duration of the call.
            unsafe { narf_arch::aarch64::smccc::smc_call(regs) }
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            regs[0] = u64::MAX;
        }
    }
}

/// `enum qcom_scm_convention` (probed).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Convention {
    Arm64,
    Arm32,
    Legacy,
}

/// SCM call failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScmError {
    /// `QCOM_SCM_ERROR` → `-EIO`.
    Io,
    /// `QCOM_SCM_EINVAL_ADDR` / `EINVAL_ARG` (and unknown codes) → `-EINVAL`.
    Invalid,
    /// `QCOM_SCM_EOPNOTSUPP` → `-EOPNOTSUPP`.
    NotSupported,
    /// `QCOM_SCM_ENOMEM` → `-ENOMEM`.
    NoMem,
    /// `QCOM_SCM_V2_EBUSY` after the retry budget → `-EBUSY`.
    Busy,
    /// The call succeeded but `res.result[0]` is non-zero (Linux returns
    /// it as a positive error).
    Result(u64),
    /// Only the legacy convention answered; it is not implemented.
    LegacyConvention,
    /// More than four arguments (needs the tzmem indirect buffer).
    TooManyArgs,
    /// `QCOM_SCM_WAITQ_SLEEP`: firmware wait queues are not implemented.
    WaitQueue,
    /// The monitor kept returning `INTERRUPTED`.
    Interrupted,
    /// A PAS metadata buffer could not be allocated.
    Alloc,
}

/// `qcom_scm_remap_error`.
pub const fn remap_error(code: i64) -> ScmError {
    match code {
        SCM_ERROR => ScmError::Io,
        SCM_EINVAL_ADDR | SCM_EINVAL_ARG => ScmError::Invalid,
        SCM_EOPNOTSUPP => ScmError::NotSupported,
        SCM_ENOMEM => ScmError::NoMem,
        SCM_V2_EBUSY => ScmError::Busy,
        _ => ScmError::Invalid,
    }
}

/// `struct qcom_scm_desc`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ScmDesc {
    pub svc: u32,
    pub cmd: u32,
    pub arginfo: u32,
    pub args: [u64; 4],
}

impl ScmDesc {
    pub const fn new(svc: u32, cmd: u32, arginfo: u32, args: [u64; 4]) -> Self {
        Self {
            svc,
            cmd,
            arginfo,
            args,
        }
    }
}

/// A physically contiguous buffer the secure world can read (PAS
/// metadata). Linux uses `dma_alloc_coherent`.
pub trait ScmBuffer {
    fn phys(&self) -> u64;
    fn as_mut_slice(&mut self) -> &mut [u8];
}

impl ScmBuffer for narf_io::DmaBuffer {
    fn phys(&self) -> u64 {
        self.dma_addr().raw()
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        narf_io::DmaBuffer::as_mut_slice(self)
    }
}

/// Allocator for [`ScmBuffer`]s.
pub trait ScmAlloc {
    type Buf: ScmBuffer;
    fn alloc(&mut self, len: usize) -> Option<Self::Buf>;
}

/// Coherent 32-bit DMA memory from `narf_io`.
#[derive(Copy, Clone, Debug, Default)]
pub struct CoherentAlloc;

impl ScmAlloc for CoherentAlloc {
    type Buf = narf_io::DmaBuffer;
    fn alloc(&mut self, len: usize) -> Option<narf_io::DmaBuffer> {
        if len == 0 {
            return None;
        }
        narf_io::alloc_coherent_masked(len, narf_lib::id::DomainId::DRIVER_0, 0xffff_ffff).ok()
    }
}

/// An SCM endpoint. Calls take `&mut self`: like Linux's `qcom_scm_lock`
/// the secure monitor sees one call at a time from this instance; a
/// shared instance belongs behind the owner's (async) mutex.
#[derive(Debug)]
pub struct Scm<C: SmcConduit> {
    conduit: C,
    convention: Option<Convention>,
    /// SMC traps issued (all re-issues included), for tests/diagnostics.
    pub traps: u64,
}

impl<C: SmcConduit> Scm<C> {
    pub const fn new(conduit: C) -> Self {
        Self {
            conduit,
            convention: None,
            traps: 0,
        }
    }

    /// The probed convention, if probing has run.
    pub fn convention(&self) -> Option<Convention> {
        self.convention
    }

    /// `__scm_smc_do_quirk`: one logical call, re-issued while the
    /// monitor answers `INTERRUPTED` (with `x0` = the status and `x6` =
    /// the returned session word, as `arm_smccc_smc_quirk` does).
    fn do_quirk(&mut self, regs: &[u64; 8]) -> Result<[u64; 8], ScmError> {
        let mut r = *regs;
        r[6] = 0;
        for _ in 0..INTERRUPTED_MAX {
            let mut io = r;
            self.conduit.smc(&mut io);
            self.traps += 1;
            if io[0] as i64 != SCM_INTERRUPTED {
                return Ok(io);
            }
            r[0] = io[0];
            r[6] = io[6];
        }
        Err(ScmError::Interrupted)
    }

    fn regs_for(desc: &ScmDesc, fast: bool, smc64: bool) -> [u64; 8] {
        let mut r = [0u64; 8];
        r[0] = call_val(fast, smc64, OWNER_SIP, smc_fnid(desc.svc, desc.cmd));
        r[1] = desc.arginfo as u64;
        r[2..6].copy_from_slice(&desc.args);
        r
    }

    /// `__get_convention`: ARM64 first, then ARM32, else legacy.
    pub fn probe_convention(&mut self) -> Convention {
        if let Some(c) = self.convention {
            return c;
        }
        let avail = ScmDesc::new(
            SVC_INFO,
            INFO_IS_CALL_AVAIL,
            arginfo(1, &[]),
            [
                (smc_fnid(SVC_INFO, INFO_IS_CALL_AVAIL) | (OWNER_SIP << 24)) as u64,
                0,
                0,
                0,
            ],
        );
        let mut found = Convention::Legacy;
        for (conv, smc64) in [(Convention::Arm64, true), (Convention::Arm32, false)] {
            if let Ok(r) = self.do_quirk(&Self::regs_for(&avail, true, smc64)) {
                if r[0] == 0 && r[1] == 1 {
                    found = conv;
                    break;
                }
            }
        }
        self.convention = Some(found);
        found
    }

    /// `qcom_scm_call` (yielding) or `qcom_scm_call_atomic` (`fast`).
    /// Returns `res.result[0..3]`.
    pub async fn call<D: Delay + ?Sized>(
        &mut self,
        desc: &ScmDesc,
        fast: bool,
        delay: &D,
    ) -> Result<[u64; 3], ScmError> {
        if desc.arginfo & 0xf > 4 {
            return Err(ScmError::TooManyArgs);
        }
        let smc64 = match self.probe_convention() {
            Convention::Arm64 => true,
            Convention::Arm32 => false,
            Convention::Legacy => return Err(ScmError::LegacyConvention),
        };
        let regs = Self::regs_for(desc, fast, smc64);
        let mut retry = 0;
        loop {
            let r = self.do_quirk(&regs)?;
            let status = r[0] as i64;
            if status == SCM_WAITQ_SLEEP && !fast {
                return Err(ScmError::WaitQueue);
            }
            if status == SCM_V2_EBUSY && !fast {
                retry += 1;
                if retry > EBUSY_MAX_RETRY {
                    return Err(ScmError::Busy);
                }
                delay.sleep_us(EBUSY_WAIT_MS * 1000).await;
                continue;
            }
            if status != 0 {
                return Err(remap_error(status));
            }
            return Ok([r[1], r[2], r[3]]);
        }
    }

    /// `ret ?: res.result[0]` — the PAS calls' return shape.
    async fn call_result0<D: Delay + ?Sized>(
        &mut self,
        desc: &ScmDesc,
        delay: &D,
    ) -> Result<(), ScmError> {
        let r = self.call(desc, false, delay).await?;
        if r[0] != 0 {
            return Err(ScmError::Result(r[0]));
        }
        Ok(())
    }

    /// `__qcom_scm_is_call_available`.
    pub async fn is_call_available<D: Delay + ?Sized>(
        &mut self,
        svc: u32,
        cmd: u32,
        delay: &D,
    ) -> bool {
        let desc = ScmDesc::new(
            SVC_INFO,
            INFO_IS_CALL_AVAIL,
            arginfo(1, &[]),
            [(smc_fnid(svc, cmd) | (OWNER_SIP << 24)) as u64, 0, 0, 0],
        );
        matches!(self.call(&desc, false, delay).await, Ok(r) if r[0] != 0)
    }

    /// `qcom_scm_pas_supported`.
    pub async fn pas_supported<D: Delay + ?Sized>(&mut self, peripheral: u32, delay: &D) -> bool {
        if !self
            .is_call_available(SVC_PIL, PIL_PAS_IS_SUPPORTED, delay)
            .await
        {
            return false;
        }
        let desc = ScmDesc::new(
            SVC_PIL,
            PIL_PAS_IS_SUPPORTED,
            arginfo(1, &[]),
            [peripheral as u64, 0, 0, 0],
        );
        matches!(self.call(&desc, false, delay).await, Ok(r) if r[0] != 0)
    }

    /// `qcom_scm_pas_init_image` with the metadata already copied into a
    /// physically contiguous buffer at `metadata_phys`.
    pub async fn pas_init_image<D: Delay + ?Sized>(
        &mut self,
        peripheral: u32,
        metadata_phys: u64,
        delay: &D,
    ) -> Result<(), ScmError> {
        let desc = ScmDesc::new(
            SVC_PIL,
            PIL_PAS_INIT_IMAGE,
            arginfo(2, &[ArgType::Val, ArgType::Rw]),
            [peripheral as u64, metadata_phys, 0, 0],
        );
        self.call_result0(&desc, delay).await
    }

    /// `qcom_scm_pas_mem_setup`.
    pub async fn pas_mem_setup<D: Delay + ?Sized>(
        &mut self,
        peripheral: u32,
        addr: u64,
        size: u64,
        delay: &D,
    ) -> Result<(), ScmError> {
        let desc = ScmDesc::new(
            SVC_PIL,
            PIL_PAS_MEM_SETUP,
            arginfo(3, &[]),
            [peripheral as u64, addr, size, 0],
        );
        self.call_result0(&desc, delay).await
    }

    /// `qcom_scm_pas_auth_and_reset`.
    pub async fn pas_auth_and_reset<D: Delay + ?Sized>(
        &mut self,
        peripheral: u32,
        delay: &D,
    ) -> Result<(), ScmError> {
        let desc = ScmDesc::new(
            SVC_PIL,
            PIL_PAS_AUTH_AND_RESET,
            arginfo(1, &[]),
            [peripheral as u64, 0, 0, 0],
        );
        self.call_result0(&desc, delay).await
    }

    /// `qcom_scm_pas_shutdown`.
    pub async fn pas_shutdown<D: Delay + ?Sized>(
        &mut self,
        peripheral: u32,
        delay: &D,
    ) -> Result<(), ScmError> {
        let desc = ScmDesc::new(
            SVC_PIL,
            PIL_PAS_SHUTDOWN,
            arginfo(1, &[]),
            [peripheral as u64, 0, 0, 0],
        );
        self.call_result0(&desc, delay).await
    }
}
