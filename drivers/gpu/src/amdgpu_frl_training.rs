//! Linux's HDMI FRL link training (link/protocols/link_hdmi_frl.c):
//! hdmi_frl_perform_link_training's LTS:1-3 over SCDC, with the source's
//! training patterns and TxFFE, its retries
//! (hdmi_frl_perform_link_training_with_retries) and the LTS:P wait for
//! FRL_Start (hdmi_frl_poll_start). Generic over the SCDC, encoder and
//! firmware side so the sequence itself is model-tested.

use core::future::Future;

/// SCDC registers (dc_hdmi_types.h).
pub const SINK_VERSION: u8 = 0x01;
pub const SOURCE_VERSION: u8 = 0x02;
pub const UPDATE_0: u8 = 0x10;
pub const CONFIG_1: u8 = 0x31;
pub const SOURCE_TEST: u8 = 0x35;
pub const STATUS_FLAGS_0: u8 = 0x40;
pub const LTP_REQ: u8 = 0x41;
const FRL_START: u8 = 0x10;
const SOURCE_TEST_UPDATE: u8 = 0x08;
const FLT_UPDATE: u8 = 0x20;
const FLT_READY: u8 = 0x40;
const FLT_NO_TIMEOUT: u8 = 0x20;
/// Polls of FLT_Ready and FLT_Update, at least 2 ms apart (500 for
/// FLT_Update with FLT_no_timeout).
const MAX_POLLS: u32 = 105;
const NO_TIMEOUT_POLLS: u32 = 500;
const POLL_US: u64 = 2000;
/// dcn401's debug.limit_ffe: FFE levels 0..3.
const FFE_LEVELS: u8 = 3;
/// LINK_TRAINING_ATTEMPTS for FRL: max_retries 3, four tries, 200 ms apart.
const ATTEMPTS: u32 = 4;
const RETRY_US: u64 = 200_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrlTraining {
    Success,
    /// The sink asked for a lower rate (0xF on a lane).
    LowerRate,
    /// No FLT_Ready, or no passing request in time.
    Timeout,
    /// Sink_Version 0: no FRL.
    Fallback,
}

/// The source side of training: SCDC over DDC, the HPO FRL link
/// encoder's patterns and the transmitter's TxFFE.
pub trait FrlTrainer {
    type Error;
    fn scdc_read(&mut self, offset: u8) -> impl Future<Output = Result<u8, Self::Error>>;
    fn scdc_write(
        &mut self,
        offset: u8,
        value: u8,
    ) -> impl Future<Output = Result<(), Self::Error>>;
    /// hpo_frl_link_enc3_set_training_pattern: LTP - 1 per lane; 8 and
    /// above leave the lane.
    fn pattern(&mut self, patterns: [u8; 4]) -> Result<(), Self::Error>;
    /// dpcs401_program_eq_setting's lane set.
    fn ffe(&mut self, lane_set: u8) -> impl Future<Output = Result<(), Self::Error>>;
    fn delay(&mut self, us: u64) -> impl Future<Output = ()>;
}

/// Live status additionally needs the last acknowledged transmitter FFE level.
pub trait FrlStatusIo: FrlTrainer {
    fn current_ffe(&mut self) -> Result<u8, Self::Error>;
}

/// Linux's hdmi_frl_poll_status_flag. Returns true when the caller must stop
/// and retrain the display through its normal ownership/retirement path.
/// That request stays pending until teardown clears it, so cancellation of
/// the monitor cannot lose it. Source-test changes are acknowledged only
/// after the source has accepted them; unrelated W1C flags are preserved.
pub async fn poll_status<T: FrlStatusIo>(t: &mut T) -> Result<bool, T::Error> {
    let test = t.scdc_read(SOURCE_TEST).await?;
    let no_timeout = test & FLT_NO_TIMEOUT != 0;
    let update = t.scdc_read(UPDATE_0).await?;
    if update & FRL_START != 0 {
        t.scdc_write(UPDATE_0, FRL_START).await?;
    }
    if update & FLT_UPDATE != 0 {
        let a = t.scdc_read(LTP_REQ).await?;
        let b = t.scdc_read(LTP_REQ + 1).await?;
        let lanes = [a & 0xf, a >> 4, b & 0xf, b >> 4];
        t.pattern(lanes.map(|l| {
            if l == 3 && !no_timeout {
                0xf // Leave LTP3 unchanged outside a source test.
            } else {
                l.wrapping_sub(1)
            }
        }))?;
        if lanes.contains(&0xe) {
            let level = (t.current_ffe()? + 1) & FFE_LEVELS;
            t.ffe(lane_set(level, test)).await?;
        } else if !no_timeout {
            return Ok(true);
        }
        t.scdc_write(UPDATE_0, FLT_UPDATE).await?;
    }
    if update & SOURCE_TEST_UPDATE != 0 {
        let test = t.scdc_read(SOURCE_TEST).await?;
        let level = t.current_ffe()?;
        t.ffe(lane_set(level, test)).await?;
        t.scdc_write(UPDATE_0, SOURCE_TEST_UPDATE).await?;
    }
    Ok(false)
}

/// dpcs401_program_eq_setting: the FFE level, then de-emphasis-only (bit
/// 5) and pre-shoot-only (bit 6), both for No_FFE, from Source_Test.
fn lane_set(level: u8, test: u8) -> u8 {
    let no_ffe = test & 8 != 0;
    let de = test & 4 != 0 || no_ffe;
    let pre = test & 2 != 0 || no_ffe;
    u8::from(de) << 5 | u8::from(pre) << 6 | (level & 3)
}

/// hdmi_frl_LTS_clear_Link_Setting.
async fn clear_link_setting<T: FrlTrainer>(t: &mut T) -> Result<(), T::Error> {
    if t.scdc_read(CONFIG_1).await? & 0xf != 0 {
        t.scdc_write(CONFIG_1, 0).await?;
    }
    Ok(())
}

/// hdmi_frl_LTS_clear_Update_flag.
async fn clear_update_flag<T: FrlTrainer>(t: &mut T) -> Result<(), T::Error> {
    if t.scdc_read(UPDATE_0).await? & FLT_UPDATE != 0 {
        t.scdc_write(UPDATE_0, FLT_UPDATE).await?;
    }
    Ok(())
}

/// hdmi_frl_perform_link_training at `rate` (the SCDC FRL_Rate code) on
/// `lanes` (3 or 4) lanes.
pub async fn train<T: FrlTrainer>(t: &mut T, rate: u8, lanes: u8) -> Result<FrlTraining, T::Error> {
    // LTS:1.
    clear_link_setting(t).await?;
    match t.scdc_read(SINK_VERSION).await? {
        0 => return Ok(FrlTraining::Fallback),
        1 => t.scdc_write(SOURCE_VERSION, 1).await?,
        _ => {}
    }
    // LTS:2: FLT_Ready, then TxFFE level 0.
    let mut ready = false;
    for _ in 0..MAX_POLLS {
        t.delay(POLL_US).await;
        if t.scdc_read(STATUS_FLAGS_0).await? & FLT_READY != 0 {
            clear_update_flag(t).await?;
            t.ffe(lane_set(0, 0)).await?;
            ready = true;
            break;
        }
    }
    let test = t.scdc_read(SOURCE_TEST).await?;
    let no_timeout = test & FLT_NO_TIMEOUT != 0;
    if !ready {
        return Ok(FrlTraining::Timeout);
    }
    // LTS:3.
    t.scdc_write(CONFIG_1, rate | FFE_LEVELS << 4).await?;
    let polls = if no_timeout {
        NO_TIMEOUT_POLLS
    } else {
        MAX_POLLS
    };
    let mut ln = [0u8; 4];
    let mut ffe = 0u8;
    let mut override_ffe = false;
    for _ in 0..polls {
        t.delay(POLL_US).await;
        let update = t.scdc_read(UPDATE_0).await?;
        let flt_update = update & FLT_UPDATE != 0;
        if override_ffe {
            if no_timeout {
                ffe = 0;
            }
            if ffe == 0 || flt_update {
                t.ffe(lane_set(ffe, test)).await?;
            }
            override_ffe = false;
        }
        if !flt_update {
            continue;
        }
        let req = [t.scdc_read(LTP_REQ).await?, t.scdc_read(LTP_REQ + 1).await?];
        let prev = ln;
        ln = [req[0] & 0xf, req[0] >> 4, req[1] & 0xf, req[1] >> 4];
        t.scdc_write(UPDATE_0, FLT_UPDATE).await?;
        if ln.contains(&3) && !no_timeout {
            continue;
        }
        if lanes == 3 {
            ln[3] = 1;
        }
        let active = &ln[..usize::from(lanes)];
        if active.iter().all(|&l| l == 0) {
            return Ok(FrlTraining::Success);
        }
        if active.contains(&0xf) {
            return Ok(FrlTraining::LowerRate);
        }
        if active.contains(&0xe) {
            ffe += 1;
            override_ffe = true;
            if ffe > FFE_LEVELS || no_timeout {
                ffe = 0;
            }
        }
        if override_ffe {
            ln = prev;
        }
        t.pattern(ln.map(|l| l.wrapping_sub(1)))?;
    }
    if no_timeout {
        return Ok(FrlTraining::Success);
    }
    t.scdc_write(CONFIG_1, 0).await?;
    clear_link_setting(t).await?;
    Ok(FrlTraining::Timeout)
}

/// hdmi_frl_perform_link_training_with_retries: up to four tries, 200 ms
/// apart from the second; a lower-rate request or Sink_Version 0 ends it.
pub async fn train_with_retries<T: FrlTrainer>(
    t: &mut T,
    rate: u8,
    lanes: u8,
) -> Result<FrlTraining, T::Error> {
    let mut result = FrlTraining::Timeout;
    for attempt in 0..ATTEMPTS {
        if attempt != 0 {
            t.delay(RETRY_US).await;
        }
        result = train(t, rate, lanes).await?;
        if matches!(
            result,
            FrlTraining::Success | FrlTraining::LowerRate | FrlTraining::Fallback
        ) {
            return Ok(result);
        }
    }
    Ok(if result == FrlTraining::Timeout {
        FrlTraining::Fallback
    } else {
        result
    })
}

/// hdmi_frl_poll_start (LTS:P), once the encoder sends FRL output: unless
/// FLT_no_timeout, up to 200 ms for FRL_Start (or a new FLT_Update),
/// acknowledging whichever came.
pub async fn poll_start<T: FrlTrainer>(t: &mut T) -> Result<(), T::Error> {
    if t.scdc_read(SOURCE_TEST).await? & FLT_NO_TIMEOUT != 0 {
        return Ok(());
    }
    for _ in 0..100 {
        t.delay(POLL_US).await;
        let update = t.scdc_read(UPDATE_0).await?;
        if update & FRL_START != 0 {
            return t.scdc_write(UPDATE_0, FRL_START).await;
        }
        if update & FLT_UPDATE != 0 {
            return t.scdc_write(UPDATE_0, FLT_UPDATE).await;
        }
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_frl_training_tests.rs"]
mod tests;
