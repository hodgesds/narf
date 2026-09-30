//! Async 8b/10b DisplayPort link training. Source and sink are programmed as
//! one transaction; AUX success alone never proves a trained link. References:
//! Linux link_dp_training_8b_10b.c and link_dp_training_dpia.c.
use core::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Bandwidth,
    Aux,
    Source,
    ClockRecovery,
    Equalization,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub rate: u8,
    pub lanes: u8,
    pub enhanced: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// DPCD rate code: 6=RBR, 10=HBR, 20=HBR2, 30=HBR3.
    pub rate: u8,
    /// Must reflect the actual Type-C lane assignment (two or four lanes).
    pub lanes: u8,
    pub pixel_clock_khz: u32,
    pub bits_per_pixel: u8,
    /// A transparent USB4 DPIA trains the remote PHY itself. The host writes
    /// sink patterns and reads status, without applying native voltage settings.
    pub dpia: bool,
}
/// The implementation owns the AUX channel and source encoder for the entire
/// operation. Cancelling a training future requires disabling that source
/// before reusing its scanout memory or starting another training operation.
pub trait LinkIo {
    fn read(
        &mut self,
        address: u32,
        data: &mut [u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;
    fn write(
        &mut self,
        address: u32,
        data: &[u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;
    fn configure(&mut self, settings: Settings) -> impl Future<Output = Result<(), Error>> + Send;
    /// 0=video, 1=TPS1, 2=TPS2, 3=TPS3, 7=TPS4.
    fn pattern(&mut self, pattern: u8) -> impl Future<Output = Result<(), Error>> + Send;
    fn tune(&mut self, lanes: &[u8]) -> impl Future<Output = Result<(), Error>> + Send;
    fn disable(&mut self) -> impl Future<Output = Result<(), Error>> + Send;
    fn delay_us(&mut self, microseconds: u32) -> impl Future<Output = ()> + Send;
}
fn supported_rate(rate: u8) -> bool {
    matches!(rate, 6 | 10 | 20 | 30)
}
fn fits(settings: Settings, limits: Limits) -> bool {
    limits.pixel_clock_khz as u64 * limits.bits_per_pixel as u64
        <= settings.rate as u64 * 27000 * 8 * settings.lanes as u64
}
fn done(status: &[u8; 6], lanes: u8, mask: u8) -> bool {
    (0..lanes as usize).all(|lane| (status[lane / 2] >> (4 * (lane % 2))) & mask == mask)
}
fn adjustment(status: &[u8; 6], lanes: u8) -> [u8; 4] {
    // Native DIO uses a common PHY level: satisfy the highest request across
    // all lanes, clamped to the DP swing+pre-emphasis <= 3 constraint.
    let mut swing = 0;
    let mut pre = 0;
    for lane in 0..lanes as usize {
        let request = status[4 + lane / 2] >> (4 * (lane % 2));
        swing = swing.max(request & 3);
        pre = pre.max((request >> 2) & 3);
    }
    pre = pre.min(3 - swing);
    let bits = swing
        | (pre << 3)
        | if swing == 3 { 4 } else { 0 }
        | if pre == 3 - swing { 0x20 } else { 0 };
    [bits; 4]
}
async fn set_pattern(io: &mut impl LinkIo, pattern: u8, dpia: bool) -> Result<(), Error> {
    if !dpia || pattern == 0 {
        io.pattern(pattern).await?;
    }
    // TPS1..3 require scrambling disabled; TPS4 uses scrambling.
    io.write(
        0x102,
        &[pattern | if matches!(pattern, 1..=3) { 0x20 } else { 0 }],
    )
    .await
}
async fn attempt(
    io: &mut impl LinkIo,
    settings: Settings,
    caps: &[u8; 16],
    limits: Limits,
) -> Result<(), Error> {
    io.configure(settings).await?;
    if caps[0] >= 0x11 {
        io.write(0x600, &[1]).await?;
        io.delay_us(1000).await;
    }
    // 8b/10b, no spread. DSC/FEC are not advertised by this SST path.
    io.write(0x107, &[0, 1]).await?;
    io.write(
        0x100,
        &[
            settings.rate,
            settings.lanes | if settings.enhanced { 0x80 } else { 0 },
        ],
    )
    .await?;
    set_pattern(io, 1, limits.dpia).await?;
    let interval = caps[14] & 0x7f;
    if interval > 4 {
        return Err(Error::Invalid);
    }
    let mut levels = [0u8; 4];
    let mut same = 0;
    let mut recovered = false;
    for _ in 0..20 {
        if !limits.dpia {
            io.tune(&levels[..settings.lanes as usize]).await?;
            io.write(0x103, &levels[..settings.lanes as usize]).await?;
        }
        io.delay_us(if interval == 0 {
            100
        } else {
            interval as u32 * 4000
        })
        .await;
        let mut status = [0; 6];
        io.read(0x202, &mut status).await?;
        if done(&status, settings.lanes, 1) {
            recovered = true;
            break;
        }
        let next = adjustment(&status, settings.lanes);
        if next == levels {
            same += 1;
        } else {
            same = 0;
        }
        if same >= 5 || levels[0] & 4 != 0 {
            break;
        }
        levels = next;
    }
    if !recovered {
        return Err(Error::ClockRecovery);
    }
    let pattern = if settings.rate == 30 && caps[3] & 0x80 != 0 {
        7
    } else if settings.rate >= 20 && caps[2] & 0x40 != 0 {
        3
    } else {
        2
    };
    set_pattern(io, pattern, limits.dpia).await?;
    for _ in 0..6 {
        if !limits.dpia {
            io.tune(&levels[..settings.lanes as usize]).await?;
            io.write(0x103, &levels[..settings.lanes as usize]).await?;
        }
        io.delay_us(if interval == 0 {
            400
        } else {
            interval as u32 * 4000
        })
        .await;
        let mut status = [0; 6];
        io.read(0x202, &mut status).await?;
        if !done(&status, settings.lanes, 1) {
            return Err(Error::ClockRecovery);
        }
        if done(&status, settings.lanes, 7) && status[2] & 1 != 0 {
            set_pattern(io, 0, limits.dpia).await?;
            return Ok(());
        }
        levels = adjustment(&status, settings.lanes);
    }
    Err(Error::Equalization)
}
/// Train only combinations able to carry the requested uncompressed mode.
/// Each failed attempt disables the source before trying a lower link rate.
/// Malformed replies/transport errors abort instead of masquerading as fallback.
pub async fn train(
    io: &mut impl LinkIo,
    caps: [u8; 16],
    limits: Limits,
) -> Result<Settings, Error> {
    if !supported_rate(limits.rate)
        || !supported_rate(caps[1])
        || !matches!(limits.lanes, 1 | 2 | 4)
        || !matches!(caps[2] & 0x1f, 1 | 2 | 4)
        || limits.pixel_clock_khz == 0
        || !matches!(limits.bits_per_pixel, 18 | 24 | 30)
        || !(0x10..=0x14).contains(&caps[0])
        || caps[14] & 0x7f > 4
    {
        return Err(Error::Invalid);
    }
    let mut last = Error::Bandwidth;
    for lanes in [4, 2, 1] {
        if lanes > limits.lanes.min(caps[2] & 0x1f) {
            continue;
        }
        for rate in [30, 20, 10, 6] {
            if rate > limits.rate.min(caps[1]) {
                continue;
            }
            if rate == 30 && caps[3] & 0x80 == 0 {
                continue;
            }
            let settings = Settings {
                rate,
                lanes,
                enhanced: caps[2] & 0x80 != 0,
            };
            if !fits(settings, limits) {
                continue;
            }
            match attempt(io, settings, &caps, limits).await {
                Ok(()) => return Ok(settings),
                Err(error) => {
                    // Attempt both cleanups, even if the sink disappeared.
                    let sink = io.write(0x102, &[0]).await;
                    let source = io.disable().await;
                    source?;
                    sink?;
                    if !matches!(error, Error::ClockRecovery | Error::Equalization) {
                        return Err(error);
                    }
                    last = error;
                }
            }
        }
    }
    Err(last)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dp_training_tests.rs"]
mod tests;
