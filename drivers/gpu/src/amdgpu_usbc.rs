//! Type-C and USB4 sink discovery through DMUB. Connector events request a
//! rescan; a UCSI connector number is never used as a GPU PHY/AUX index.
use super::amdgpu_dmub::{Channel, Dmub, Error};
use alloc::{sync::Arc, vec::Vec};
use core::{
    fmt::Write as _,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering},
};
use narf_lib::sync::IrqSafeSpinLock;

/// Detection is distinct from an active scanout. A successful EDID read does
/// not imply source encoder configuration or DisplayPort link training.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sink {
    pub channel: Channel,
    pub instance: u8,
    pub dpcd: [u8; 16],
    pub edid: Vec<u8>,
}
static SINKS: IrqSafeSpinLock<Vec<Sink>> = IrqSafeSpinLock::new(Vec::new());
static OWNED: AtomicBool = AtomicBool::new(false);
// 0 idle, 1 mailbox cycle in progress, 2 suspended. Suspend never waits for
// another executor task while holding a synchronous PM callback's context.
static PHASE: AtomicU8 = AtomicU8::new(0);
static DIRTY: AtomicBool = AtomicBool::new(true);
static GENERATION: AtomicU32 = AtomicU32::new(0);
pub fn sinks() -> Vec<Sink> {
    SINKS.lock().clone()
}
pub(crate) fn owns_dmub() -> bool {
    OWNED.load(Ordering::Acquire)
}
pub(crate) fn suspend() -> bool {
    !owns_dmub()
        || PHASE
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}
pub(crate) fn resume() {
    if PHASE.load(Ordering::Acquire) != 2 {
        return;
    }
    GENERATION.fetch_add(1, Ordering::AcqRel);
    PHASE.store(0, Ordering::Release);
    DIRTY.store(true, Ordering::Release);
}
struct Observer;
impl narf_drivers_usbpd::ucsi::ConnectorObserver for Observer {
    fn changed(&self, _: &narf_drivers_usbpd::ucsi::Connector) {
        DIRTY.store(true, Ordering::Release);
    }
}
async fn aux(
    dmub: &mut Dmub,
    channel: Channel,
    instance: u8,
    action: u8,
    address: u32,
    data: &mut [u8],
) -> Result<(), Error> {
    for _ in 0..7 {
        match dmub.aux(channel, instance, action, address, data).await {
            Err(Error::Aux(2 | 8)) => {
                narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await
            }
            other => return other,
        }
    }
    Err(Error::Aux(2))
}
async fn edid(dmub: &mut Dmub, channel: Channel, instance: u8) -> Result<Vec<u8>, Error> {
    // Reset an E-EDID segment left by an earlier read. Sinks without a
    // segment pointer may NACK address 0x30; their base block is still valid.
    match aux(dmub, channel, instance, 0, 0x30, &mut [0]).await {
        Ok(()) | Err(Error::Aux(1 | 4)) => {}
        Err(e) => return Err(e),
    }
    let result = async {
        let mut bytes = Vec::new();
        let mut blocks = 1usize;
        let mut block = 0;
        while block < blocks {
            if block >= 2 && block % 2 == 0 {
                aux(dmub, channel, instance, 0, 0x30, &mut [(block / 2) as u8]).await?;
            }
            aux(
                dmub,
                channel,
                instance,
                0x40,
                0x50,
                &mut [((block % 2) * 128) as u8],
            )
            .await?;
            let start = bytes.len();
            bytes.resize(start + 128, 0);
            for offset in (0..128).step_by(16) {
                aux(
                    dmub,
                    channel,
                    instance,
                    if offset == 112 { 0x10 } else { 0x50 },
                    0x50,
                    &mut bytes[start + offset..start + offset + 16],
                )
                .await?;
            }
            if block == 0 {
                narf_edid::Block::parse(&bytes).map_err(|_| Error::Invalid)?;
                if bytes[126] > 4 {
                    return Err(Error::Invalid);
                }
                blocks = 1 + bytes[126] as usize;
            } else if bytes[start..]
                .iter()
                .fold(0u8, |sum, b| sum.wrapping_add(*b))
                != 0
            {
                return Err(Error::Invalid);
            }
            block += 1;
        }
        Ok(bytes)
    }
    .await;
    if result.is_err() {
        // A failed MOT transfer may leave the sink's I2C transaction open.
        // The transport rejects this safely if the DMUB itself was poisoned.
        let _ = aux(dmub, channel, instance, 0x10, 0x50, &mut []).await;
    }
    result
}

async fn scan(dmub: &mut Dmub) -> Result<Vec<Sink>, Error> {
    let mut result = Vec::new();
    // DCN314 exposes four DPIAs (dcn314_resource.c), independently of the
    // number of NHI PCI functions or physical receptacles. Native AUX channels
    // are probed directly, without assuming an HPD-to-DDC wiring map.
    for (channel, count) in [(Channel::Legacy, 6), (Channel::Dpia, 4)] {
        for instance in 0..count {
            if channel == Channel::Dpia {
                match dmub.hpd(instance, channel).await {
                    Ok(true) => {}
                    Ok(false) | Err(Error::Firmware(_)) => continue,
                    Err(e) => return Err(e),
                }
            }
            let mut dpcd = [0; 16];
            match aux(dmub, channel, instance, 0x90, 0, &mut dpcd).await {
                Ok(()) if (0x10..=0x20).contains(&dpcd[0]) => {}
                Ok(()) | Err(Error::Firmware(_) | Error::Aux(_)) => continue,
                Err(e) => return Err(e),
            }
            match edid(dmub, channel, instance).await {
                Ok(edid) => result.push(Sink {
                    channel,
                    instance,
                    dpcd,
                    edid,
                }),
                Err(Error::Firmware(_) | Error::Aux(_) | Error::Invalid) => continue,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(result)
}
pub(crate) fn start() -> narf_init::InitResult {
    if !super::amdgpu::is_probed() || OWNED.swap(true, Ordering::AcqRel) {
        return narf_init::InitResult::NotPresent;
    }
    PHASE.store(1, Ordering::Release);
    let dmub = super::amdgpu::with_controller(|gpu| {
        // SAFETY: OWNED excludes firmware replacement and GPU suspend while
        // a mailbox cycle is in progress. This is the sole DMUB client.
        unsafe { Dmub::attach(gpu) }
    });
    let Some(Ok(mut dmub)) = dmub else {
        PHASE.store(0, Ordering::Release);
        OWNED.store(false, Ordering::Release);
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu-usbc: native DCN314 DAL firmware/mailbox unavailable: {dmub:?}"
        );
        return narf_init::InitResult::NotPresent;
    };
    narf_drivers_usbpd::ucsi::register_observer(Arc::new(Observer));
    narf_scheduler::spawn(async move {
        let mut generation = GENERATION.load(Ordering::Acquire);
        let setup = dmub.enable_notifications().await;
        PHASE.store(0, Ordering::Release);
        if let Err(e) = setup {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu-usbc: DMUB notification setup failed: {e:?}"
            );
            // Retain ownership on failure: a late firmware reply may still
            // arrive, so no other client may attach to the same mailbox.
            return;
        }
        loop {
            if PHASE
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let current = GENERATION.load(Ordering::Acquire);
                if current != generation {
                    // Firmware can relocate its VRAM mailbox over suspend.
                    // Reattach under the GPU lock while PM sees us as busy.
                    let attached = super::amdgpu::with_controller(|gpu| {
                        // SAFETY: this task retains sole DMUB ownership and
                        // PHASE excludes GPU suspend during reattachment.
                        unsafe { Dmub::attach(gpu) }
                    });
                    match attached {
                        Some(Ok(new)) => dmub = new,
                        _ => {
                            SINKS.lock().clear();
                            PHASE.store(0, Ordering::Release);
                            break;
                        }
                    }
                    if dmub.enable_notifications().await.is_err() {
                        SINKS.lock().clear();
                        PHASE.store(0, Ordering::Release);
                        break;
                    }
                    generation = current;
                }
                let found = scan(&mut dmub).await;
                PHASE.store(0, Ordering::Release);
                match found {
                    Ok(found) => {
                        let mut sinks = SINKS.lock();
                        if *sinks != found {
                            let _ = writeln!(
                                narf_console::Writer,
                                "amdgpu-usbc: {} sinks detected; native encoder modeset required",
                                found.len()
                            );
                            *sinks = found;
                        }
                    }
                    Err(e) => {
                        SINKS.lock().clear();
                        let _ = writeln!(narf_console::Writer, "amdgpu-usbc: DMUB stopped: {e:?}");
                        break;
                    }
                }
            }
            DIRTY.store(false, Ordering::Release);
            for _ in 0..10 {
                narf_time::SleepUntil::new(narf_time::Deadline::after_ms(100).as_instant()).await;
                if DIRTY.swap(false, Ordering::AcqRel) {
                    break;
                }
            }
        }
    });
    narf_init::InitResult::Ok
}
