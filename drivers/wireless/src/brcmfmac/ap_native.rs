// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual primary-bsscfg firmware transactions. Each per-poll/final check
//! uses only original fixed authority; an IOCTL ACK is a firmware operation
//! receipt, never a beacon TX, peer, key PN or packet ACK inferred by host.
use super::{
    ap_plan::{same_rates, Plan},
    ap_scope::Capture,
    ap_source::Source,
    ap_wire,
};
use crate::cyw43439::{fullmac::Fullmac, ioctl::Direction, runtime::Error};
use alloc::vec::Vec;
use core::{
    future::{poll_fn, Future},
    pin::pin,
    task::Poll,
};
use zeroize::Zeroizing;

pub(super) enum Guard<'a> {
    Program(&'a Capture),
    /// Original physical owner may stop/clear a revoked AP. This permits
    /// denial-only teardown, not a new RF/data/key publication.
    Stop(&'a Source),
}
impl Guard<'_> {
    fn current(&self) -> Result<(), Error> {
        match self {
            Self::Program(original) => original.current(),
            Self::Stop(native) => native.current(),
        }
        .map_err(|_| Error::Authority)
    }
}
pub(super) async fn command<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    direction: Direction,
    command: u32,
    input: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    guard.current()?;
    let mut future = pin!(async {
        match guard {
            Guard::Program(original) => {
                runtime
                    .command_ap(original, direction, command, input, maximum)
                    .await
            }
            Guard::Stop(_) => runtime.command(direction, command, input, maximum).await,
        }
    });
    poll_fn(|cx| {
        if let Err(error) = guard.current() {
            return Poll::Ready(Err(error));
        }
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(guard.current().and(result)),
        }
    })
    .await
}
pub(super) async fn set<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    command_id: u32,
    value: u32,
) -> Result<(), Error> {
    command(
        runtime,
        guard,
        Direction::Set,
        command_id,
        &value.to_le_bytes(),
        4,
    )
    .await
    .map(|_| ())
}
pub(super) async fn get<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    command_id: u32,
) -> Result<u32, Error> {
    scalar(&command(runtime, guard, Direction::Get, command_id, &[], 4).await?)
}
fn scalar(bytes: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| Error::Malformed)?,
    ))
}
pub(super) async fn get_var<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    name: &str,
    suffix: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    let mut input = Zeroizing::new(name.as_bytes().to_vec());
    input.push(0);
    input.extend_from_slice(suffix);
    command(runtime, guard, Direction::Get, 262, &input, maximum).await
}
pub(super) async fn get_int<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    name: &str,
) -> Result<u32, Error> {
    scalar(&get_var(runtime, guard, name, &[], 4).await?)
}
pub(super) async fn set_var<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    name: &str,
    body: &[u8],
) -> Result<(), Error> {
    let mut input = Zeroizing::new(name.as_bytes().to_vec());
    input.push(0);
    input.extend_from_slice(body);
    command(runtime, guard, Direction::Set, 263, &input, input.len())
        .await
        .map(|_| ())
}
pub(super) async fn set_int<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    name: &str,
    value: u32,
) -> Result<(), Error> {
    set_var(runtime, guard, name, &value.to_le_bytes()).await?;
    if get_int(runtime, guard, name).await? != value {
        return Err(Error::Malformed);
    }
    Ok(())
}
const SAVED: [&str; 9] = [
    "nmode",
    "vhtmode",
    "wme_bss_disable",
    "apsta",
    "ap_isolate",
    "mpc",
    "arpoe",
    "arp_ol",
    "ndoe",
];
#[derive(Clone, Copy)]
enum Variable {
    Known(u32),
    UnknownRead,
    Absent,
    ReadOnlyZero,
    DisabledWriteOnly,
}
pub(super) struct Saved {
    vars: [Variable; 9],
    beacon: u32,
    dtim: u32,
    events: [u8; 16],
}
impl Saved {
    pub(super) async fn read<R: Fullmac>(
        runtime: &mut R,
        original: &Capture,
    ) -> Result<Self, Error> {
        let guard = Guard::Program(original);
        if get(runtime, &guard, ap_wire::GET_AP).await? != 0 || get(runtime, &guard, 19).await? != 1
        {
            return Err(Error::Busy);
        }
        let mut vars = [Variable::UnknownRead; 9];
        for (index, name) in SAVED.iter().enumerate() {
            vars[index] = match get_int(runtime, &guard, name).await {
                Ok(value) => Variable::Known(value),
                Err(Error::Firmware(code)) if index >= 6 && code as i32 == -23 => {
                    Variable::UnknownRead
                }
                Err(error) => return Err(error),
            };
        }
        let events = get_var(runtime, &guard, "event_msgs", &[], 16)
            .await?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        Ok(Self {
            vars,
            beacon: get(runtime, &guard, ap_wire::GET_BEACON).await?,
            dtim: get(runtime, &guard, ap_wire::GET_DTIM).await?,
            events,
        })
    }
    async fn disable_offloads<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        guard: &Guard<'_>,
    ) -> Result<(), Error> {
        for (index, &name) in SAVED.iter().enumerate().skip(6) {
            match set_var(runtime, guard, name, &0u32.to_le_bytes()).await {
                Ok(()) => match self.vars[index] {
                    Variable::Known(_) => {
                        if get_int(runtime, guard, name).await? != 0 {
                            return Err(Error::Malformed);
                        }
                    }
                    Variable::UnknownRead => self.vars[index] = Variable::DisabledWriteOnly,
                    _ => return Err(Error::Malformed),
                },
                Err(Error::Firmware(code)) if code as i32 == -23 => {
                    self.vars[index] = match self.vars[index] {
                        Variable::UnknownRead => Variable::Absent,
                        Variable::Known(0) => Variable::ReadOnlyZero,
                        // A real observed enabled engine cannot be silently
                        // treated as absent when this image cannot disable it.
                        _ => return Err(Error::Unsupported),
                    };
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    async fn check_disabled<R: Fullmac>(
        &self,
        runtime: &mut R,
        guard: &Guard<'_>,
    ) -> Result<(), Error> {
        for (index, name) in SAVED.iter().enumerate().skip(6) {
            if matches!(
                self.vars[index],
                Variable::Known(_) | Variable::ReadOnlyZero
            ) && get_int(runtime, guard, name).await? != 0
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
    pub(super) async fn restore<R: Fullmac>(
        &self,
        runtime: &mut R,
        native: &Source,
    ) -> Result<(), Error> {
        let guard = Guard::Stop(native);
        set(runtime, &guard, ap_wire::DOWN, 1).await?;
        set(runtime, &guard, ap_wire::SET_AP, 0).await?;
        if get(runtime, &guard, ap_wire::GET_AP).await? != 0 {
            return Err(Error::Malformed);
        }
        set(runtime, &guard, ap_wire::INFRA, 1).await?;
        // Never replay a retired AP/STA credential or native key/port. A
        // later station join explicitly programs its own new security owner.
        for name in ["auth", "wsec", "wpa_auth", "sup_wpa"] {
            set_int(runtime, &guard, name, 0).await?;
        }
        for (name, value) in SAVED.iter().zip(self.vars) {
            match value {
                Variable::Known(value) => set_int(runtime, &guard, name, value).await?,
                Variable::ReadOnlyZero => {
                    if get_int(runtime, &guard, name).await? != 0 {
                        return Err(Error::Malformed);
                    }
                }
                Variable::DisabledWriteOnly => {
                    // No previous value was observed: never invent a saved
                    // zero or guess a re-enable. The ordinary host stack
                    // continues to own ARP/ND, as its station API already does.
                    set_var(runtime, &guard, name, &0u32.to_le_bytes()).await?;
                }
                Variable::Absent => {}
                Variable::UnknownRead => {
                    // Setup may have failed before probing this setter. No
                    // earlier value was observed, so denial-only cleanup can
                    // disable it or prove that the native API is absent.
                    match set_var(runtime, &guard, name, &0u32.to_le_bytes()).await {
                        Ok(()) => {}
                        Err(Error::Firmware(code)) if code as i32 == -23 => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        set(runtime, &guard, ap_wire::SET_BEACON, self.beacon).await?;
        set(runtime, &guard, ap_wire::SET_DTIM, self.dtim).await?;
        set_var(runtime, &guard, "event_msgs", &self.events).await?;
        set(runtime, &guard, ap_wire::UP, 1).await?;
        Ok(())
    }
}
/// Install exact caller vendor IEs. The AP firmware generates the standard
/// beacon/probe fields; this API never pretends to upload arbitrary templates.
pub(super) async fn vendor<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    installed: &[u8],
    requested: &[u8],
    flag: u32,
) -> Result<(), Error> {
    if installed == requested {
        return Ok(());
    }
    let mut input = Vec::new();
    for (command, mut rest) in [(b"del\0", installed), (b"add\0", requested)] {
        while !rest.is_empty() {
            let length = usize::from(*rest.get(1).ok_or(Error::Malformed)?);
            let element = rest.get(..2 + length).ok_or(Error::Malformed)?;
            if element[0] != 221 {
                return Err(Error::Malformed);
            }
            input.extend_from_slice(command);
            input.extend_from_slice(&1u32.to_le_bytes());
            input.extend_from_slice(&flag.to_le_bytes());
            input.extend_from_slice(element);
            rest = &rest[element.len()..];
        }
    }
    set_var(runtime, guard, "vndr_ie", &input).await
}
/// Validate actual firmware BSS fields after native SET_SSID completion. This
/// is a BSS observation, not an independently proven over-air beacon receipt.
pub(super) async fn verify<R: Fullmac>(
    runtime: &mut R,
    original: &Capture,
    plan: &Plan,
) -> Result<(), Error> {
    let guard = Guard::Program(original);
    if get(runtime, &guard, ap_wire::GET_AP).await? != 1
        || get(runtime, &guard, ap_wire::GET_BEACON).await? != plan.config.beacon_interval
        || get(runtime, &guard, ap_wire::GET_DTIM).await? != plan.config.dtim_period
        || get_int(runtime, &guard, "chanspec").await? != u32::from(plan.chanspec)
        || get_int(runtime, &guard, "nmode").await? != 0
        || get_int(runtime, &guard, "vhtmode").await? != 0
        || get_int(runtime, &guard, "wme_bss_disable").await? != 1
        || get_int(runtime, &guard, "ap_isolate").await? != 1
    {
        return Err(Error::Malformed);
    }
    let rates = command(runtime, &guard, Direction::Get, ap_wire::GET_RATES, &[], 20).await?;
    if !same_rates(&ap_wire::rates(&rates)?, &plan.rates) {
        return Err(Error::Unsupported);
    }
    let bss = command(
        runtime,
        &guard,
        Direction::Get,
        ap_wire::GET_BSS,
        &2048u32.to_le_bytes(),
        2048,
    )
    .await?;
    let bss = ap_wire::bss(&bss)?;
    if bss.own != plan.own
        || bss.ssid != plan.config.ssid
        || u32::from(bss.beacon_interval) != plan.config.beacon_interval
        || u32::from(bss.dtim) != plan.config.dtim_period
        || bss.capability != plan.capability
        || bss.chanspec != plan.chanspec
        || !same_rates(&bss.rates, &plan.rates)
    {
        return Err(Error::Malformed);
    }
    // Native variable IEs are optional. When supplied they are checked as a
    // complete vector, never treated as authority from a public BSS cache.
    if !bss.ies.is_empty() {
        let observed =
            Plan::observed_elements(bss.ies, &plan.config, original.policy.domain().country_code)?;
        if !same_rates(&observed.rates, &plan.rates)
            || observed.rsne != plan.rsne
            || observed.vendor != plan.beacon_vendor
        {
            return Err(Error::Malformed);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Prepared,
    Changing,
    BssRequested,
    Formed,
    Stopping,
    Restored,
}
/// `saved` has already been retained by the Session before this method can
/// mutate firmware. Phase records attempts, not an invented native receipt.
pub(super) async fn program<R: Fullmac>(
    runtime: &mut R,
    original: &Capture,
    plan: &Plan,
    power_dbm: u8,
    mfp_supported: bool,
    saved: &mut Saved,
    phase: &mut Phase,
) -> Result<(), Error> {
    let guard = Guard::Program(original);
    *phase = Phase::Changing;
    set_int(runtime, &guard, "mpc", 0).await?;
    saved.disable_offloads(runtime, &guard).await?;
    set(
        runtime,
        &guard,
        ap_wire::SET_BEACON,
        plan.config.beacon_interval,
    )
    .await?;
    set(runtime, &guard, ap_wire::SET_DTIM, plan.config.dtim_period).await?;
    set(runtime, &guard, ap_wire::DOWN, 1).await?;
    set_int(runtime, &guard, "apsta", 0).await?;
    set_int(runtime, &guard, "nmode", 0).await?;
    set_int(runtime, &guard, "vhtmode", 0).await?;
    set(runtime, &guard, ap_wire::INFRA, 1).await?;
    set(runtime, &guard, ap_wire::SET_AP, 1).await?;
    set_int(runtime, &guard, "chanspec", u32::from(plan.chanspec)).await?;
    set_int(runtime, &guard, "qtxpower", u32::from(power_dbm) * 4).await?;
    set_int(runtime, &guard, "ap_isolate", 1).await?;
    set_int(runtime, &guard, "wme_bss_disable", 1).await?;
    set(runtime, &guard, ap_wire::UP, 1).await?;
    set_int(runtime, &guard, "sup_wpa", 0).await?;
    set_int(runtime, &guard, "auth", 0).await?;
    // Linux's AP WPA/RSN configuration includes SES_OW_ENABLED (0x40).
    let wsec = if plan.rsne.is_some() { 4 | 0x40 } else { 0 };
    set_int(runtime, &guard, "wsec", wsec).await?;
    if mfp_supported {
        set_int(runtime, &guard, "mfp", 0).await?;
    }
    set_int(runtime, &guard, "wpa_auth", plan.wpa_auth).await?;
    set_int(
        runtime,
        &guard,
        "closednet",
        u32::from(plan.config.hidden_ssid == 1),
    )
    .await?;
    let mut mask = [0; 16];
    // Actual AP SME association/removal plus radio/firmware loss. No P2P
    // or extra-bsscfg namespace is created by enabling these observations.
    for event in [0usize, 5, 6, 8, 10, 11, 12, 16, 17, 23, 63] {
        mask[event / 8] |= 1 << (event % 8);
    }
    set_var(runtime, &guard, "event_msgs", &mask).await?;
    *phase = Phase::BssRequested;
    command(
        runtime,
        &guard,
        Direction::Set,
        ap_wire::SET_SSID,
        &ap_wire::ssid(&plan.config.ssid)?,
        52,
    )
    .await?;
    // Linux programs native vndr_ie after creating the primary BSS. The
    // successful public result still requires all template transactions.
    vendor(runtime, &guard, &[], &plan.beacon_vendor, 1).await?;
    vendor(runtime, &guard, &[], &plan.probe_vendor, 2).await?;
    verify(runtime, original, plan).await?;
    saved.check_disabled(runtime, &guard).await?;
    *phase = Phase::Formed;
    Ok(())
}
/// A complete native input idle observation is distinct from independently
/// proving firmware MAC/FIFO RX-key quiescence. This method claims only the
/// former; crypto/replay/SCB state remains firmware-owned.
pub(super) fn prefix<R: Fullmac>(runtime: &mut R) -> Result<bool, Error> {
    for _ in 0..4 {
        let count = runtime.poll()?;
        if count == 0 && runtime.ap_completed_prefix()? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Only the actual matching native install transaction can construct this
/// token. Its original whole wire body and source/role/peer bind the consumer;
/// an IOCTL for a different key cannot become an install receipt by metadata.
pub(super) struct KeyReceipt {
    body: [u8; 32],
    original: Capture,
}
fn key_body_digest(body: &[u8]) -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(body);
    hash.finalize()
}
impl KeyReceipt {
    pub(super) fn consume(self, key: &narf_wireless::KeyParams) -> Result<Capture, Error> {
        let body = super::ap_key::body(key)?;
        if key_body_digest(&body[..]) != self.body {
            return Err(Error::Malformed);
        }
        self.original.current().map_err(|_| Error::Authority)?;
        Ok(self.original)
    }
}
pub(super) async fn install_key<R: Fullmac>(
    runtime: &mut R,
    original: &Capture,
    key: &narf_wireless::KeyParams,
) -> Result<KeyReceipt, Error> {
    let body = super::ap_key::body(key)?;
    let guard = Guard::Program(original);
    set_var(runtime, &guard, "wsec_key", &body[..]).await?;
    original.current().map_err(|_| Error::Authority)?;
    Ok(KeyReceipt {
        body: key_body_digest(&body[..]),
        original: original.clone(),
    })
}
