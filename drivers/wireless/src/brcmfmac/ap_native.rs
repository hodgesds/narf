// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual primary-bsscfg firmware transactions. Each per-poll/final check
//! uses only original fixed authority; an IOCTL ACK is a firmware operation
//! receipt, never a beacon TX, peer, key PN or packet ACK inferred by host.
use super::{
    ap_plan::{same_rates, Plan},
    ap_scope::Capture,
    ap_source::Source,
    ap_wire,
    event_mask::{self, Need},
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
/// Which interface an AP Program addresses (Linux 7.3-rc4
/// `cfg80211.c::brcmf_cfg80211_start_ap` / `brcmf_cfg80211_stop_ap`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Interface 0: the established device-wide primary Program.
    Primary,
    /// A secondary bsscfg on its own ifidx (`vif_bsscfg::Bsscfg`). Linux
    /// `start_ap` never writes `event_msgs`, `nmode`, `vhtmode` or
    /// `qtxpower`, so this scope leaves the primary's device-wide event
    /// mask (it only adds the AP SME bits) and PHY modes untouched.
    Secondary {
        /// `BRCMF_C_DOWN` + `apsta 0` before `SET_INFRA`: Linux issues
        /// them for an AP vif only when `ifp->ifidx == 0` or the firmware
        /// has neither `BRCMF_FEAT_RSDB` nor `BRCMF_FEAT_MCHAN`.
        down_apsta: bool,
        /// `BRCMF_FEAT_MBSS`: `mbss 1` before `SET_AP` when this AP
        /// first enables firmware MBSS mode (no other secondary AP
        /// running), and `mbss 0` on stop only when it is the last
        /// MBSS AP (see `Saved::restore`'s `clear_mbss`).
        mbss: bool,
    },
    /// A P2P GO connection bsscfg (`vif_owner::create_p2p`, `p2p_ifadd`
    /// GO): Linux 7.3-rc4 `brcmf_cfg80211_start_ap` P2P_GO branch. The
    /// shared radio setup (`mpc 0`, offloads, `BCNPRD`, `DTIMPRD`,
    /// `SET_INFRA 1`) runs as for the first AP, but without `DOWN`/`apsta`,
    /// `mbss`, `SET_AP` or `UP`; the BSS is formed by `chanspec`, the
    /// security iovars, bsscfg `ssid` and `bss` enable for `bsscfgidx`
    /// (`brcmf_fil_bss_enable_le`), and stopped by `bss` disable
    /// (`brcmf_cfg80211_stop_ap` non-AP branch).
    Go {
        /// The GO connection bsscfg's firmware index (`ifp->bsscfgidx`).
        bsscfgidx: u8,
    },
}
impl Scope {
    /// Linux `brcmf_cfg80211_start_ap` rules for a secondary AP vif.
    /// `other_ap` is true once another AP already exists: the shared
    /// radio setup (DOWN/apsta) is skipped (Linux `vif->mbss` path).
    /// `other_secondary_active` is true once another secondary AP is
    /// actually running: firmware MBSS mode is then already enabled
    /// (a running primary AP never enables it), so `mbss 1` is skipped;
    /// otherwise the first secondary AP enables it. RSDB is not parsed
    /// by NARF (`rsdb_mode`); it is treated as absent.
    pub(crate) fn secondary(
        features: super::vif_wire::Features,
        other_ap: bool,
        other_secondary_active: bool,
    ) -> Self {
        Self::Secondary {
            down_apsta: !features.mchan && !other_ap,
            mbss: features.mbss && !other_secondary_active,
        }
    }
    /// Whether this scope writes (and therefore must save and restore) the
    /// `SAVED` var at `index`. A secondary never writes the device-wide
    /// PHY modes (`nmode`, `vhtmode`), and writes `apsta` only when it
    /// takes the radio down (`down_apsta`); a GO writes neither. The
    /// offloads and the per-BSS vars are written by every scope.
    fn writes_saved(self, index: usize) -> bool {
        match self {
            Self::Primary => true,
            Self::Secondary { down_apsta, .. } => index >= 2 && (index != 3 || down_apsta),
            Self::Go { .. } => index >= 2 && index != 3,
        }
    }
    fn primary(self) -> bool {
        self == Self::Primary
    }
    /// The P2P GO scope's bsscfg index.
    pub(super) fn go(self) -> Option<u8> {
        match self {
            Self::Go { bsscfgidx } => Some(bsscfgidx),
            _ => None,
        }
    }
    /// A scope is only valid on its own kind of runtime: the primary
    /// Program never runs through a bsscfg view, nor a secondary on ifidx 0.
    pub(crate) fn admits<R: Fullmac>(self) -> Result<(), Error> {
        if self.primary() == R::BSSCFG || !self.primary() && !R::SECONDARY_AP {
            return Err(Error::Authority);
        }
        Ok(())
    }
}
/// AP SME events (association/removal plus radio/firmware loss).
const AP_EVENTS: [usize; 11] = [0, 5, 6, 8, 10, 11, 12, 16, 17, 23, 63];
#[derive(Clone, Copy)]
enum Variable {
    Known(u32),
    UnknownRead,
    Absent,
    ReadOnlyZero,
    DisabledWriteOnly,
}
pub(super) struct Saved {
    scope: Scope,
    vars: [Variable; 9],
    beacon: u32,
    dtim: u32,
    events: [u8; 16],
}
impl Saved {
    pub(super) async fn read<R: Fullmac>(
        runtime: &mut R,
        original: &Capture,
        scope: Scope,
    ) -> Result<Self, Error> {
        scope.admits::<R>()?;
        let guard = Guard::Program(original);
        // A GO bsscfg is created in the AP role by `p2p_ifadd`; Linux
        // checks no AP/infra precondition on it.
        if scope.go().is_none()
            && (get(runtime, &guard, ap_wire::GET_AP).await? != 0
                || get(runtime, &guard, 19).await? != 1)
        {
            return Err(Error::Busy);
        }
        let mut vars = [Variable::UnknownRead; 9];
        for (index, name) in SAVED.iter().enumerate() {
            // Never touch a var this scope does not write: a secondary
            // program must contain no `apsta` command at all (Linux
            // `start_ap` leaves the device-wide STA/AP mode to the
            // primary), and the PHY modes belong to the primary alone.
            if !scope.writes_saved(index) {
                continue;
            }
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
            scope,
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
        clear_mbss: bool,
    ) -> Result<(), Error> {
        let guard = Guard::Stop(native);
        let go = self.scope.go().is_some();
        // A GO's BSS was already disabled by `bss` 0 (`ap_stop`); Linux
        // never takes the radio down or clears `SET_AP` for it.
        if !go {
            set(runtime, &guard, ap_wire::DOWN, 1).await?;
            set(runtime, &guard, ap_wire::SET_AP, 0).await?;
            if get(runtime, &guard, ap_wire::GET_AP).await? != 0 {
                return Err(Error::Malformed);
            }
            set(runtime, &guard, ap_wire::INFRA, 1).await?;
        }
        // Never replay a retired AP/STA credential or native key/port. A
        // later station join explicitly programs its own new security owner.
        for name in ["auth", "wsec", "wpa_auth", "sup_wpa"] {
            set_int(runtime, &guard, name, 0).await?;
        }
        for (index, (name, value)) in SAVED.iter().zip(self.vars).enumerate() {
            // Restore only what this scope wrote (`read` only saved those).
            if !self.scope.writes_saved(index) {
                continue;
            }
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
        match self.scope {
            // The saved firmware mask becomes the primary need again, and
            // live secondary owners' bits stay in the written union.
            Scope::Primary => {
                let mask = runtime.events_compose(Need::Primary, self.events);
                set_var(runtime, &guard, "event_msgs", &mask).await?;
                runtime.events_written(mask);
            }
            // brcmf_cfg80211_stop_ap: `mbss 0` with BRCMF_FEAT_MBSS,
            // but only when this is the last MBSS AP: clearing the
            // device-wide mode while another MBSS AP runs would
            // strand its BSS. The shared event mask stays (Linux
            // keeps every handled event).
            Scope::Secondary { mbss, .. } => {
                if mbss && clear_mbss {
                    set_var(runtime, &guard, "mbss", &0u32.to_le_bytes()).await?;
                }
            }
            Scope::Go { .. } => {}
        }
        if !go {
            set(runtime, &guard, ap_wire::UP, 1).await?;
        }
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
    scope: Scope,
) -> Result<(), Error> {
    let guard = Guard::Program(original);
    // Linux never reads `SET_AP` state of a GO bsscfg (it never sets it);
    // the GO BSS is observed through `GET_BSS_INFO` below.
    if scope.go().is_none() && get(runtime, &guard, ap_wire::GET_AP).await? != 1
        || get(runtime, &guard, ap_wire::GET_BEACON).await? != plan.config.beacon_interval
        || get(runtime, &guard, ap_wire::GET_DTIM).await? != plan.config.dtim_period
        || get_int(runtime, &guard, "chanspec").await? != u32::from(plan.chanspec)
        || scope.primary() && get_int(runtime, &guard, "nmode").await? != 0
        || scope.primary() && get_int(runtime, &guard, "vhtmode").await? != 0
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
    let scope = saved.scope;
    scope.admits::<R>()?;
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
    let (down_apsta, mbss) = match scope {
        Scope::Primary => (true, false),
        Scope::Secondary { down_apsta, mbss } => (down_apsta, mbss),
        Scope::Go { .. } => (false, false),
    };
    let go = scope.go();
    if down_apsta {
        set(runtime, &guard, ap_wire::DOWN, 1).await?;
        set_int(runtime, &guard, "apsta", 0).await?;
    }
    if scope.primary() {
        set_int(runtime, &guard, "nmode", 0).await?;
        set_int(runtime, &guard, "vhtmode", 0).await?;
    }
    set(runtime, &guard, ap_wire::INFRA, 1).await?;
    if mbss {
        set_int(runtime, &guard, "mbss", 1).await?;
    }
    if go.is_none() {
        set(runtime, &guard, ap_wire::SET_AP, 1).await?;
    }
    set_int(runtime, &guard, "chanspec", u32::from(plan.chanspec)).await?;
    if scope.primary() {
        set_int(runtime, &guard, "qtxpower", u32::from(power_dbm) * 4).await?;
    }
    set_int(runtime, &guard, "ap_isolate", 1).await?;
    set_int(runtime, &guard, "wme_bss_disable", 1).await?;
    if go.is_none() {
        set(runtime, &guard, ap_wire::UP, 1).await?;
    }
    set_int(runtime, &guard, "sup_wpa", 0).await?;
    set_int(runtime, &guard, "auth", 0).await?;
    // Linux's AP WPA/RSN configuration includes SES_OW_ENABLED (0x40).
    let wsec = if plan.rsne.is_some() { 4 | 0x40 } else { 0 };
    set_int(runtime, &guard, "wsec", wsec).await?;
    if mfp_supported {
        set_int(runtime, &guard, "mfp", 0).await?;
    }
    set_int(runtime, &guard, "wpa_auth", plan.wpa_auth).await?;
    // `closednet` is AP-branch only in Linux; a hidden GO is refused at
    // prepare (`ap::Session::prepare_in`).
    if go.is_none() {
        set_int(
            runtime,
            &guard,
            "closednet",
            u32::from(plan.config.hidden_ssid == 1),
        )
        .await?;
    }
    // Actual AP SME association/removal plus radio/firmware loss. No P2P
    // or extra-bsscfg namespace is created by enabling these observations.
    // This AP's events replace only its own owner's need (the primary
    // role, or the secondary bsscfg's through its view); the firmware
    // receives the union of every live owner (`event_mask`), so a live
    // secondary STA/AP or the interface registry keeps its bits.
    let mask = runtime.events_compose(Need::Primary, event_mask::mask(&AP_EVENTS));
    set_var(runtime, &guard, "event_msgs", &mask).await?;
    runtime.events_written(mask);
    *phase = Phase::BssRequested;
    match go {
        None => {
            command(
                runtime,
                &guard,
                Direction::Set,
                ap_wire::SET_SSID,
                &ap_wire::ssid(&plan.config.ssid)?,
                52,
            )
            .await?;
        }
        // P2P_GO branch: bsscfg `ssid` (`brcmf_ssid_le`) then `bss` enable.
        Some(bsscfgidx) => {
            let ssid = ap_wire::ssid(&plan.config.ssid)?;
            set_var(runtime, &guard, "ssid", &ssid[..ap_wire::SSID_LE]).await?;
            set_var(
                runtime,
                &guard,
                "bss",
                &ap_wire::bss_enable(bsscfgidx, true),
            )
            .await?;
        }
    }
    // Linux programs native vndr_ie after creating the primary BSS. The
    // successful public result still requires all template transactions.
    vendor(runtime, &guard, &[], &plan.beacon_vendor, 1).await?;
    vendor(runtime, &guard, &[], &plan.probe_vendor, 2).await?;
    verify(runtime, original, plan, scope).await?;
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
