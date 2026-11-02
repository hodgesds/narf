//! P2P grant wire contracts from Linux7.3-rc7 fw/api/time-event.h.
//! ABI selection is metadata only. The native owner must separately retain
//! the actual admitted device/source, MAC/link/STA allocation, current PHY,
//! NVM/MCC/host power and request authority. SESSION codecs remain test-only
//! until their actual API77/API89 native adapters are implemented.
use super::{firmware_api::FirmwareApi, native_band::Channel};

pub(super) const GROUP: u8 = 3;
pub(super) const ROC: u8 = 0x0e;
pub(super) const ROC_NOTIFICATION: u8 = 0xf8;
pub(super) const SESSION: u8 = 5;
pub(super) const SESSION_NOTIFICATION: u8 = 0xfb;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Abi {
    Roc6,
    Session1,
    Session2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Activity {
    Discover,
    Negotiate,
}
impl Activity {
    fn roc(self) -> u32 {
        match self {
            Self::Discover => 1,
            Self::Negotiate => 3,
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    fn session(self) -> u32 {
        match self {
            Self::Discover => 2,
            Self::Negotiate => 3,
        }
    }
}
/// The actual allocated MAC ID for sessionv1 or active FW-link ID for v2.
/// Neither an observed interface number nor the AP's spec link ID belongs here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "kernel-test"))]
pub(super) enum Target {
    Mac(u8),
    Link(u8),
}
/// Raw matching firmware outcome, not a host READY/EXPIRED receipt.
/// A failed START still needs the adapter's native removal/retirement path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Notification {
    pub started: bool,
    pub success: bool,
}
/// Linux MSEC_TO_TU rounds down. A zero/native-overflow interval is refused;
/// the physical owner also imposes its advertised finite request limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Duration(u32);
impl Duration {
    pub fn from_ms(ms: u32) -> Result<Self, &'static str> {
        let tu = ms.checked_mul(1000).ok_or("P2P duration overflow")? / 1024;
        if tu == 0 {
            return Err("P2P native duration is zero");
        }
        Ok(Self(tu))
    }
    pub fn microseconds(self) -> u64 {
        u64::from(self.0) * 1024
    }
}
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn boolean(value: u32) -> Result<bool, &'static str> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("P2P native notification boolean invalid"),
    }
}
impl Abi {
    pub fn read(api: &FirmwareApi<'_>) -> Result<Self, &'static str> {
        let notification = |id| api.versions(GROUP, id).map(|v| v.1);
        match api.command_version(GROUP, 8) {
            Some(3)
                if api.command_version(GROUP, ROC) == Some(6)
                    && notification(ROC_NOTIFICATION) == Some(1) =>
            {
                Ok(Self::Roc6)
            }
            Some(1)
                if api.has_capability(54)
                    && api.command_version(GROUP, SESSION) == Some(1)
                    && notification(SESSION_NOTIFICATION) == Some(2) =>
            {
                Ok(Self::Session1)
            }
            Some(2)
                if api.has_capability(54)
                    && api.command_version(GROUP, SESSION) == Some(2)
                    && notification(SESSION_NOTIFICATION) == Some(3)
                    && api.command_version(GROUP, ROC) == Some(3)
                    && notification(ROC_NOTIFICATION) == Some(1) =>
            {
                // API89 ROCv3 describes its hotspot path. Linux uses P2P
                // over AUX only for ROCv4+, so P2P retains sessionv2 here.
                Ok(Self::Session2)
            }
            _ => Err("P2P actual firmware grant ABI unsupported"),
        }
    }
    /// ROCv6 has no MAC/link selector. The actual AUX-STA allocation and
    /// single current activity owner must precede this request's publication.
    pub fn roc_add(
        self,
        activity: Activity,
        aux_station: u8,
        channel: Channel,
        node: [u8; 6],
        duration: Duration,
    ) -> Result<[u8; 44], &'static str> {
        if self != Self::Roc6
            || aux_station >= 16
            || channel.index().is_none()
            || node == [0; 6]
            || node[0] & 1 != 0
        {
            return Err("P2P ROC native owner/geometry invalid");
        }
        let mut bytes = [0; 44];
        put(&mut bytes, 0, 1); // FW_CTXT_ACTION_ADD
        put(&mut bytes, 4, activity.roc());
        put(&mut bytes, 8, u32::from(aux_station));
        put(&mut bytes, 12, u32::from(channel.number));
        bytes[16] = channel.band as u8;
        // Width20, primary control0, reserved and single repetition are0.
        bytes[20..26].copy_from_slice(&node);
        put(&mut bytes, 28, 200 * 1000 / 1024);
        put(&mut bytes, 32, duration.0);
        Ok(bytes)
    }
    pub fn roc_remove(self, activity: Activity) -> Result<[u8; 44], &'static str> {
        if self != Self::Roc6 {
            return Err("P2P ROC REMOVE requires actual ROCv6");
        }
        let mut bytes = [0; 44];
        put(&mut bytes, 0, 3); // FW_CTXT_ACTION_REMOVE
        put(&mut bytes, 4, activity.roc());
        Ok(bytes)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    fn target(self, target: Target) -> Result<u32, &'static str> {
        match (self, target) {
            (Self::Session1, Target::Mac(id)) | (Self::Session2, Target::Link(id)) => {
                Ok(u32::from(id))
            }
            _ => Err("P2P session MAC/FW-link identity mismatched"),
        }
    }
    /// The session command has no channel field: the actual current
    /// P2P-device MAC/active-link/PHY receipts supply that separate proof.
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn session_add(
        self,
        target: Target,
        activity: Activity,
        duration: Duration,
    ) -> Result<[u8; 24], &'static str> {
        let mut bytes = [0; 24];
        put(&mut bytes, 0, self.target(target)?);
        put(&mut bytes, 4, 1);
        put(&mut bytes, 8, activity.session());
        put(&mut bytes, 12, duration.0);
        Ok(bytes)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn session_remove(
        self,
        target: Target,
        activity: Activity,
    ) -> Result<[u8; 24], &'static str> {
        let mut bytes = [0; 24];
        put(&mut bytes, 0, self.target(target)?);
        put(&mut bytes, 4, 3);
        put(&mut bytes, 8, activity.session());
        Ok(bytes)
    }
    /// Call only for a notification copied under the same actual activity
    /// epoch. A reused activity number alone cannot identify an old ROC.
    pub fn roc_notification(
        self,
        activity: Activity,
        bytes: &[u8],
    ) -> Result<Notification, &'static str> {
        if self != Self::Roc6 || bytes.len() != 12 || word(bytes, 8) != activity.roc() {
            return Err("P2P ROC notification owner/extent invalid");
        }
        Ok(Notification {
            success: boolean(word(bytes, 0))?,
            started: boolean(word(bytes, 4))?,
        })
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn session_notification(
        self,
        target: Target,
        activity: Activity,
        bytes: &[u8],
    ) -> Result<Notification, &'static str> {
        let target = self.target(target)?;
        if bytes.len() != 16 || word(bytes, 0) != target || word(bytes, 12) != activity.session() {
            return Err("P2P session notification owner/extent invalid");
        }
        Ok(Notification {
            success: boolean(word(bytes, 4))?,
            started: boolean(word(bytes, 8))?,
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "p2p_wire_tests.rs"]
mod tests;
