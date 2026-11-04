// SPDX-License-Identifier: GPL-2.0-or-later
//! MLD EAPOL key-data checks. Primary sources: hostap wpa.c
//! blob5a05a991b9f95ae0411bdc136bc3ef6ddd0ecb6a and Android wpa_common.h
//! commit073b9ad1b7e6876417fe0927c6364245ecf26d8b (BSD-compatible wire defs).
//! Helpers consume already MIC-authenticated/decrypted M3/group data. They
//! grant no MIC, native key-install, RF or terminal-delivery authority.
use super::{Gtk, Igtk, KI_ENCRYPTED_KEY_DATA, KI_INSTALL, KI_SECURE};
use crate::association::mlo::Context;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Duplicate,
    Address,
    Link,
    Flags,
    Profile,
    Key,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Pairwise3,
    Group1,
}
#[derive(Clone, Copy, Debug)]
pub struct Profile<'a> {
    /// Complete AP elements, including element id and length.
    pub rsne: &'a [u8],
    pub rsnxe: Option<&'a [u8]>,
    pub gtk_len: usize,
    pub igtk_len: Option<usize>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keys {
    pub link_id: u8,
    pub gtk: Gtk,
    pub igtk: Option<Igtk>,
}
const LINKS: usize = 15;
#[derive(Default)]
struct Kdes<'a> {
    mac: Option<&'a [u8]>,
    link: [Option<&'a [u8]>; LINKS],
    gtk: [Option<&'a [u8]>; LINKS],
    igtk: [Option<&'a [u8]>; LINKS],
    rsne: Option<&'a [u8]>,
    rsnxe: Option<&'a [u8]>,
}
impl Kdes<'_> {
    fn any_link_kde(&self) -> bool {
        [&self.link, &self.gtk, &self.igtk]
            .iter()
            .any(|slots| slots.iter().any(Option::is_some))
    }
}
fn set<'a>(slot: &mut Option<&'a [u8]>, value: &'a [u8]) -> Result<(), Error> {
    if slot.replace(value).is_some() {
        return Err(Error::Duplicate);
    }
    Ok(())
}
/// Per-link KDEs (MLO GTK/IGTK/Link) for a link outside `links` are
/// ignored, as hostap wpa_common.c `wpa_parse_generic` records every link
/// and wpa.c consumes only requested/valid ones: hostapd's
/// `wpa_auth_ml_kdes` sends an MLO Link KDE for every affiliated AP of the
/// AP MLD, not only the links this station requested. A link id of 15 is
/// not a link (`MAX_NUM_MLD_LINKS`).
fn link_slot<'b, 'a>(
    slots: &'b mut [Option<&'a [u8]>; LINKS],
    link: u8,
    links: u16,
) -> Result<Option<&'b mut Option<&'a [u8]>>, Error> {
    if usize::from(link) >= LINKS {
        return Err(Error::Link);
    }
    Ok((links & (1 << link) != 0).then(|| &mut slots[usize::from(link)]))
}
fn set_link<'a>(
    slots: &mut [Option<&'a [u8]>; LINKS],
    link: u8,
    links: u16,
    value: &'a [u8],
) -> Result<(), Error> {
    match link_slot(slots, link, links)? {
        Some(slot) => set(slot, value),
        None => Ok(()),
    }
}
fn parse(bytes: &[u8], links: u16) -> Result<Kdes<'_>, Error> {
    if bytes.len() > 4096 {
        return Err(Error::Length);
    }
    let mut result = Kdes::default();
    let mut at = 0;
    while at < bytes.len() {
        // RFC3394 EAPOL padding: DD then zero padding, with no hidden KDE.
        if bytes[at] == 0xdd && bytes[at + 1..].iter().all(|b| *b == 0) {
            break;
        }
        let header = bytes.get(at..at + 2).ok_or(Error::Length)?;
        let end = at + 2 + usize::from(header[1]);
        let element = bytes.get(at..end).ok_or(Error::Length)?;
        match header[0] {
            48 => set(&mut result.rsne, element)?,
            244 => set(&mut result.rsnxe, element)?,
            221 if header[1] >= 4 && element[2..5] == [0, 0x0f, 0xac] => {
                let data = &element[6..];
                match element[5] {
                    3 => {
                        if data.len() != 6 {
                            return Err(Error::Length);
                        }
                        set(&mut result.mac, data)?;
                    }
                    // wpa_common.h RSN_MLO_*: reserved bits are ignored on
                    // receipt, as wpa_parse_generic ignores them.
                    16 => {
                        if data.len() < 7 {
                            return Err(Error::Link);
                        }
                        set_link(&mut result.gtk, data[0] >> 4, links, data)?;
                    }
                    17 => {
                        if data.len() < 9 {
                            return Err(Error::Link);
                        }
                        set_link(&mut result.igtk, data[8] >> 4, links, data)?;
                    }
                    19 => {
                        if data.len() < 7 {
                            return Err(Error::Link);
                        }
                        set_link(&mut result.link, data[0] & 15, links, data)?;
                    }
                    // No mixed legacy group keys, Extended Key ID, or
                    // unnegotiated beacon-protection/BIGTK in this profile.
                    1 | 9 | 10 | 14 | 18 => return Err(Error::Profile),
                    4 if data.len() != 16 => return Err(Error::Length),
                    _ => {}
                }
            }
            _ => {}
        }
        at = end;
    }
    Ok(result)
}
fn link_profile(link: &[u8], context: Context, profile: Profile<'_>) -> Result<(), Error> {
    if link[1..7] != context.peer_link() {
        return Err(Error::Address);
    }
    if link[0] & 0x10 == 0 {
        return Err(Error::Profile);
    }
    let mut at = 7;
    let rsne_header = link.get(at..at + 2).ok_or(Error::Length)?;
    let end = at + 2 + usize::from(rsne_header[1]);
    let rsne = link.get(at..end).ok_or(Error::Length)?;
    if rsne_header[0] != 48 || rsne != profile.rsne {
        return Err(Error::Profile);
    }
    at = end;
    let rsnxe = if link[0] & 0x20 != 0 {
        let header = link.get(at..at + 2).ok_or(Error::Length)?;
        let end = at + 2 + usize::from(header[1]);
        let value = link.get(at..end).ok_or(Error::Length)?;
        if header[0] != 244 {
            return Err(Error::Profile);
        }
        at = end;
        Some(value)
    } else {
        None
    };
    if rsnxe != profile.rsnxe || at != link.len() {
        return Err(Error::Profile);
    }
    Ok(())
}
/// M1's AP MLD MAC is checked before nonce consumption or PTK derivation.
/// M1 itself is not MIC authenticated; this binds it to the selected peer.
pub fn message1(context: Context, bytes: &[u8]) -> Result<(), Error> {
    let parsed = parse(bytes, 1 << context.link_id())?;
    if parsed.mac != Some(context.peer_mld().as_slice()) {
        return Err(Error::Address);
    }
    if parsed.any_link_kde() {
        return Err(Error::Profile);
    }
    Ok(())
}
/// M2 repeats the station RSNE/RSNXE and adds its MLD MAC KDE. Hostap skips
/// Link KDEs for the association link; this profile requests no other link.
pub fn message2(context: Context, association_ies: &[u8]) -> Result<Vec<u8>, Error> {
    message2_links(context, &[], association_ies)
}
/// M2 for a multiple-link association: after the MLD MAC KDE, one MLO Link
/// KDE (Link Information = link id with RSNE/RSNXE bits clear, then this
/// station's link MAC) per further link that was *requested*, accepted or
/// rejected, in ascending link id order and never for the association link
/// (hostap wpa.c `wpa_mlo_link_kde` over `sm->mlo.req_links`; hostapd
/// `wpa_auth_validate_ml_kdes_m2` counts the rejected links too).
pub fn message2_links(
    context: Context,
    requested: &[Context],
    association_ies: &[u8],
) -> Result<Vec<u8>, Error> {
    if association_ies.len() > 4084 - 13 * requested.len() {
        return Err(Error::Length);
    }
    let links = further_mask(context, requested.iter())?;
    let parsed = parse(association_ies, links | 1 << context.link_id())?;
    if parsed.mac.is_some() || parsed.any_link_kde() {
        return Err(Error::Profile);
    }
    let mut bytes = association_ies.to_vec();
    bytes.extend_from_slice(&[221, 10, 0, 0x0f, 0xac, 3]);
    bytes.extend_from_slice(&context.own_mld());
    for link_id in 0..LINKS as u8 {
        let Some(link) = requested.iter().find(|link| link.link_id() == link_id) else {
            continue;
        };
        bytes.extend_from_slice(&[221, 11, 0, 0x0f, 0xac, 19, link_id & 15]);
        bytes.extend_from_slice(&link.own_link());
    }
    Ok(bytes)
}
/// Further links must be distinct affiliated links of the same MLD pair.
fn further_mask<'a>(
    context: Context,
    further: impl Iterator<Item = &'a Context>,
) -> Result<u16, Error> {
    let mut links = 0u16;
    for link in further {
        let bit = 1u16 << link.link_id();
        if link.own_mld() != context.own_mld()
            || link.peer_mld() != context.peer_mld()
            || link.link_id() == context.link_id()
            || links & bit != 0
        {
            return Err(Error::Profile);
        }
        links |= bit;
    }
    Ok(links)
}
/// Validate key delivery after actual descriptor/MIC/AES-unwrapping checks.
/// Native adapters must install only into this exact selected link context.
pub fn authenticated_keys(
    context: Context,
    kind: Kind,
    key_info: u16,
    bytes: &[u8],
    profile: Profile<'_>,
) -> Result<Keys, Error> {
    let mut keys = authenticated_link_keys(context, &[], &[], kind, key_info, bytes, profile)?;
    keys.pop().ok_or(Error::Key)
}
/// Multiple-link key delivery (hostap wpa.c `wpa_supplicant_process_3_of_4`
/// and the MLO group-key handler): every link of the association, the
/// association link first and then each `further` accepted link with that
/// link's own AP RSNE/RSNXE, needs its MLO GTK KDE. M3 also needs an MLO
/// Link KDE for every *requested* link, including each `rejected` one,
/// naming that link's AP address with RSNE (and RSNXE when advertised)
/// identical to its beacon (`wpa_supplicant_validate_link_kde` over
/// `sm->mlo.req_links`); a rejected link's GTK is not consumed. KDEs for a
/// link that was never requested are ignored. The result is in the same
/// order: association link, then `further`.
pub fn authenticated_link_keys(
    context: Context,
    further: &[(Context, Profile<'_>)],
    rejected: &[(Context, Profile<'_>)],
    kind: Kind,
    key_info: u16,
    bytes: &[u8],
    profile: Profile<'_>,
) -> Result<Vec<Keys>, Error> {
    if core::iter::once(&profile)
        .chain(further.iter().map(|(_, profile)| profile))
        .any(|profile| profile.gtk_len != 16 || profile.igtk_len != Some(16))
    {
        return Err(Error::Profile);
    }
    let required = KI_ENCRYPTED_KEY_DATA
        | if kind == Kind::Pairwise3 {
            KI_INSTALL | KI_SECURE
        } else {
            0
        };
    if key_info & required != required {
        return Err(Error::Flags);
    }
    let links = further_mask(
        context,
        further.iter().chain(rejected).map(|(link, _)| link),
    )?;
    let parsed = parse(bytes, links | 1 << context.link_id())?;
    if kind == Kind::Pairwise3 && parsed.mac != Some(context.peer_mld().as_slice())
        || parsed
            .mac
            .is_some_and(|mac| mac != context.peer_mld().as_slice())
    {
        return Err(Error::Address);
    }
    if let Some(rsne) = parsed.rsne {
        if rsne != profile.rsne {
            return Err(Error::Profile);
        }
    }
    if let Some(rsnxe) = parsed.rsnxe {
        if Some(rsnxe) != profile.rsnxe {
            return Err(Error::Profile);
        }
    }
    for (link, profile) in rejected {
        match parsed.link[usize::from(link.link_id())] {
            Some(kde) => link_profile(kde, *link, *profile)?,
            None if kind == Kind::Pairwise3 => return Err(Error::Link),
            None => {}
        }
    }
    let mut keys = Vec::with_capacity(1 + further.len());
    for (link, profile) in core::iter::once((&context, &profile))
        .chain(further.iter().map(|(link, profile)| (link, profile)))
    {
        keys.push(link_keys(&parsed, *link, kind, *profile)?);
    }
    Ok(keys)
}
fn link_keys(
    parsed: &Kdes<'_>,
    context: Context,
    kind: Kind,
    profile: Profile<'_>,
) -> Result<Keys, Error> {
    let index = usize::from(context.link_id());
    match parsed.link[index] {
        Some(link) => link_profile(link, context, profile)?,
        None if kind == Kind::Pairwise3 => return Err(Error::Link),
        None => {}
    }
    let gtk = parsed.gtk[index].ok_or(Error::Key)?;
    if gtk.len() != 7 + profile.gtk_len {
        return Err(Error::Length);
    }
    let mut rsc = [0; 8];
    rsc[..6].copy_from_slice(&gtk[1..7]);
    let gtk = Gtk {
        key_id: gtk[0] & 3,
        tx: false,
        key: gtk[7..].to_vec(),
        rsc,
    };
    let igtk = parsed.igtk[index]
        .map(|data| {
            if data.len() != 9 + 16 {
                return Err(Error::Length);
            }
            let key_id = u16::from_le_bytes([data[0], data[1]]);
            if !(4..=5).contains(&key_id) {
                return Err(Error::Key);
            }
            Ok(Igtk {
                key_id,
                ipn: data[2..8].try_into().map_err(|_| Error::Length)?,
                key: data[9..].to_vec(),
            })
        })
        .transpose()?;
    Ok(Keys {
        link_id: context.link_id(),
        gtk,
        igtk,
    })
}
impl Keys {
    /// Feed the existing install/reinstallation/terminal state machine only
    /// after the MLO wire identities above were checked. No frame MIC changes.
    pub(super) fn legacy_data(&self, profile: Profile<'_>) -> Vec<u8> {
        let mut bytes = profile.rsne.to_vec();
        if let Some(rsnxe) = profile.rsnxe {
            bytes.extend_from_slice(rsnxe);
        }
        bytes.extend_from_slice(&[
            221,
            (6 + self.gtk.key.len()) as u8,
            0,
            0x0f,
            0xac,
            1,
            self.gtk.key_id,
            0,
        ]);
        bytes.extend_from_slice(&self.gtk.key);
        if let Some(igtk) = &self.igtk {
            bytes.extend_from_slice(&[221, (12 + igtk.key.len()) as u8, 0, 0x0f, 0xac, 9]);
            bytes.extend_from_slice(&igtk.key_id.to_le_bytes());
            bytes.extend_from_slice(&igtk.ipn);
            bytes.extend_from_slice(&igtk.key);
        }
        bytes
    }
}
