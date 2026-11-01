// SPDX-License-Identifier: GPL-2.0-or-later
//! Single-link MLD EAPOL key-data checks. Primary sources: hostap wpa.c
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
#[derive(Default)]
struct Kdes<'a> {
    mac: Option<&'a [u8]>,
    link: Option<&'a [u8]>,
    gtk: Option<&'a [u8]>,
    igtk: Option<&'a [u8]>,
    rsne: Option<&'a [u8]>,
    rsnxe: Option<&'a [u8]>,
}
fn set<'a>(slot: &mut Option<&'a [u8]>, value: &'a [u8]) -> Result<(), Error> {
    if slot.replace(value).is_some() {
        return Err(Error::Duplicate);
    }
    Ok(())
}
fn parse(bytes: &[u8], context: Context) -> Result<Kdes<'_>, Error> {
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
                    16 => {
                        if data.len() < 7 || data[0] >> 4 != context.link_id() {
                            return Err(Error::Link);
                        }
                        if data[0] & 8 != 0 {
                            return Err(Error::Flags);
                        }
                        set(&mut result.gtk, data)?;
                    }
                    17 => {
                        if data.len() < 9 || data[8] >> 4 != context.link_id() {
                            return Err(Error::Link);
                        }
                        if data[8] & 15 != 0 {
                            return Err(Error::Flags);
                        }
                        set(&mut result.igtk, data)?;
                    }
                    19 => {
                        if data.len() < 7 || data[0] & 15 != context.link_id() {
                            return Err(Error::Link);
                        }
                        if data[0] & 0xc0 != 0 {
                            return Err(Error::Flags);
                        }
                        set(&mut result.link, data)?;
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
    let parsed = parse(bytes, context)?;
    if parsed.mac != Some(context.peer_mld().as_slice()) {
        return Err(Error::Address);
    }
    if parsed.link.is_some() || parsed.gtk.is_some() || parsed.igtk.is_some() {
        return Err(Error::Profile);
    }
    Ok(())
}
/// M2 repeats the station RSNE/RSNXE and adds its MLD MAC KDE. Hostap skips
/// Link KDEs for the association link; this profile requests no other link.
pub fn message2(context: Context, association_ies: &[u8]) -> Result<Vec<u8>, Error> {
    if association_ies.len() > 4084 {
        return Err(Error::Length);
    }
    let parsed = parse(association_ies, context)?;
    if parsed.mac.is_some()
        || parsed.link.is_some()
        || parsed.gtk.is_some()
        || parsed.igtk.is_some()
    {
        return Err(Error::Profile);
    }
    let mut bytes = association_ies.to_vec();
    bytes.extend_from_slice(&[221, 10, 0, 0x0f, 0xac, 3]);
    bytes.extend_from_slice(&context.own_mld());
    Ok(bytes)
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
    if profile.gtk_len != 16 || profile.igtk_len != Some(16) {
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
    let parsed = parse(bytes, context)?;
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
    match parsed.link {
        Some(link) => link_profile(link, context, profile)?,
        None if kind == Kind::Pairwise3 => return Err(Error::Link),
        None => {}
    }
    let gtk = parsed.gtk.ok_or(Error::Key)?;
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
    let igtk = parsed
        .igtk
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
