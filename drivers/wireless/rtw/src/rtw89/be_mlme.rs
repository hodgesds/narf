// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Source RTL8922A port0/no-link initialization over the original CH12 owner.
//! Full packet authority and live source receipt checks belong to the native
//! N22O adapter. Source REC is never represented as command execution.
use super::{
    ap_wire::UpdMode,
    cctl_g7,
    fwcmd_8922a::H2cCmd,
    link_h2c_8922a as link,
    power::{self, Io},
    rfk::be_features::Features,
};
use alloc::vec::Vec;
pub(super) trait Interface: Io {
    fn current(&mut self) -> Result<(), power::Error>;
    async fn command(&mut self, command: link::LinkCmd, body: &[u8]) -> Result<(), power::Error>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Busy,
    Passive,
}
#[derive(Default)]
pub(super) struct Controller {
    state: State,
    own: Option<[u8; 6]>,
    version: Option<[u8; 4]>,
}
fn r32(io: &mut impl Interface, a: u32) -> Result<u32, power::Error> {
    io.current()?;
    let value = io.read32(a)?;
    if value == u32::MAX {
        Err(power::Error::Gone)
    } else {
        Ok(value)
    }
}
fn f32(io: &mut impl Interface, a: u32, mask: u32, value: u32) -> Result<(), power::Error> {
    let old = r32(io, a)?;
    io.write32(a, (old & !mask) | (value & mask))?;
    if r32(io, a)? & mask != value & mask {
        return Err(power::Error::Access);
    }
    io.current()
}
fn f16(io: &mut impl Interface, a: u32, mask: u16, value: u16) -> Result<(), power::Error> {
    io.current()?;
    let old = io.read16(a)?;
    if old == u16::MAX {
        return Err(power::Error::Gone);
    }
    io.write16(a, (old & !mask) | (value & mask))?;
    if io.read16(a)? & mask != value & mask {
        return Err(power::Error::Access);
    }
    io.current()
}
fn f8(io: &mut impl Interface, a: u32, mask: u8, value: u8) -> Result<(), power::Error> {
    io.current()?;
    let old = io.read8(a)?;
    if old == u8::MAX {
        return Err(power::Error::Gone);
    }
    io.write8(a, (old & !mask) | (value & mask))?;
    if io.read8(a)? & mask != value & mask {
        return Err(power::Error::Access);
    }
    io.current()
}
fn cmac_bytes(cmac: cctl_g7::DefaultCmac) -> [u8; 132] {
    let mut bytes = [0u8; 132];
    for (i, word) in core::iter::once(cmac.c0)
        .chain(cmac.w)
        .chain(cmac.m)
        .enumerate()
    {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
const CMAC: link::LinkCmd = link::LinkCmd {
    cmd: H2cCmd {
        cat: 1,
        class: 5,
        func: 0x11,
    },
    rec_ack: false,
    done_ack: true,
};
pub(super) const BA_USERS: link::LinkCmd = link::LinkCmd {
    cmd: H2cCmd {
        cat: 1,
        class: 0xc,
        func: 2,
    },
    rec_ack: false,
    done_ack: true,
};
fn cam(own: [u8; 6], features: Features) -> Result<Vec<u8>, power::Error> {
    let args = link::CamArgs {
        macid: 0,
        port: 0,
        phy_idx: 0,
        addr_cam_idx: 0,
        bssid_cam_idx: 0,
        net_type: 0,
        valid: true,
        bssid_valid: true,
        sma: own,
        tma: [0; 6],
        bssid: [0; 6],
        aid: 0,
        trigger: false,
    };
    if features.addr_cam_v0() {
        link::cam_v0(&args).map(|b| b.to_vec())
    } else {
        link::cam_v1(&args, UpdMode::Create).map(|b| b.to_vec())
    }
    .map_err(|_| power::Error::Unsupported)
}
async fn port0(io: &mut impl Interface) -> Result<(), power::Error> {
    // Fresh no-link profile has no old BSS/timing ownership. Refuse an
    // unexpectedly active source port instead of adopting/replaying a TSF
    // switch from an unrelated interface. Association updates need retained
    // actual prior beacon timing and are a separate transition.
    if r32(io, 0x10400)? & (1 << 2) != 0 {
        return Err(power::Error::Unsupported);
    }
    for (mask, value) in [
        (1 << 1, 0),
        (1, 0),
        (3 << 10, 0),
        ((1 << 13) | (1 << 16), 0),
        (1 << 4, 0),
        (1 << 3, 0),
        (1 << 12, 0),
    ] {
        f32(io, 0x10400, mask, value)?;
    }
    f32(io, 0x10414, 0xffff, 100)?; // source default when no-link bcn_int0
    f8(io, 0x10590, 0xff, 0)?;
    f8(io, 0x10e08, 3, 3)?;
    f16(io, 0x10426, 0xff00, 0)?; // actual new no-link DTIM software state0
    f32(io, 0x1083c, (1 << 16) | 1, 0)?;
    f32(io, 0x10404, 0xff, 2)?;
    f32(io, 0x10404, 0x0fff0000, 200 << 16)?;
    f32(io, 0x10408, 0x0fff0000, 0)?;
    f16(io, 0x1040e, 0xfff, 5)?;
    f16(io, 0x10412, 0xff00, 1 << 8)?;
    f32(io, 0x108a0, 0x3f, 0)?;
    f32(io, 0x10568, 0x00fffffe, 0)?;
    f32(io, 0x10400, 1 << 2, 1 << 2)?;
    // Sole station has no AP TSF-resync effects. The source real delay
    // precedes the overlapping-width beacon-early update.
    io.delay_us(20).await;
    io.current()?;
    f32(io, 0x1040c, 0xfff, 160)?;
    f32(io, 0x11484, 0x7ff, 0)
}
impl Controller {
    pub(super) fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Original complete N22W source radio + distinct current N22O joint
    /// packet/response scope, original inactive checked rings/CH12 and sole
    /// new station port. No packet enables/publication or competing reset.
    /// Retain this owner Busy on error/drop; no replacement/retry.
    pub(super) async unsafe fn initialize(
        &mut self,
        io: &mut impl Interface,
        own: [u8; 6],
        features: Features,
    ) -> Result<(), power::Error> {
        if self.state != State::New {
            return Err(power::Error::Terminal);
        }
        self.state = State::Busy;
        if !super::efuse::mac_is_valid(own) || !features.packet_mlme() {
            return Err(power::Error::Unsupported);
        }
        let cam = cam(own, features)?;
        let pause = link::macid_pause_sleep(0, false).map_err(|_| power::Error::Unsupported)?;
        let role = link::role_maintain(
            0,
            link::SELF_ROLE_CLIENT,
            UpdMode::Create,
            link::WIFI_ROLE_STATION,
            0,
            0,
        )
        .map_err(|_| power::Error::Unsupported)?;
        let join = link::join_info_v1(&link::JoinV1 {
            macid: 0,
            dis_conn: true,
            mac_idx: 0,
            wmm: 0,
            trigger: false,
            port: 0,
            net_type: 0,
            wifi_role: link::WIFI_ROLE_STATION,
            self_role: link::SELF_ROLE_CLIENT,
            sta_type: link::StaType::Nac,
            is_mld: false,
            main_macid: 0,
            init_ps: false,
            link_id: 0,
        })
        .map_err(|_| power::Error::Unsupported)?;
        let cmac =
            cmac_bytes(cctl_g7::build_default(0, true).map_err(|_| power::Error::Unsupported)?);
        let dmac = link::default_dmac_tbl_v2(0).map_err(|_| power::Error::Unsupported)?;
        io.current()?;
        // BE-specific host-crypto profile: keep clock bits8..10, disable
        // all RX/TX/management decrypt and pre-enqueue encryption effects.
        f32(io, 0x9d00, 0x83f, 0)?;
        f32(io, 0x9d04, 3, 0)?;
        // Source V1 DMAC BA-user table initialization for both band tags.
        // These exact firmware receipts prove neither MAC1 host access nor
        // off-domain power/packet readiness; rejected/missing ACK is terminal.
        io.command(BA_USERS, &1u32.to_le_bytes()).await?;
        io.command(BA_USERS, &0x01004001u32.to_le_bytes()).await?;
        // core-start final report shape. PPDU is reasserted after the same
        // source fields already used by the path/reset bracket.
        f32(io, 0x9c30, 0xff, 3)?;
        f32(io, 0x11440, u32::MAX, 0x6d)?;
        f32(io, 0x11400, 0x30, 0x10)?;
        f32(io, 0x11400, 0xc0, 0)?;
        f32(io, 0x11470, 1, 1)?;
        f16(io, 0x10814, 0xff00, 0x200)?;
        f16(io, 0x10814, 0xff, 0xff)?;
        port0(io).await?;
        // Direct DMAC/CMAC indirect-table init is source AX-only and has no
        // BE effects. Preserve each actual source acknowledgement contract.
        io.command(link::CMD_MACID_PAUSE_SLEEP, &pause).await?;
        io.command(link::CMD_ROLE_MAINTAIN, &role).await?;
        io.command(link::CMD_JOIN_INFO, &join).await?;
        io.command(link::CMD_CAM, &cam).await?;
        io.command(CMAC, &cmac).await?;
        io.command(link::CMD_DMAC_V2, &dmac).await?;
        io.current()?;
        self.own = Some(own);
        self.version = Some(features.version());
        self.state = State::Passive;
        Ok(())
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_mlme_tests.rs"]
mod tests;
