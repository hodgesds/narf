// SPDX-License-Identifier: GPL-2.0-or-later
//! SU and MU beamformee programs against a byte-addressed register model.
//! Expected values are authored from Linux `bf.c` / `rtw8822c.c`.
use super::super::firmware_transport::{Error, Io};
use super::{
    enable_mu, enable_su, gid_management, phy_init, readback, remove, remove_su, set_gid, Bfee,
    MuGroup, Role,
};
use alloc::{boxed::Box, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Regs {
    mem: Vec<u8>,
}
impl Regs {
    fn new() -> Self {
        Self {
            mem: vec![0; 0x10000],
        }
    }
    fn get(&self, r: u16) -> u32 {
        let r = usize::from(r);
        u32::from_le_bytes(self.mem[r..r + 4].try_into().unwrap())
    }
    fn set(&mut self, r: u16, v: u32) {
        let r = usize::from(r);
        self.mem[r..r + 4].copy_from_slice(&v.to_le_bytes());
    }
}
#[async_trait::async_trait]
// SAFETY: test model with no DMA or hardware.
unsafe impl Io for Regs {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn read8(&mut self, r: u16) -> Result<u8, Error> {
        Ok(self.mem[usize::from(r)])
    }
    fn read16(&mut self, r: u16) -> Result<u16, Error> {
        let r = usize::from(r);
        Ok(u16::from_le_bytes([self.mem[r], self.mem[r + 1]]))
    }
    fn read32(&mut self, r: u16) -> Result<u32, Error> {
        Ok(self.get(r))
    }
    fn write8(&mut self, r: u16, v: u8) -> Result<(), Error> {
        self.mem[usize::from(r)] = v;
        Ok(())
    }
    fn write16(&mut self, r: u16, v: u16) -> Result<(), Error> {
        let a = usize::from(r);
        self.mem[a..a + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, r: u16, v: u32) -> Result<(), Error> {
        self.set(r, v);
        Ok(())
    }
    async fn reserved_page(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Err(Error::Unsupported)
    }
    async fn lte_restore(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn delay_us(&mut self, _: u64) {}
}

const AP: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];

fn smoke_rtw88_bf_phy_init_and_su_bfee_program() -> TestResult {
    let mut r = Regs::new();
    // Prior MU state the source init must clear/replace.
    r.set(0x14c0, 0x0000_f0bf);
    r.set(0x6dc, 0x3f00_1000);
    if phy_init(&mut r).is_err() {
        return TestResult::Fail("rtw_bf_phy_init readback");
    }
    // P1 wait bit16, retry limit 0xa at 15:12, MU MIMO bit7 and table
    // valid 5:0 cleared; option 0x70; NDPA rate 0x10; CSI rate 6M.
    if r.get(0x14c0) != 0x0001_a000
        || r.mem[0x167c] != 0x70
        || r.get(0x1680) & 0xffff != 0
        || r.get(0x42c) != 1 << 30
        || r.mem[0x45f] != 0x10
        || r.get(0x6dc) != 0x0400_1000
    {
        return TestResult::Fail("rtw_bf_phy_init words");
    }
    // AP with 2 sounding dimensions (field 1); C22 nc 1, C21 nc 0.
    let (Some(c22), Some(c21)) = (Bfee::su(0xc822, AP, 2), Bfee::su(0xc821, AP, 2)) else {
        return TestResult::Fail("SU bfee refused");
    };
    if c22.csi_param() != 0x0d09
        || c21.csi_param() != 0x0d08
        || Bfee::su(0xb822, AP, 2).is_some()
        || Bfee::su(0xc822, AP, 0).is_some()
    {
        return TestResult::Fail("csi_param (coef 3, codebook 1, nr, nc) or chip gate");
    }
    r.mem[0x718] = 0x40;
    if enable_su(&mut r, 0xc822, c22).is_err() {
        return TestResult::Fail("C22 SU enable readback");
    }
    if r.mem[0x718] != 0xdb
        || r.mem[0x6e4..0x6ea] != AP
        || r.get(0x6f4) & 0xffff != 0x0d09
        || r.mem[0x71b] != 0x70
        || r.get(0x6dc) & (1 << 30 | 1 << 12) != 1 << 30
        || r.get(0x1678) != 0x550
    {
        return TestResult::Fail("rtw8822c_bf_enable_bfee_su words");
    }
    if remove_su(&mut r).is_err()
        || r.mem[0x718] != 0xd8
        || r.mem[0x6e4..0x6ea] != [0; 6]
        || r.get(0x6f4) & 0xffff != 0
        || readback(&mut r, 0xc822, c22).is_ok()
    {
        return TestResult::Fail("rtw_bf_remove_bfee_su");
    }
    let mut r = Regs::new();
    if enable_su(&mut r, 0xc821, c21).is_err() || r.get(0x1678) != 0 || r.get(0x6dc) != 0 {
        return TestResult::Fail("C21 uses the generic SU path only");
    }
    TestResult::Pass
}

/// Retained post-init RX filter maps: 0x6a0/0x6a2 0xffff (C22 init, C21
/// init followed by the source MAC table), RXFLTMAP4 bit4 set.
fn retained(r: &mut Regs) {
    r.mem[0x6a0..0x6a4].copy_from_slice(&[0xff; 4]);
    r.mem[0x68a] = 0x10;
}

fn smoke_rtw88_bf_mu_bfee_enable_and_remove() -> TestResult {
    // BSSID ..:0x84:0x55 -> p_aid (0x55 << 1) | (0x84 >> 7) = 0xab.
    let bssid = [2, 0x11, 0x22, 0x33, 0x84, 0x55];
    let (Some(c22), Some(c21)) = (Bfee::mu(0xc822, bssid, 5), Bfee::mu(0xc821, bssid, 5)) else {
        return TestResult::Fail("MU bfee refused");
    };
    if c22.role
        != (Role::Mu {
            p_aid: 0xab,
            aid: 5,
        })
        || !c22.is_mu()
        || c22.csi_param() != 0x0109
        || c21.csi_param() != 0x0108
        || Bfee::mu(0xb822, bssid, 5).is_some()
        || Bfee::mu(0xc822, bssid, 0).is_some()
    {
        return TestResult::Fail("rtw_bf_assoc MU p_aid / csi_param (coef 0, nr 1, nc)");
    }
    let mut r = Regs::new();
    retained(&mut r);
    r.mem[0x718] = 0x40;
    r.set(0x1680, 0xc000);
    r.set(0x6dc, 0x0400_7000);
    if phy_init(&mut r).is_err() {
        return TestResult::Fail("phy_init before MU enable");
    }
    r.set(0x1680, 0xc000);
    if enable_mu(&mut r, 0xc822, c22).is_err() {
        return TestResult::Fail("C22 MU enable readback");
    }
    if r.mem[0x6e4..0x6ea] != bssid
        || r.get(0x6e8) >> 16 != 0xab
        || r.get(0x6f4) & 0xffff != 0x0109
        || r.get(0x1680) & 0xffff != 0xc005
        || r.mem[0x718] != 0xdb
        || r.mem[0x71b] != 0x26
        // CSI_RSC 0 ORed in; bit12 cleared; NDPA rate bit30.
        || r.get(0x6dc) != 0x4400_6000
        || r.get(0x6a0) != 0xffff_ffff
        || r.mem[0x68a] != 0
        || r.get(0x1678) != 0
    {
        return TestResult::Fail("rtw_bf_enable_bfee_mu words (C22)");
    }
    if readback(&mut r, 0xc822, c22).is_err() {
        return TestResult::Fail("MU readback dispatch");
    }
    r.set(0x14c0, 0x0001_a0ff);
    if remove(&mut r, c22).is_err()
        || r.mem[0x718] != 0x40
        || r.mem[0x6e4..0x6ec] != [0; 8]
        || r.get(0x1680) & 0xffff != 0
        || r.get(0x14c0) != 0x0001_a000
        // Not cleared by rtw_bf_remove_bfee_mu.
        || r.get(0x6f4) & 0xffff != 0x0109
        || r.get(0x6a0) != 0xffff_ffff
        || readback(&mut r, 0xc822, c22).is_ok()
    {
        return TestResult::Fail("rtw_bf_remove_bfee_mu + rtw_bf_del_sounding");
    }
    // C21: CSI_RSC_FOLLOW_RX_PACKET_BW at bit13; retained 0x6a2 0xffff kept
    // (the stale Linux 0x0fff shadow is not written).
    let mut r = Regs::new();
    retained(&mut r);
    r.set(0x6dc, 0x0400_1000);
    if enable_mu(&mut r, 0xc821, c21).is_err()
        || r.get(0x6dc) != 0x4400_2000
        || r.get(0x6a0) != 0xffff_ffff
        || r.get(0x6f4) & 0xffff != 0x0108
    {
        return TestResult::Fail("rtw_bf_enable_bfee_mu words (C21)");
    }
    // An SU entry is not accepted by the MU path; SU removal stays SU.
    let Some(su) = Bfee::su(0xc822, bssid, 2) else {
        return TestResult::Fail("SU bfee refused");
    };
    let mut r = Regs::new();
    if enable_mu(&mut r, 0xc822, su).is_ok() || remove(&mut r, su).is_err() || r.mem[0x718] != 0x98
    {
        return TestResult::Fail("role dispatch");
    }
    TestResult::Pass
}

fn gid_frame(own: [u8; 6], ap: [u8; 6]) -> Vec<u8> {
    let mut f = vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&own);
    f.extend_from_slice(&ap);
    f.extend_from_slice(&ap);
    f.extend_from_slice(&[0x30, 0, 21, 1]);
    f.extend((1..=8).map(|i| i * 0x11));
    f.extend((0..16).map(|i| 0xa0 | i));
    f
}

fn smoke_rtw88_bf_vht_group_id_management_table() -> TestResult {
    let own = [0x02, 0, 0, 0, 0, 1];
    let f = gid_frame(own, AP);
    let Some(g) = gid_management(&f, own, AP) else {
        return TestResult::Fail("Group ID Management refused");
    };
    if g.membership != [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        || g.position[0] != 0xa0
        || g.position[15] != 0xaf
    {
        return TestResult::Fail("membership / user position parse");
    }
    let mut bad = f.clone();
    bad[25] = 0; // Operating Mode Notification
    let mut prot = f.clone();
    prot[1] = 0x40;
    let mut mcast = f.clone();
    mcast[4..10].copy_from_slice(&[0xff; 6]);
    if gid_management(&f[..49], own, AP).is_some()
        || gid_management(&bad, own, AP).is_some()
        || gid_management(&prot, own, AP).is_some()
        || gid_management(&mcast, own, AP).is_some()
        || gid_management(&f, own, [9; 6]).is_some()
    {
        return TestResult::Fail("admission (length, action, protected, RA, AP)");
    }
    let mut r = Regs::new();
    // Prior control: MU MIMO bit7 and table-valid bits set, bit6 kept;
    // table-select upper bits kept.
    r.mem[0x14c0] = 0xff;
    r.mem[0x14c1] = 0xfe;
    if set_gid(&mut r, &g).is_err() {
        return TestResult::Fail("rtw_bf_cfg_mu_bfee readback");
    }
    // Model keeps only the last selected table (1).
    if r.mem[0x14c0] != 0x43
        || r.mem[0x14c1] != 0xf9
        || r.get(0x14c4) != 0x8877_6655
        || r.get(0x14c8) != 0xabaa_a9a8
        || r.get(0x14cc) != 0xafae_adac
    {
        return TestResult::Fail("rtw_bf_cfg_mu_bfee table words");
    }
    if MuGroup::default() == g {
        return TestResult::Fail("mu_group change detection");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw88/bf",
    smoke_rtw88_bf_phy_init_and_su_bfee_program
);
kernel_test_in!(
    "drivers/wireless/rtw88/bf",
    smoke_rtw88_bf_mu_bfee_enable_and_remove
);
kernel_test_in!(
    "drivers/wireless/rtw88/bf",
    smoke_rtw88_bf_vht_group_id_management_table
);
