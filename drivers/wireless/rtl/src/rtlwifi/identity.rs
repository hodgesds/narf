// SPDX-License-Identifier: GPL-2.0-or-later
//! The probe's identification stage, shared by both builds.
//!
//! Linux `rtl_pci_probe` maps the chip's control BAR, then the per-chip
//! `read_eeprom_info` / `_rtl<chip>_init_mac` prefix powers the MAC from
//! CardDisabled to Active, masks the chip's interrupt sources and reads the
//! factory EFUSE map. Built in, `pci::bring_up` runs this inside its live PCI
//! capability operation; in `rtl.ko`, `pci_kabi` runs the same function over
//! the KABI register window. Neither build touches packet DMA here.

use super::{efuse, irq, power, regs::*};
use crate::platform::MmioRegion;

/// Why the identification stage stopped.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The chip's NIC-enable power sequence failed.
    PowerOn(power::PwrSeqError),
    /// The factory EFUSE map could not be read or decoded.
    Efuse(efuse::EfuseError),
}

/// Whether the mapped control BAR (BAR2) of chip `did` is `len` bytes long
/// enough for every register this driver addresses on it: the EFUSE access
/// gate everywhere, and the chip's full register map where one is defined.
pub fn control_bar_ok(did: u16, len: u64) -> bool {
    let need = match did {
        RTL_DEV_8188EE => 0x2000,
        RTL_DEV_8821AE => super::rtl8821ae::MMIO_SIZE as u64,
        RTL_DEV_8192EE => super::rtl8192ee::MMIO_SIZE as u64,
        RTL_DEV_8723AE => super::rtl8723ae::MMIO_SIZE as u64,
        RTL_DEV_8723BE => super::rtl8723be::MMIO_SIZE as u64,
        _ if super::rtl8192ce::is_8192ce(did) => super::rtl8192ce::MMIO_SIZE as u64,
        _ => 0,
    };
    len > REG_EFUSE_ACCESS && len >= need
}

/// Power the MAC on, mask interrupts and read the factory identity of the
/// PCI function `function` of chip `did`.
///
/// 1. The chip's NIC-enable table, where it has one (chips without one are
///    tolerated; Linux powers them later in `hw_init`).
/// 2. Both interrupt-mask registers cleared: nothing here owns an IRQ.
/// 3. RTL8723AE only: select the Wi-Fi EFUSE bank (`REG_EFUSE_TEST[9:8]`,
///    `rtl8723e_read_eeprom_info`).
/// 4. The physical EFUSE read and logical decode, MAC validated.
///
/// # Safety
/// The caller exclusively owns `registers`, chip `did`'s control BAR, with
/// memory decoding on and bus mastering parked, for the whole call.
pub unsafe fn identify(
    registers: &MmioRegion,
    did: u16,
    function: u8,
) -> Result<efuse::Factory, Error> {
    if power::power_on_table_for(did).is_some() {
        // SAFETY: BAR2 mapped and exclusively owned (caller contract).
        unsafe { power::power_on(registers, did) }.map_err(Error::PowerOn)?;
    }
    // SAFETY: as above.
    unsafe { irq::disable_interrupts_for(registers, did) };
    if did == RTL_DEV_8723AE {
        use super::rtl8723ae::adapter::{efuse_test_wifi_sel, REG_EFUSE_TEST};
        // SAFETY: as above; the length covers REG_EFUSE_ACCESS.
        unsafe {
            let value = registers.read32(u64::from(REG_EFUSE_TEST));
            registers.write32(u64::from(REG_EFUSE_TEST), efuse_test_wifi_sel(value));
        }
    }
    // SAFETY: as above; the EFUSE read clocks are configured by the reader.
    unsafe { efuse::read_factory(registers, did, function) }.map_err(Error::Efuse)
}

/// Whether the identified function's facts admit its retained native
/// station profile: the facts each chip's `configure_*` re-derives before
/// the function is retained (test chips, unprovisioned maps, unsupported
/// boards and maps without TX power stay diagnostic). Shared by both builds.
///
/// # Safety
/// As [`identify`]: `registers` is chip `did`'s exclusively owned control BAR.
pub unsafe fn admissible(
    registers: &MmioRegion,
    did: u16,
    function: u8,
    factory: &efuse::Factory,
) -> bool {
    let rtl8192ce = super::rtl8192ce::is_8192ce(did);
    let rtl8723be = did == RTL_DEV_8723BE;
    let rtl8192de = did == RTL_DEV_8192DE;
    let rtl8723ae = did == RTL_DEV_8723AE;
    // RTL8192EE: the facts `configure_rtl8192ee` re-derives, checked
    // before the function is retained. A test chip, an unprovisioned
    // map, a BT-coexist board (`rtl92ee_read_bt_coexist_info_from_hwpg`
    // board type 1) or a map without TX power (`0x11 == 0xff`, Linux's
    // autoload-fail TX power branch) stays diagnostic.
    let admissible = did != RTL_DEV_8192EE || {
        use super::rtl8192ee::{adapter, txpower};
        // SAFETY: BAR2 mapped, length checked above, owned exclusively.
        let (sys_cfg1, cr9346) = unsafe {
            (
                registers.read32(u64::from(adapter::REG_SYS_CFG1)),
                registers.read8(u64::from(adapter::REG_9346CR)),
            )
        };
        adapter::Adapter::from_hardware(sys_cfg1, cr9346, &factory.logical)
            .is_ok_and(|facts| !facts.bt_coexist && facts.mac == factory.mac)
            && txpower::Efuse::from_logical(&factory.logical).is_ok()
    };

    // RTL8192CE / RTL8188CE: the facts `configure_rtl8192ce`
    // re-derives. `_rtl92ce_read_chip_version` must qualify (no
    // `TRP_VAUX_EN` test chip, no `CHIP_BONDING_92C_1T2R`, no unknown
    // cut, so the RF type is RF_1T1R or RF_2T2R), the map must be
    // provisioned (`REG_9346CR` EFUSE boot, autoload, `0x8129`), the
    // board must not be BT-coexist (`RF_OPTION1[7:5]`), the EFUSE MAC
    // must be the factory identity and the TX-power areas must decode.
    let admissible = admissible
        && (!rtl8192ce || {
            use super::rtl8192ce::{adapter, txpower, version};
            // SAFETY: BAR2 mapped, length checked above, owned exclusively.
            let (sys_cfg, cr9346) = unsafe {
                (
                    registers.read32(u64::from(version::REG_SYS_CFG)),
                    registers.read8(u64::from(adapter::REG_9346CR)),
                )
            };
            // SAFETY: as above (HPON_FSM is read only for 92C serials).
            let hpon = || unsafe { registers.read32(u64::from(version::REG_HPON_FSM)) };
            version::Version::from_registers(sys_cfg, hpon).is_ok_and(|qualified| {
                adapter::Adapter::from_hardware(qualified, cr9346, &factory.logical).is_ok_and(
                    |facts| {
                        !facts.bt_coexistence()
                            && facts.mac == factory.mac
                            && txpower::Efuse::from_hwinfo(&facts.hwinfo).is_ok()
                    },
                )
            })
        });

    // RTL8723BE: the facts `configure_rtl8723be` re-derives.
    // `_rtl8723be_read_chip_version` must carry `CHIP_8723B`, the map
    // must be provisioned (`REG_9346CR` EFUSE boot, autoload, `0x8129`;
    // `_rtl8723be_read_package_type` reads physical `0x1fb`, 0 after a
    // timeout), the EFUSE MAC must be the factory identity and the
    // path-A TX-power area must decode (`0x11 != 0xff`).
    let admissible = admissible
        && (!rtl8723be || {
            use super::rtl8723be::{adapter, txpower, version};
            // SAFETY: BAR2 mapped, length checked above, owned exclusively.
            let (sys_cfg1, sys_cfg, cr9346, multi_func_ctrl) = unsafe {
                (
                    registers.read32(u64::from(version::REG_SYS_CFG1)),
                    registers.read32(u64::from(version::REG_SYS_CFG)),
                    registers.read8(u64::from(adapter::REG_9346CR)),
                    registers.read32(u64::from(adapter::REG_MULTI_FUNC_CTRL)),
                )
            };
            // SAFETY: as above; only the EFUSE read registers are touched.
            let package =
                unsafe { efuse::read_physical_byte(registers, adapter::EFUSE_PACKAGE_ADDR) }
                    .unwrap_or(0);
            version::Version::from_registers(sys_cfg1, sys_cfg).is_ok_and(|qualified| {
                adapter::Adapter::from_hardware(
                    qualified,
                    cr9346,
                    multi_func_ctrl,
                    &factory.logical,
                    package,
                )
                .is_ok_and(|facts| facts.mac == factory.mac)
            }) && txpower::Efuse::from_logical(&factory.logical).is_ok()
        });

    // RTL8723AE: the facts `configure_rtl8723ae` would re-derive.
    // `_rtl8723e_read_chip_version` must qualify (no `TRP_VAUX_EN`
    // test chip, `BT_FUNC` set so Linux assigns `RF_1T1R`), the map
    // must be provisioned (`REG_9346CR` EFUSE boot, autoload,
    // `0x8129`) and the EFUSE MAC must be the factory identity. A
    // BT-coexist board is the norm for this combo chip, not a refusal.
    let admissible = admissible
        && (!rtl8723ae || {
            use super::rtl8723ae::{adapter, version};
            // SAFETY: BAR2 mapped, length checked above, owned exclusively.
            let (sys_cfg, gpio, multi, cr9346) = unsafe {
                (
                    registers.read32(u64::from(version::REG_SYS_CFG)),
                    registers.read32(u64::from(version::REG_GPIO_OUTSTS)),
                    registers.read32(u64::from(version::REG_MULTI_FUNC_CTRL)),
                    registers.read8(u64::from(adapter::REG_9346CR)),
                )
            };
            version::Version::from_registers(sys_cfg, || gpio, || multi).is_ok_and(|qualified| {
                adapter::Adapter::from_hardware(qualified, cr9346, multi, &factory.logical)
                    .is_ok_and(|facts| facts.mac == factory.mac)
            })
        });

    // RTL8192DE: the facts `configure_rtl8192de` / `prepare_rtl8192de`
    // re-derive. `_rtl92de_read_chip_version` must not be a test chip
    // (`REG_SYS_CFG` version bits), EFUSE autoload must have succeeded
    // (`REG_9346CR` BIT(5): an autoload-failed board has no power-group
    // store for the channel step) and the PROM mode
    // (`rtl92d_read_eeprom_info` `EEPROM_MAC_FUNCTION`) must give this
    // function a bandset holding the 2.4 GHz station plan (a dual-dual
    // MAC0 is 5 GHz only; the composed station is 2.4 GHz legacy).
    admissible
        && (!rtl8192de || {
            use super::rtl8192de::{mode_from_prom, native_channel, version, Interface};
            // SAFETY: BAR2 mapped, length checked above, owned exclusively.
            let (sys_cfg, cr9346) = unsafe {
                (
                    registers.read32(u64::from(version::REG_SYS_CFG)),
                    registers.read8(u64::from(version::REG_9346CR)),
                )
            };
            sys_cfg != u32::MAX
                && sys_cfg & version::SYS_CFG_VERSION_MASK != 0
                && cr9346 & version::CR9346_AUTOLOAD_OK != 0
                && mode_from_prom(Interface::Pci, &factory.logical)
                    .is_some_and(|mode| native_channel(1, mode, function))
        })
}

/// `control_bar_ok` is the bound `pci::bring_up` used to spell inline
/// (before both builds shared it), for every id and around every edge.
#[cfg(feature = "kernel-test")]
fn smoke_rtlwifi_identity_control_bar_bound_matches_builtin() -> narf_kernel_test::TestResult {
    let inline = |did: u16, len: u64| {
        let rtl8192ce = super::rtl8192ce::is_8192ce(did);
        !(len <= REG_EFUSE_ACCESS
            || (did == RTL_DEV_8188EE && len < 0x2000)
            || (did == RTL_DEV_8821AE && len < super::rtl8821ae::MMIO_SIZE as u64)
            || (did == RTL_DEV_8192EE && len < super::rtl8192ee::MMIO_SIZE as u64)
            || (did == RTL_DEV_8723AE && len < super::rtl8723ae::MMIO_SIZE as u64)
            || (rtl8192ce && len < super::rtl8192ce::MMIO_SIZE as u64)
            || (did == RTL_DEV_8723BE && len < super::rtl8723be::MMIO_SIZE as u64))
    };
    let lengths = [
        0,
        REG_EFUSE_ACCESS,
        REG_EFUSE_ACCESS + 1,
        0x1fff,
        0x2000,
        0x3fff,
        0x4000,
        0x10000,
    ];
    for &did in ALL_DEV_IDS.iter().chain([0xB822u16, 0xffff].iter()) {
        for &len in &lengths {
            if control_bar_ok(did, len) != inline(did, len) {
                return narf_kernel_test::TestResult::Fail(
                    "identity::control_bar_ok differs from the built-in BAR2 bound",
                );
            }
        }
    }
    narf_kernel_test::TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "drivers/wireless/rtlwifi/module",
    smoke_rtlwifi_identity_control_bar_bound_matches_builtin
);
