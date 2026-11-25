//! MLD station start-up shared by the built-in `device::Device` and the
//! module build (`module/pci.rs`): the firmware command-version profile and
//! the post-ALIVE configuration sequence (NVM, chains, coexistence, SoC,
//! scan configuration, device power, MAC and link contexts).
use super::{runtime::Hardware, station_api};

/// Refuse a firmware whose MLD station command versions this driver does not
/// implement (API89 MVM-unified images use their own profile).
pub(super) fn validate_station_profile(hardware: &Hardware) -> Result<(), &'static str> {
    if hardware.is_mvm89() {
        return Ok(());
    }
    for (group, command, version) in [
        (3, 8, 3),
        (3, 9, 8),
        (3, 10, 2),
        (1, 8, 6),
        (5, 0x17, 3),
        (1, 0xc, 5),
    ] {
        if hardware.version(group, command).map(|v| v.0) != Some(version) {
            return Err("unsupported MLD station command version");
        }
    }
    Ok(())
}

/// Read the NVM and send the runtime configuration commands, in the
/// built-in driver's order. Returns the NVM's channels, chains and PHY.
pub(super) async fn configure(
    hardware: &mut Hardware,
    mac: [u8; 6],
) -> Result<station_api::Nvm, &'static str> {
    let nvm_packet = hardware.command(0xc, 2, &[0; 4]).await?;
    let mut nvm = station_api::Nvm::parse(
        hardware.version(0xc, 2).ok_or("missing NVM version")?.1,
        &nvm_packet.payload,
    )?;
    if nvm.phy.ht {
        hardware.check_aggregation_api()?;
    }
    nvm.phy.he &= super::sc_he::native_supported(hardware);
    nvm.phy.native_rates = super::sc_he::rates_version(hardware).unwrap_or(0);
    nvm.phy.eht = nvm.phy.he && hardware.eht_supported();
    nvm.phy.eht_320 = nvm.phy.eht && hardware.eht_320_supported();
    if !nvm.phy.he || !hardware.band_in_rx_supported() {
        nvm.six_channels.clear();
    }
    let runtime = hardware.runtime_configuration()?;
    hardware
        .command(1, 0x98, &nvm.tx_chains.to_le_bytes())
        .await?;
    hardware.command(1, 0x9b, &runtime.coexistence).await?;
    hardware.command(2, 1, &runtime.soc).await?;
    hardware.station_receive_chains(nvm.rx_chains).await?;
    hardware
        .command(1, 0xc, &station_api::scan_config(&nvm))
        .await?;
    hardware.command(1, 0x77, &runtime.power).await?;
    hardware
        .command(3, 8, &station_api::mac(1, mac, None))
        .await?;
    hardware
        .command(3, 9, &station_api::link(1, mac, false, 1, 0, 1))
        .await?;
    Ok(nvm)
}
