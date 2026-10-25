# Wi-Fi conversation fixtures

`narf-wifi-fixtures` supplies deterministic AP and DHCP peers for driver
conversation tests. It is a no_std verification dependency alongside
`narf-kernel-test`, not a station implementation. The shared peer speaks
ordinary 802.11/EAPOL and Ethernet; each adapter retains its own firmware wire
format, rings, completions, regulatory policy and controlled port. See
[verification §3](../specification/spec.md#3-test-taxonomy) for the contract.

`FakeAp` handles one legacy 2.4-GHz Open or WPA2-PSK/CCMP association, including
M2/M4 MIC and replay validation. `with_basic_1mbps()` selects the checked CCK
rate profile required by RTL8188EU before authentication; other adapters keep
the default OFDM profile. `DhcpServer` handles one station's initial
lease, correlated by its Ethernet/BOOTP identity, transaction, requested
address and server. It rejects malformed checksums, lengths and duplicate
control options. Renewal, roaming, WPA3, 6 GHz and physical RF are outside
this fixture profile.

Kernel fixtures compare the AP's PTK against an independently computed
SHA1-PRF vector and reject truncated packets, foreign peers, wrong RSN, replay
counters and MICs. They run inside QEMU because the real network and crypto
types depend on kernel linker symbols. For example:

```sh
cargo xtask test --arch=x86_64 --subsystem verification/wifi-fixtures,drivers/wireless/mt7921/dhcp,drivers/wireless/ath11k/dhcp,drivers/wireless/iwlwifi/dhcp,drivers/wireless/rtl8xxxu/dhcp,drivers/wireless/brcmfmac/station,drivers/wireless/cyw43439/interface
cargo xtask test --arch=aarch64 --subsystem verification/wifi-fixtures,drivers/wireless/mt7921/dhcp,drivers/wireless/iwlwifi/dhcp,drivers/wireless/rtl8xxxu/dhcp,drivers/wireless/brcmfmac/station,drivers/wireless/cyw43439/interface
```

MT76 uses the reactive shared AP and its native CONNAC2 descriptor adapter.
Ath11k retains its WMI/HTT/native TCL/REO-ring AP and consumes the shared DHCP
peer. Intel Sc c103 uses the shared AP after firmware INIT through native
TFH/RFH queues. RTL8188EU uses native USB descriptors, the shared AP and actual
software CCMP on its initial channel1 profile. CYW retains its SDPCM/BDC
FullMAC firmware model; BCM43602 uses CR4/msgbuf shared5/6 rings with zero
descriptor prefix. Their WPA2 evidence is firmware-offloaded key completion.
Each path runs the production DHCP client and verifies the resulting lease
and exact post-lease Ethernet data in both directions. Synthetic board,
calibration and firmware inputs remain private to these fixtures; physical
acceptance still requires the exact authenticated deployment assets.

`firmware::metadata_replay` also supports firmware parser fixtures. It rebuilds
the original image geometry from bounded metadata fragments while zeroing all
omitted executable/calibration bytes. These synthetic images must never be
registered or loaded onto a device. See the [fixture provenance and audit
instructions](../data/wifi-firmware/README.md).
