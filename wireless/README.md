# wireless — 802.11 Wireless Networking Core

`narf-wireless` is NARF's wireless networking core: the kernel-side
control plane for IEEE 802.11 (Wi-Fi) interfaces. It is the wireless
analogue of a cfg80211/nl80211 layer, sitting above the generic network
stack in `narf-net` and below the concrete chip drivers in
`drivers/wireless`. It owns the vocabulary that every Wi-Fi interface
shares — scanning, association, PHY configuration, security — while
leaving radio-specific register and firmware work to the drivers and
complex policy to userspace.

The core extends the generic `Interface` abstraction from `narf-net`
with an 802.11-aware interface trait. Through it, authorized callers
trigger scans and read back discovered BSSIDs, associate with and leave
access points, and adjust PHY parameters such as channel and transmit
power. Interfaces register themselves in a global registry so the rest
of the system can enumerate the available radios. An nl80211-style
control surface (modeled on the Linux UAPI, with its own submodule)
exposes this functionality in a familiar shape.

A substantial part of the crate is the 802.11 security machinery,
implemented clean-room from the public IEEE standards. This includes the
EAPOL 4-Way Handshake and PRF/PTK key derivation (IEEE 802.1X and
802.11 §12.7), CCMP packet protection built on AES-CCM (§12.5.3), the
RSN information element and cipher/AKM suite tables (§9.4.2.24),
management frame protection (MFP/802.11w), SAE for WPA3
(§12.4, Simultaneous Authentication of Equals), and MLME helpers for
building and parsing management frames (§9). Cryptographic primitives —
AES-CCM, the ECC group, and MAC functions — are injected through traits
so the protocol state machines compile without dragging in the full
crypto stack; production wires them to `narf-crypto`. A regulatory
submodule validates channel use against a database rather than trusting
the radio alone.

Design intent is microkernel-pure and capability-gated: the kernel does
not host a full supplicant, and discovery (scan) is a distinct right
from connectivity (associate), with further rights for PHY config and
monitor mode. Secret key material uses `zeroize` to scrub on drop.
Capabilities, IPC rings, scheduling, and I/O come from the respective
NARF crates; the crate is `no_std`.

- Spec: [`specification/spec.md`](./specification/spec.md)
