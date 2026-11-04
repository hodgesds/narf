# ath10k explicit indoor installation policy

This is an additional current host-policy condition for the already admitted
station channels and occupied20/40/80 or separately admitted80+80 spans. It
adds no frequency, factory identity, firmware capability, power or width.

## Installation fact and authority

NRGD v1 rule flag bit1 (`INDOOR_ONLY`) remains restrictive. Additional bit7
(`DEPLOYMENT_INDOOR`) means that the trusted deployment-policy installer
asserts that this installation is indoors. The two bits must appear together
before this station profile may transmit under an indoor-only rule. A lone
installation bit is rejected by the shared parser and the native permission
check. Indoor-only rules without the fact remain valid restrictive policies.

The source is the existing signed `wireless-regulatory.bin` bootstrap through
current firmware capability invocation, or the existing trusted policy
installer. Parsing alone authenticates nothing. Installation maintenance is
the installer's responsibility: it must replace or clear policy when the
physical deployment changes. No AP beacon, Country IE, EEPROM country code
or radio capability asserts indoor installation. Firmware-blob revocation
does not retroactively revoke an already installed database snapshot; the
existing trusted installer must replace or clear that policy.

Linux v7.2 treats indoor operation as a separately supplied installation fact
in [`regulatory_hint_indoor`](https://github.com/torvalds/linux/blob/v7.2/net/wireless/reg.c)
and the nl80211 user regulatory hint. NARF supplies the corresponding fact
through its signed deployment-policy contract. This continuation does not
implement Linux's netlink-owner lifetime or claim that a country database
alone proves installation location. `GET_REG` still reports the indoor-only
restriction as Linux `NO_OUTDOOR`; deployment metadata is not another Linux
restriction flag.

## Native admission and loss

`regulatory::Permission` intersects every overlapping rule with the immutable
factory country/CTL, reported hardware frequency range, existing primary and
extension/segment geometry, maximum bandwidth and minimum power ceiling.
Each overlapping indoor-only row needs its own installation fact. A second
permissive row cannot erase another row's restriction. DFS, NO_IR, unknown
restrictions, negative power and World-factory5GHz remain refused.

The original permission is used by native active probes, station setup,
peer/port admission and the existing current-policy packet/control/copy
guards. Removing the installation bit while retaining `INDOOR_ONLY` makes
revalidation fail before further native publication. Reinstallation does not
reopen a terminal old radio or authorize an old queued frame. This closes
host admission; it does not retract already published DMA or establish
autonomous firmware RF quiescence.

## Software evidence and physical qualification

The source cases include an independently signed test-only NRGD vector
through the actual firmware registry, unsigned/tampered/revoked refusal,
20/40/80 whole-span and overlapping-rule checks, native Open/WPA2 active and
passive discovery through real CE/HTT/RSNA/DHCP/IP, VHT80 receive/transmit,
and installation-fact loss during queued DATA and native credit waits.
Existing unproven-indoor negatives remain. The test key is the public
RFC8032 example, compiled only with tests; it is never a deployment key.

Release compile/native acceptance is pending. Actual indoor installation,
country policy, vendor calibration, signed assets and per-device RF/power
acceptance remain deployment responsibilities.
