# MT7921/MT7922 WM feature receipts

Audit date: 2026-10-30. These are observations of the actual installed primary
firmware artifacts, not a claim that every future image has the same features.

The source model is Linux `drivers/net/wireless/mediatek/mt76/mt792x_core.c`,
`mt792x_get_offload_capability` (:861–919): sum the lengths of the trailer's
40-byte region records, skip the16-byte release prefix, walk the bounded release
headers and read tag4's16-byte body data byte1. `mt792x.h` defines CNM=bit7 and
NAN=bit5. `mt792x_init_wiphy` (:795–807) adds NAN/NAN_DATA only when both are set;
the ordinary station/AP/P2P roles (:790–794) are independent of these bits.
The current native `fw_features::parse` uses those same actual offsets with
extent and duplicate validation. Observing a feature grants no firmware, device,
started-wdev or RF authority.

| Installed artifact under `/usr/lib/firmware/mediatek/` | Bytes | Build date | Release header offset | Feature data offset | Feature byte |
| --- | ---: | --- | ---: | ---: | --- |
| `WIFI_RAM_CODE_MT7961_1.bin` | 792036 | 20260224110949 | 791664 | 791769 | 0xc0 |
| `WIFI_RAM_CODE_MT7961_1a.bin` | 802808 | 20260224110939 | 802432 | 802541 | 0xc0 |
| `WIFI_RAM_CODE_MT7922_1.bin` | 1122084 | 20260605203411 | 1121680 | 1121777 | 0xc0 |

SHA256 identities:

- MT7961_1: `b94217a951518a9c14095765f367bc5dd7698f2dc033941d6f18fc2ebd6a2ab9`
- MT7961_1a: `3edec74ffe341b917e7fa4ddb2b68851411f2416555f10619a5900fa4b141e6c`
- MT7922_1: `d95cef824e8fd6a51324a04eca067c2a005239451f471a96a83d0190b022e7fe`

All three actual feature receipts therefore enable CNM and leave NAN clear.
Modern generic mt792x NAN code is real, but these supported-family artifacts do
not make its positive advertisement condition true. The prior claim that no
NAN mode exists anywhere in mt76 was too broad. Future supported-family firmware
with both bits set must trigger a new conditional implementation/applicability
audit; these dated negative receipts cannot exclude that future capability.
