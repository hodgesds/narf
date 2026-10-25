#!/usr/bin/env python3
"""Compile Linux's unchanged CONNAC2 scan encoder over a minimal host adapter.

Only the allocation, wiphy inputs and send callback are replaced. The packed
structures and mt76_connac_mcu_hw_scan function come from the original source.
The output is parser/command evidence, never executable device firmware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src/mt7921/scan_oracle.bytes"
META = OUT.with_suffix(".json")
POWER_ORDER = OUT.with_name("power_order.bytes")

PREFIX = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint16_t __le16;
typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define IEEE80211_MAX_SSID_LEN 32
#define ETH_ALEN 6
#define MT76_CONNAC_SCAN_IE_LEN 600
#define MT76_CONNAC_SCAN_CHANNEL_TIME 60
#define MT76_HW_SCANNING 0
#define BIT(n) (1U << (n))
#define max_t(t,a,b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define min_t(t,a,b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define cpu_to_le16(x) ((uint16_t)(x))
#define cpu_to_le32(x) ((uint32_t)(x))
#define SCAN_FUNC_SPLIT_SCAN BIT(5)
#define SCAN_FUNC_RANDOM_MAC BIT(0)
#define NL80211_SCAN_FLAG_RANDOM_ADDR 1
#define NL80211_BAND_2GHZ 0
#define NL80211_BAND_5GHZ 1
#define NL80211_BAND_6GHZ 3
#define MCU_CE_CMD(x) 3
struct mt76_dev { int unused; };
struct mt76_phy {
    struct mt76_dev *dev; unsigned long state;
    struct { bool has_2ghz, has_5ghz, has_6ghz; } cap;
};
static int mt76_connac_mcu_rate_txpower_band(struct mt76_phy *phy, int band) {
    (void)phy;
    if (fputc(band == NL80211_BAND_2GHZ ? 1 : band == NL80211_BAND_5GHZ ? 2 : 3, stdout) == EOF) abort();
    return 0;
}
struct mt76_vif_link { u8 scan_seq_num, band_idx, idx; };
struct ieee80211_vif { void *drv_priv; };
struct ieee80211_channel { int band, hw_value; };
struct cfg80211_ssid { u8 ssid[32]; u8 ssid_len; };
struct cfg80211_scan_request {
    int n_ssids, n_channels, ie_len, flags;
    struct cfg80211_ssid *ssids;
    struct ieee80211_channel **channels;
    u8 *ie;
    u8 bssid[6], mac_addr[6], mac_addr_mask[6];
};
struct ieee80211_scan_request { struct cfg80211_scan_request req; };
struct sk_buff { void *data; size_t length; };
static int test_bit(int bit, unsigned long *value) { return !!(*value & (1UL << bit)); }
static void set_bit(int bit, unsigned long *value) { *value |= 1UL << bit; }
static void clear_bit(int bit, unsigned long *value) { *value &= ~(1UL << bit); }
static int is_connac2(struct mt76_dev *dev) { (void)dev; return 1; }
static struct sk_buff *mt76_mcu_msg_alloc(struct mt76_dev *dev, void *data, size_t len) {
    (void)dev; (void)data;
    struct sk_buff *skb = calloc(1, sizeof(*skb));
    skb->data = calloc(1, len); skb->length = len; return skb;
}
static void *skb_put_zero(struct sk_buff *skb, size_t len) {
    if (len != skb->length) abort();
    return skb->data;
}
static void get_random_mask_addr(u8 *out, u8 *address, u8 *mask) {
    (void)out; (void)address; (void)mask; abort();
}
static int mt76_mcu_skb_send_msg(struct mt76_dev *dev, struct sk_buff *skb, int cmd, bool response) {
    (void)dev; (void)cmd;
    if (response || fwrite(skb->data, 1, skb->length, stdout) != skb->length) abort();
    free(skb->data); free(skb); return 0;
}
"""

SUFFIX = r"""
static void fixture(int sequence, const u8 *numbers, int count,
                    const struct cfg80211_ssid *input, int ssid_count) {
    struct mt76_dev dev = {0};
    struct mt76_phy phy = {.dev = &dev};
    struct mt76_vif_link link = {.scan_seq_num = sequence - 1};
    struct ieee80211_vif vif = {.drv_priv = &link};
    struct ieee80211_channel channels[64];
    struct ieee80211_channel *pointers[64];
    for (int i = 0; i < count; i++) {
        channels[i].hw_value = numbers[i];
        channels[i].band = numbers[i] <= 11 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ;
        pointers[i] = &channels[i];
    }
    struct ieee80211_scan_request scan = {.req = {
        .channels = pointers, .n_channels = count,
        .ssids = (struct cfg80211_ssid *)input, .n_ssids = ssid_count,
        .bssid = {255,255,255,255,255,255},
    }};
    if (mt76_connac_mcu_hw_scan(&phy, &vif, &scan)) abort();
}
int main(void) {
    u8 passive[] = {1,6,36};
    fixture(1, passive, 3, NULL, 0);
    u8 wildcard_channels[] = {1,6,11};
    struct cfg80211_ssid wildcard[] = {{.ssid_len = 0}};
    fixture(127, wildcard_channels, 3, wildcard, 1);
    u8 directed_channels[] = {36,1,177};
    struct cfg80211_ssid directed[4] = {
        {.ssid = {'n','a','r','f',0,'o','n','e'}, .ssid_len = 8},
        {.ssid_len = 32}, {.ssid = {'x'}, .ssid_len = 1},
        {.ssid = {'f','o','u','r'}, .ssid_len = 4},
    };
    for (int i = 0; i < 32; i++) directed[1].ssid[i] = i;
    fixture(7, directed_channels, 3, directed, 4);
    u8 all_channels[] = {1,2,3,4,5,6,7,8,9,10,11,36,40,44,48,52,56,60,64,
        100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165,169,173,177};
    struct cfg80211_ssid mixed[4] = {
        {.ssid_len = 0}, {.ssid = {'h','i','d','d','e','n'}, .ssid_len = 6},
        {.ssid_len = 0}, {.ssid = {'z'}, .ssid_len = 1},
    };
    fixture(2, all_channels, 39, mixed, 4);
    struct mt76_phy phy = {.cap = {.has_2ghz = true, .has_5ghz = true}};
    if (mt76_connac_mcu_set_rate_txpower(&phy)) abort();
    return 0;
}
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--linux", type=Path, default=Path("/usr/src/linux"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = args.linux / "drivers/net/wireless/mediatek/mt76"
    c_bytes = (directory / "mt76_connac_mcu.c").read_bytes()
    h_bytes = (directory / "mt76_connac_mcu.h").read_bytes()
    c, h = c_bytes.decode(), h_bytes.decode()
    structures = []
    for name in ("mt76_connac_mcu_scan_channel", "mt76_connac_mcu_scan_ssid", "mt76_connac_hw_scan_req"):
        match = re.search(r"^struct " + name + r" \{.*?^\} __packed;", h, re.M | re.S)
        if match is None:
            raise SystemExit(f"missing original structure: {name}")
        structures.append(match.group())
    function = c[c.index("int mt76_connac_mcu_hw_scan("):c.index("EXPORT_SYMBOL_GPL(mt76_connac_mcu_hw_scan);")]
    power_function = c[c.index("int mt76_connac_mcu_set_rate_txpower("):c.index("EXPORT_SYMBOL_GPL(mt76_connac_mcu_set_rate_txpower);")]
    with tempfile.TemporaryDirectory(prefix="narf-mt76-scan-oracle-") as tmp:
        source, binary = Path(tmp) / "oracle.c", Path(tmp) / "oracle"
        source.write_text(PREFIX + "\n".join(structures) + "\n" + function + power_function + SUFFIX)
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)], check=True)
        output = subprocess.check_output([str(binary)])
    assert len(output) == 4 * 1186 + 2
    power_order, output = output[-2:], output[:-2]
    metadata = json.dumps({
        "source": "Linux mt76_connac_mcu_hw_scan, original packed structures",
        "c_sha256": hashlib.sha256(c_bytes).hexdigest(),
        "h_sha256": hashlib.sha256(h_bytes).hexdigest(),
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "fixture_bytes": 1186,
        "power_order_source": "unchanged mt76_connac_mcu_set_rate_txpower with dual-band PHY",
        "power_order_sha256": hashlib.sha256(power_order).hexdigest(),
        "cases": ["passive", "active wildcard", "four directed binary SSIDs", "39 channels/mixed empty SSIDs"],
    }, indent=2) + "\n"
    if args.check:
        if OUT.read_bytes() != output or META.read_text() != metadata or POWER_ORDER.read_bytes() != power_order:
            raise SystemExit("original Linux scan oracle differs")
    else:
        OUT.write_bytes(output)
        META.write_text(metadata)
        POWER_ORDER.write_bytes(power_order)


if __name__ == "__main__":
    main()
