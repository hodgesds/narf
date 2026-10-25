#!/usr/bin/env python3
"""Compile unchanged Linux CONNAC2 marker/padding and A-MSDU conversion code.

The adapter supplies only skb storage/queue operations and a fixed three-address
QoS header length for these fixtures. Descriptor macros, marker interpretation,
padding removal, subframe lengths, injection detection and Ethernet conversion
come from the original source, with source/output hashes retained beside bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src/mt7921/amsdu_oracle.bytes"

PREFIX = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint16_t __be16;
typedef uint16_t __le16;
#define ETH_ALEN 6
#define ETH_P_AARP 0x80f3
#define ETH_P_IPX 0x8137
#define ALIGN(v,a) (((v)+(a)-1)&~((a)-1))
#define GENMASK(h,l) (((1U << ((h)-(l)+1))-1) << (l))
#define BIT(n) (1U << (n))
#define FIELD_GET(mask,value) (((value)&(mask)) >> __builtin_ctz(mask))
#define be16_to_cpu(v) ntohs(v)
#define le16_to_cpu(v) (v)
#define likely(v) (v)
enum nl80211_iftype { NL80211_IFTYPE_STATION, NL80211_IFTYPE_MESH_POINT };
struct ethhdr { u8 h_dest[6], h_source[6]; __be16 h_proto; } __attribute__((packed));
struct sk_buff {
    u8 *allocation, *data;
    unsigned int len;
    bool head_frag;
    void *dev;
    int priority;
    struct sk_buff *next;
};
struct sk_buff_head { struct sk_buff *head, *tail; };
static const u8 rfc1042_header[] = {0xaa,0xaa,3,0,0,0};
static const u8 bridge_tunnel_header[] = {0xaa,0xaa,3,0,0,0xf8};
static bool ether_addr_equal(const void *a, const void *b) { return !memcmp(a,b,6); }
static bool is_multicast_ether_addr(const void *p) { return *(const u8 *)p & 1; }
static int skb_has_frag_list(struct sk_buff *skb) { (void)skb; return 0; }
static int skb_is_nonlinear(struct sk_buff *skb) { (void)skb; return 0; }
static unsigned int __ieee80211_get_mesh_hdrlen(u8 flags) { (void)flags; abort(); }
static void skb_copy_bits(struct sk_buff *skb, int offset, void *out, int count) {
    if (offset < 0 || count < 0 || (unsigned int)(offset+count) > skb->len) abort();
    memcpy(out, skb->data+offset, count);
}
static void *skb_pull(struct sk_buff *skb, unsigned int count) {
    if (count > skb->len) abort();
    skb->data += count; skb->len -= count; return skb->data;
}
static void *skb_push(struct sk_buff *skb, unsigned int count) {
    if (skb->data-count < skb->allocation) abort();
    skb->data -= count; skb->len += count; return skb->data;
}
static void skb_reset_network_header(struct sk_buff *skb) { (void)skb; }
static void dev_kfree_skb(struct sk_buff *skb) { free(skb->allocation); free(skb); }
static void __skb_queue_tail(struct sk_buff_head *queue, struct sk_buff *skb) {
    if (queue->tail) queue->tail->next=skb; else queue->head=skb;
    queue->tail=skb;
}
static void __skb_queue_purge(struct sk_buff_head *queue) {
    struct sk_buff *skb=queue->head;
    while (skb) { struct sk_buff *next=skb->next; dev_kfree_skb(skb); skb=next; }
    queue->head=queue->tail=NULL;
}
static struct sk_buff *__ieee80211_amsdu_copy(struct sk_buff *skb, unsigned int hlen,
                    int offset, int len, bool reuse, int room) {
    (void)skb; (void)hlen; (void)offset; (void)len; (void)reuse; (void)room; abort();
}
static struct sk_buff *make_skb(const u8 *data, size_t length) {
    struct sk_buff *skb=calloc(1,sizeof(*skb));
    skb->allocation=calloc(1,64+length); skb->data=skb->allocation+64;
    skb->len=length; memcpy(skb->data,data,length); return skb;
}
static unsigned int ieee80211_get_hdrlen_from_skb(struct sk_buff *skb) {
    if (skb->len<26 || skb->data[0]!=0x88 || (skb->data[1]&3)!=2) abort();
    return 26;
}
static void emit(const void *data, size_t length) {
    if (fwrite(data,1,length,stdout)!=length) abort();
}
"""

SUFFIX = r"""
int main(void) {
    const u8 own[]={2,0x11,0x22,0x33,0x44,0x55}, ap[]={2,1,2,3,4,5};
    for (u8 marker=0;marker<4;marker++) {
        u8 frame[53]={0x88,2};
        memcpy(frame+4,own,6); memcpy(frame+10,ap,6); memcpy(frame+16,ap,6);
        frame[22]=0x70; frame[24]=0x80;
        frame[26]=0xde; frame[27]=0xad;
        memcpy(frame+28,own,6); memcpy(frame+34,ap,6); frame[41]=11;
        memcpy(frame+42,rfc1042_header,6); frame[48]=8;
        frame[50]=frame[51]=frame[52]=marker;
        struct sk_buff *skb=make_skb(frame,sizeof(frame));
        struct { bool amsdu, first_amsdu, last_amsdu; } state={0}, *status=&state;
        u8 amsdu_info; unsigned int rxd4=marker;
        /* ORIGINAL_MARKERS */
        /* ORIGINAL_PADDING */
        u8 result[]={marker,status->amsdu,status->first_amsdu,status->last_amsdu,(u8)skb->len};
        emit(result,sizeof(result)); emit(skb->data,skb->len);
        dev_kfree_skb(skb);
        // Linux conversion of the source-padded native subframe's MSDU span.
        struct sk_buff_head queue={0};
        skb=make_skb(frame+28,sizeof(frame)-28);
        ieee80211_amsdu_to_8023s(skb,&queue,own,NL80211_IFTYPE_STATION,0,own,NULL,0);
        if (!queue.head || queue.head!=queue.tail || queue.head->len!=17) abort();
        emit(queue.head->data,queue.head->len); __skb_queue_purge(&queue);
    }
    return 0;
}
"""


def original_function(text, start, end):
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--linux", type=Path, default=Path("/usr/src/linux"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    sources = {
        name: (args.linux / name).read_bytes() for name in (
            "drivers/net/wireless/mediatek/mt76/mt76_connac2_mac.h",
            "drivers/net/wireless/mediatek/mt76/mt7921/mac.c",
            "net/wireless/util.c",
        )
    }
    header, mac, util = (value.decode() for value in sources.values())
    macros = "\n".join(re.findall(r"^#define MT_RXD4_(?:NORMAL_PAYLOAD_FORMAT|FIRST_AMSDU_FRAME|LAST_AMSDU_FRAME).*", header, re.M))
    assert len(macros.splitlines()) == 3
    markers = original_function(mac, "\tamsdu_info = FIELD_GET", "\n\thdr_gap =")
    padding_start = mac.index("\t\t\tmemmove(skb->data + 2, skb->data,")
    padding = mac[padding_start:mac.index("\n\t\t}", padding_start)]
    functions = "\n".join((
        original_function(util, "bool ieee80211_get_8023_tunnel_proto(", "EXPORT_SYMBOL(ieee80211_get_8023_tunnel_proto);"),
        original_function(util, "static u16\nieee80211_amsdu_subframe_length(", "\n}\n") + "\n}",
        original_function(util, "static bool\nis_amsdu_aggregation_attack(", "EXPORT_SYMBOL(ieee80211_amsdu_to_8023s);"),
    ))
    # The marker block and two-byte removal are unchanged source slices.
    suffix = SUFFIX.replace("/* ORIGINAL_MARKERS */", markers).replace(
        "/* ORIGINAL_PADDING */", "if (status->amsdu) {\n" + padding + "\n}"
    )
    with tempfile.TemporaryDirectory(prefix="narf-mt76-amsdu-oracle-") as tmp:
        source, binary = Path(tmp) / "oracle.c", Path(tmp) / "oracle"
        source.write_text(PREFIX + macros + "\n" + functions + suffix)
        subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-sign-compare", "-Wno-address-of-packed-member", str(source), "-o", str(binary)], check=True)
        output = subprocess.check_output([str(binary)])
    metadata = json.dumps({
        "source": "Original Linux CONNAC2 RXD4 macros, mt7921_mac_fill_rx marker/padding slices, ieee80211_amsdu_to_8023s and helper functions",
        "source_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()},
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "cases": "RXD4 normal/last/middle/first; normalized native frame then Ethernet-II bytes",
        "adapter": "Fixed native three-address QoS header geometry; skb storage and queue operations only; no device or firmware execution",
    }, indent=2) + "\n"
    if args.check:
        if OUT.read_bytes() != output or OUT.with_suffix(".json").read_text() != metadata:
            raise SystemExit("original Linux A-MSDU receive oracle differs")
    else:
        OUT.write_bytes(output)
        OUT.with_suffix(".json").write_text(metadata)


if __name__ == "__main__":
    main()
