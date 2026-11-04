use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn ap_get_key_selectors_refuse_peer_aliases_and_key_material() -> TestResult {
    let mut bytes = Vec::new();
    push_attr(&mut bytes, 8, &[1]);
    let group = selector(&attributes(&bytes).unwrap());
    if group
        != Ok(Selector {
            index: 1,
            pairwise: false,
            peer: None,
        })
    {
        return TestResult::Fail("group selector did not preserve the key index");
    }
    for (kind, value, expected) in [
        (6, [0xff; 6].to_vec(), ENOENT),
        (55, 2u32.to_ne_bytes().to_vec(), EINVAL),
        (313, vec![0], EINVAL),
        (7, vec![0x5a; 16], EINVAL),
        (80, vec![0; 8], EINVAL),
    ] {
        let mut request = bytes.clone();
        push_attr(&mut request, kind, &value);
        if selector(&attributes(&request).unwrap()) != Err(expected) {
            return TestResult::Fail("GET_KEY accepted an unsupported key/peer/link selector");
        }
    }
    let peer = [2, 0, 0, 0, 1, 2];
    let mut bytes = Vec::new();
    push_attr(&mut bytes, 6, &peer);
    if selector(&attributes(&bytes).unwrap())
        != Ok(Selector {
            index: 0,
            pairwise: true,
            peer: Some(peer),
        })
    {
        return TestResult::Fail("pairwise selector changed the original unicast client");
    }
    push_attr(&mut bytes, 55, &0u32.to_ne_bytes());
    if selector(&attributes(&bytes).unwrap()) != Err(ENOENT) {
        return TestResult::Fail("group peer namespace was admitted without IBSS_RSN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211/ap-key",
    ap_get_key_selectors_refuse_peer_aliases_and_key_material
);

fn ap_get_key_reply_matches_linux_sequence_only_shape() -> TestResult {
    let sequence = crate::KeySequence {
        cipher: 0x000fac04,
        seq: [1, 2, 3, 4, 5, 6],
    };
    let reply = reply(
        27,
        (3u64 << 32) | 27,
        Selector {
            index: 2,
            pairwise: false,
            peer: None,
        },
        sequence,
    );
    let attrs = attributes(&reply.attrs).unwrap();
    let nested = attributes(attr(&attrs, 80).unwrap()).unwrap();
    if reply.command != 11
        || attrs.len() != 6
        || nested.len() != 3
        || attr(&attrs, 8) != Some(&[2][..])
        || attr(&attrs, 153) != Some(&((3u64 << 32) | 27).to_ne_bytes()[..])
        || attr(&attrs, 10) != Some(&sequence.seq[..])
        || attr(&nested, 2) != Some(&[2][..])
        || attr(&nested, 4) != Some(&sequence.seq[..])
        || attr(&attrs, 9) != Some(&sequence.cipher.to_ne_bytes()[..])
        || attr(&nested, 3) != Some(&sequence.cipher.to_ne_bytes()[..])
        || attr(&attrs, 7).is_some()
        || attr(&nested, 1).is_some()
    {
        return TestResult::Fail("GET_KEY reply changed PN/cipher/index or exported key data");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211/ap-key",
    ap_get_key_reply_matches_linux_sequence_only_shape
);
