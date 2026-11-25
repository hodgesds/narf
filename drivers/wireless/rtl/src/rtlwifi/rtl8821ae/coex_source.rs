// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact source helpers bound before N21C measurement issuance. This
//! conservatively invalidates a record on source-text changes; it is not
//! executable signing, a compiler attestation or physical RF evidence.
use crate::platform::lib::sync::OnceLock;

pub(super) fn digest() -> [u8; 32] {
    static DIGEST: OnceLock<[u8; 32]> = OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(b"NARF RTL8821AE N21C explicit source-program set v1");
        for (name, bytes) in [
            (
                "halbtc8821a1ant",
                include_bytes!("../btcoex/b8821a1ant.rs").as_slice(),
            ),
            (
                "halbtc8821a2ant",
                include_bytes!("../btcoex/b8821a2ant.rs").as_slice(),
            ),
            ("common-btc", include_bytes!("../btcoex/btc.rs").as_slice()),
            ("8821-btc", include_bytes!("btc.rs").as_slice()),
            ("8821-h2c", include_bytes!("h2c.rs").as_slice()),
            ("8821-phy", include_bytes!("phy.rs").as_slice()),
            ("8821-trx", include_bytes!("trx.rs").as_slice()),
            (
                "8821-coex-runtime",
                include_bytes!("coex_runtime.rs").as_slice(),
            ),
            (
                "8821-coex-dispatch",
                include_bytes!("coex_dispatch.rs").as_slice(),
            ),
            (
                "8821-coex-inbox",
                include_bytes!("coex_inbox.rs").as_slice(),
            ),
            (
                "8821-native-packet",
                include_bytes!("../packet_ae.rs").as_slice(),
            ),
            (
                "8821-station-hooks",
                include_bytes!("../coex_8821_runtime.rs").as_slice(),
            ),
            ("8821-park", include_bytes!("park.rs").as_slice()),
            (
                "8821-native-park",
                include_bytes!("park_native.rs").as_slice(),
            ),
        ] {
            h.update(&(name.len() as u64).to_le_bytes());
            h.update(name.as_bytes());
            h.update(&(bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        h.finalize()
    })
}
