# Linux wireless regulatory database

`regulatory.db`, its detached `regulatory.db.p7s`, and `LICENSE` are
unmodified files from [wireless-regdb 2026.09.03](https://www.kernel.org/pub/software/network/wireless-regdb/wireless-regdb-2026.09.03.tar.xz).
The database is ISC licensed; its copyright and permission notice are in
`LICENSE`. This is a generic upstream asset, independent of the build host,
hardware, and deployment country.

`trusted-certs.pem` contains the two public X.509 certificates shipped by
Linux in [`net/wireless/certs`](https://github.com/torvalds/linux/tree/master/net/wireless/certs),
converted from the hexadecimal DER representation without modifying their
bytes. Source revision: `ecd997b0189a6c40f5df66cb72d1df4e0f080443`.
SHA-256 fingerprints of their DER encodings:

| Certificate | SHA-256 |
| --- | --- |
| Seth Forshee (`sforshee`) | `cad3ddc5f274b8213c9956e2611a415252fd3619ca6700dc8ed396ed23acf6b0` |
| Chen-Yu Tsai (`wens`) | `eeb049594eb3a83e50bfb6782e7fdf9e96fbd5c2954a0bbb0931cd55321d0bcf` |

The build verifies the upstream PKCS#7 content signature using OpenSSL and
only these certificates. Certificates carried inside an input signature
cannot add trust. The exact verified database is embedded in the kernel;
runtime PKCS#7 verification and loading arbitrary rootfs updates are not
implemented. No private key or NARF re-signing is involved.

To build with another upstream-signed version, set `NARF_WIRELESS_REGDB` to
the absolute directory containing `regulatory.db` and `regulatory.db.p7s`.
The existing trust roots still apply. Missing or rejected input fails the
build, including development builds that allow unsigned vendor firmware.
Rebuild to incorporate a database update. Updating a trust root requires a
reviewed source change; never extract a new trusted root from the supplied
signature.
