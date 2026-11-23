//! Fuzz target: ACPI table body parsers.
//!
//! Surface: the `__test_parse_*_body` shims in `narf_acpi` — the
//! per-table decoders for the ~45 tables the kernel parses from
//! firmware (PPTT, IORT, DMAR, IVRS, HEST, SPCR, ...). Each shim
//! takes the table bytes directly (full SDT: 36-byte header +
//! body, exactly as the `__test_parse_*_body` unit tests feed
//! them), so the fuzzer exercises the real decoders without a
//! firmware chain. The RSDP/XSDT chain walkers (`parse_rsdp`,
//! `parse_srat`, ...) are NOT in scope here: they dereference
//! physical addresses through the direct map, which has no host
//! meaning. SRAT is the one exception — its entries are decoded
//! by `__parse_srat_body_for_test` over a plain entry stream
//! (bytes after the 36-byte header + 12 reserved bytes, i.e.
//! offset 48), so it is fed `&data[48..]`.
//!
//! The input's first four bytes select the table by signature;
//! unknown signatures exercise nothing (there is no generic
//! byte-slice SDT-header parser to fall back to). Every body
//! parser resets its fixed-size table to empty on entry, so no
//! state accumulates across inputs.
//!
//! Invariant: never panic, never read out of bounds, for any byte
//! string. A short / wrong-length table is simply rejected by the
//! length checks at each decoder's head.

#![no_main]

use libfuzzer_sys::fuzz_target;
use narf_fuzz::host;

/// Cap the table size: the largest real tables (NFIT, HEST) are
/// tens of KiB; parsing risk lives in entry arithmetic, not bulk.
const MAX_TABLE: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 || data.len() > MAX_TABLE {
        return;
    }
    host::init();

    match &data[..4] {
        b"ECDT" => narf_acpi::__test_parse_ecdt_body(data),
        b"SRAT" => {
            // SAFETY: test-only entry point over a synthetic entry
            // stream; the hook itself only reads the slice.
            if data.len() > 48 {
                let _ = unsafe { narf_acpi::__parse_srat_body_for_test(&data[48..]) };
            }
        }
        b"PPTT" => {
            let _ = narf_acpi::__test_parse_pptt_body(data);
        }
        b"IORT" => {
            let _ = narf_acpi::__test_parse_iort_body(data);
        }
        b"DMAR" => {
            let _ = narf_acpi::__test_parse_dmar_body(data);
        }
        b"IVRS" => {
            let _ = narf_acpi::__test_parse_ivrs_body(data);
        }
        b"SPCR" => narf_acpi::__test_parse_spcr_body(data),
        b"HEST" => {
            let _ = narf_acpi::__test_parse_hest_body(data);
        }
        b"PCCT" => {
            let _ = narf_acpi::__test_parse_pcct_body(data);
        }
        b"SLIT" => {
            let _ = narf_acpi::__test_parse_slit_body(data);
        }
        b"CEDT" => {
            let _ = narf_acpi::__test_parse_cedt_body(data);
        }
        b"BERT" => narf_acpi::__test_parse_bert_body(data),
        b"AEST" => {
            let _ = narf_acpi::__test_parse_aest_body(data);
        }
        b"WDDT" => narf_acpi::__test_parse_wddt_body(data),
        b"LPIT" => {
            let _ = narf_acpi::__test_parse_lpit_body(data);
        }
        b"NFIT" => {
            let _ = narf_acpi::__test_parse_nfit_body(data);
        }
        b"ERST" => {
            let _ = narf_acpi::__test_parse_erst_body(data);
        }
        b"EINJ" => {
            let _ = narf_acpi::__test_parse_einj_body(data);
        }
        b"TPM2" => narf_acpi::__test_parse_tpm2_body(data),
        b"BGRT" => narf_acpi::__test_parse_bgrt_body(data),
        b"DBG2" => {
            let _ = narf_acpi::__test_parse_dbg2_body(data);
        }
        b"WSMT" => narf_acpi::__test_parse_wsmt_body(data),
        b"WAET" => narf_acpi::__test_parse_waet_body(data),
        b"HPET" => narf_acpi::__test_parse_hpet_body(data),
        b"FACS" => narf_acpi::__test_parse_facs_body(data),
        b"PRMT" => {
            let _ = narf_acpi::__test_parse_prmt_body(data);
        }
        b"CCEL" => narf_acpi::__test_parse_ccel_body(data),
        b"MPST" => {
            let _ = narf_acpi::__test_parse_mpst_body(data);
        }
        b"SDEV" => {
            let _ = narf_acpi::__test_parse_sdev_body(data);
        }
        b"SBST" => narf_acpi::__test_parse_sbst_body(data),
        b"RAS2" => {
            let _ = narf_acpi::__test_parse_ras2_body(data);
        }
        b"NHLT" => {
            let _ = narf_acpi::__test_parse_nhlt_body(data);
        }
        b"IBFT" => {
            let _ = narf_acpi::__test_parse_ibft_body(data);
        }
        b"CSRT" => {
            let _ = narf_acpi::__test_parse_csrt_body(data);
        }
        b"AGDI" => narf_acpi::__test_parse_agdi_body(data),
        b"BOOT" => narf_acpi::__test_parse_boot_body(data),
        b"DBGP" => narf_acpi::__test_parse_dbgp_body(data),
        b"WPBT" => narf_acpi::__test_parse_wpbt_body(data),
        b"MSCT" => {
            let _ = narf_acpi::__test_parse_msct_body(data);
        }
        b"XENV" => narf_acpi::__test_parse_xenv_body(data),
        b"TCPA" => narf_acpi::__test_parse_tcpa_body(data),
        b"MCHI" => narf_acpi::__test_parse_mchi_body(data),
        b"PHAT" => {
            let _ = narf_acpi::__test_parse_phat_body(data);
        }
        b"STAO" => narf_acpi::__test_parse_stao_body(data),
        b"UEFI" => narf_acpi::__test_parse_uefi_body(data),
        _ => {}
    }
});
