use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct Temp(pub PathBuf);
impl Temp {
    pub(super) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "narf-wifi-board-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cli_only_encodes_explicit_board_records() {
    use clap::Parser;
    for mode in ["check", "write", "extract"] {
        assert!(crate::Cli::try_parse_from(["xtask", "wifi-fixtures", mode]).is_err());
    }
    assert!(crate::Cli::try_parse_from([
        "xtask",
        "wifi-fixtures",
        "board-manifest",
        "--output",
        "out.bin"
    ])
    .is_err());
    assert!(crate::Cli::try_parse_from([
        "xtask",
        "wifi-fixtures",
        "board-manifest",
        "--input",
        "records.json",
        "--output",
        "out.bin"
    ])
    .is_ok());
}
