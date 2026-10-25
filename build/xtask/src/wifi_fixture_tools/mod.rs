//! Native encoding of explicit deployment board facts. No firmware extraction.
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

mod board;
#[cfg(test)]
mod tests;

#[derive(clap::Args)]
pub(crate) struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(clap::Subcommand)]
enum Command {
    /// Encode explicit deployment JSON as unsigned NBSP v1 (sign separately).
    BoardManifest(board::Args),
}
pub(crate) fn run(args: Args) -> Result<()> {
    match args.command {
        Command::BoardManifest(args) => board::run(args),
    }
}

fn safe_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|x| x.is_ascii_alphanumeric() || b"/_.-".contains(&x))
            && Path::new(name)
                .components()
                .all(|x| matches!(x, Component::Normal(_)))
            && name
                .split('/')
                .all(|x| !x.is_empty() && x != "." && x != ".."),
        "invalid relative asset key"
    );
    Ok(())
}
fn u32le(raw: &[u8], at: usize) -> Result<u32> {
    let bytes = raw
        .get(at..at.checked_add(4).context("extent overflow")?)
        .context("truncated envelope field")?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}
