// SPDX-License-Identifier: GPL-2.0-or-later

//! `cargo narf` — the single NARF frontend.
//!
//! The dev commands live in [`dev`] (the former `cargo narf` orchestrator,
//! nested under `build` / `test` / `run` / `smoke` / `bench` /
//! `firmware` / `ci` / `disk` groups); the native packaging commands
//! live in [`pkg`] under the `pkg` group. `cargo narf` keeps working
//! as a deprecated shim — see `dev::normalized_args`.

mod dev;
mod pkg;

use std::process::ExitCode;

fn main() -> ExitCode {
    match dev::main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cargo narf: {error:#}");
            ExitCode::FAILURE
        }
    }
}
