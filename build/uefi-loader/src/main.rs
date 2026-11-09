// SPDX-License-Identifier: GPL-2.0-or-later
#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

#[cfg(any(target_arch = "aarch64", test))]
mod aarch64;
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
mod x86_64;
