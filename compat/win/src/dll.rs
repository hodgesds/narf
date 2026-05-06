//! DLL loading — design surface only.
//!
//! M0 ships built-in thunk sets (`thunks::kernel32`) that the loader
//! resolves imports against directly. That works for hello-world
//! console PEs but fails the moment a binary imports its own engine
//! DLLs — every non-trivial Win32 game ships its own `.dll` files.
//!
//! M1 closes the gap. This module documents the M1 surface so the
//! M0 loader (`process::load_pe`) can be retargeted without
//! reshaping its callers.
//!
//! ## Model
//!
//! A `WinModule` is one loaded PE32+ image — either the main
//! executable (`IMAGE_FILE_DLL` clear) or a DLL (`IMAGE_FILE_DLL`
//! set). A `WinProcess` owns one main module + zero-or-more
//! dependent modules; the `ModuleTable` indexes them by lowercase
//! ASCII filename for import resolution.
//!
//! ```ignore
//! pub struct WinModule {
//!     pub name:        String,           // lowercase, e.g. "kernel32.dll"
//!     pub base:        VirtAddr,         // chosen image base
//!     pub size:        u32,              // SizeOfImage
//!     pub exports:     ExportTable,      // RVA-keyed export map
//!     pub is_dll:      bool,
//!     pub entry:       Option<VirtAddr>, // DllMain (DLL) or _start (exe)
//! }
//!
//! pub struct ModuleTable {
//!     by_name: BTreeMap<String, WinModule>,
//! }
//! ```
//!
//! ## Recursive load
//!
//! Loading the main exe walks its import directory; for every
//! `(module, symbol)` we don't already have:
//!
//! 1. Look up `module` in the host filesystem (`filesystem/` cap
//!    rules apply; the spawner grants the WinProcess a directory
//!    cap to its system32-equivalent at process-create time).
//! 2. Parse + load the DLL (same `load_pe` pipeline, re-entered).
//! 3. Add it to the `ModuleTable`.
//! 4. Continue resolving imports against the now-larger table.
//!
//! ## DllMain calling convention
//!
//! ```ignore
//! BOOL WINAPI DllMain(
//!   HINSTANCE hinstDLL,        // module base
//!   DWORD     fdwReason,       // DLL_PROCESS_ATTACH = 1, etc.
//!   LPVOID    lpvReserved,     // NULL for dynamic load
//! );
//! ```
//!
//! Called once on initial load with `DLL_PROCESS_ATTACH`. Per-thread
//! `DLL_THREAD_ATTACH` calls land with the M2 thread surface — M1
//! ships single-threaded WinProcesses and ignores per-thread DLL
//! notifications, matching what every M0/M1-class binary expects.
//!
//! ## Forwarders
//!
//! An export entry whose RVA points inside the export directory
//! itself is a *forwarder* — its target is a `module.symbol` string
//! the loader chases through the `ModuleTable`. Forwarders are how
//! `kernel32!HeapAlloc` becomes `ntdll!RtlAllocateHeap` in modern
//! Windows. M1 implements them.
//!
//! ## Bound imports
//!
//! Skipped entirely. Bound imports are an optimisation that bakes a
//! specific module's RVAs into the importer's IAT at link time;
//! they break the moment we relocate the export's host module to a
//! different base, which we always do (different `image_base` per
//! load). Honour the `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT` directory
//! existing but never trust its contents — fall back to the
//! ordinary import directory walk we already have.
//!
//! ## Deferred (lazy) imports
//!
//! Skipped for M1. Visual C++ ships `__delayLoadHelper2` for
//! deferred-bound imports; a real implementation needs an
//! `Import_DescriptorEx`-walker plus a per-DLL lazy-load trampoline
//! distinct from the M0.5 syscall trampoline. M2.

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::string::String;

use narf_memory::VirtAddr;

/// A loaded module — main executable or DLL.
#[derive(Debug)]
pub struct WinModule {
    pub name: String,
    pub base: VirtAddr,
    pub size: u32,
    pub is_dll: bool,
    pub entry: Option<VirtAddr>,
}

/// Per-process module index. Imports resolve against this table.
#[derive(Debug, Default)]
pub struct ModuleTable {
    by_name: BTreeMap<String, WinModule>,
}

impl ModuleTable {
    pub fn new() -> Self {
        Self {
            by_name: BTreeMap::new(),
        }
    }

    /// Look up a loaded module by its (lowercase ASCII) filename.
    pub fn get(&self, name: &str) -> Option<&WinModule> {
        // Imports may name `KERNEL32.DLL` or `kernel32.dll` —
        // canonicalise on read since insertion already lowercases.
        // (We allocate a temporary lowercase copy; the table is
        // small enough that the cost doesn't matter.)
        let key: String = name.chars().map(|c| c.to_ascii_lowercase()).collect();
        self.by_name.get(&key)
    }

    /// Insert a freshly-loaded module. The name is lowercased on
    /// the way in.
    pub fn insert(&mut self, mut m: WinModule) {
        m.name = m.name.chars().map(|c| c.to_ascii_lowercase()).collect();
        self.by_name.insert(m.name.clone(), m);
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn lookup_canonicalises_case() {
        let mut t = ModuleTable::new();
        t.insert(WinModule {
            name: "Kernel32.DLL".into(),
            base: VirtAddr::new(0x1000_0000),
            size: 0x100,
            is_dll: true,
            entry: None,
        });
        assert_eq!(t.len(), 1);
        // Inserts lowercase the key.
        assert!(t.get("kernel32.dll").is_some());
        // Lookups also case-fold.
        assert!(t.get("KERNEL32.DLL").is_some());
        assert!(t.get("Kernel32.Dll").is_some());
        assert!(t.get("ntdll.dll").is_none());
    }
}
