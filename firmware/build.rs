use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const REGDB: &[u8] = include_bytes!("regdb/regulatory.db");
const REGDB_SIGNATURE: &[u8] = include_bytes!("regdb/regulatory.db.p7s");
const REGDB_CERTIFICATES: &[u8] = include_bytes!("regdb/trusted-certs.pem");

fn bounded_read(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(maximum + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!("{} is empty or too large", path.display()));
    }
    Ok(bytes)
}

/// Verify a snapshot using only Linux's two shipped regdb certificates.
/// `-nointern` excludes certificates supplied by the untrusted signature.
/// `-noverify` skips CA-chain validation, not the content signature: these
/// exact public certificates are trust anchors, as in Linux's regdb keyring.
/// The verified bytes themselves are embedded; no source file is reread.
fn verify_regdb(bytes: &[u8], signature: &[u8], output: &Path) -> Result<(), String> {
    if bytes.len() < 12
        || bytes.len() > 1024 * 1024
        || bytes[..8] != *b"RGDB\0\0\0\x14"
        || signature.is_empty()
        || signature.len() > 64 * 1024
    {
        return Err("invalid Linux regulatory database/signature envelope".into());
    }
    let database_path = output.join("linux-regulatory.db");
    let signature_path = output.join("linux-regulatory.db.p7s");
    let certificates_path = output.join("linux-regulatory-certs.pem");
    fs::write(&database_path, bytes).map_err(|error| error.to_string())?;
    fs::write(&signature_path, signature).map_err(|error| error.to_string())?;
    fs::write(&certificates_path, REGDB_CERTIFICATES).map_err(|error| error.to_string())?;
    let verified = Command::new("openssl")
        .args(["cms", "-verify", "-binary", "-inform", "DER", "-in"])
        .arg(&signature_path)
        .arg("-content")
        .arg(&database_path)
        .args(["-nointern", "-noverify", "-certfile"])
        .arg(&certificates_path)
        .stdout(Stdio::null())
        .output()
        .map_err(|error| format!("OpenSSL is required to verify Linux wireless-regdb: {error}"))?;
    if !verified.status.success() {
        return Err(format!(
            "Linux wireless-regdb signature rejected: {}",
            String::from_utf8_lossy(&verified.stderr).trim()
        ));
    }
    Ok(())
}

fn embed_linux_regdb(output: &Path) -> Result<(), String> {
    println!("cargo:rerun-if-env-changed=NARF_WIRELESS_REGDB");
    for path in ["regulatory.db", "regulatory.db.p7s", "trusted-certs.pem"] {
        println!("cargo:rerun-if-changed=regdb/{path}");
    }
    match env::var_os("NARF_WIRELESS_REGDB") {
        Some(directory) => {
            let directory = PathBuf::from(directory);
            if !directory.is_absolute() {
                return Err("NARF_WIRELESS_REGDB must be an absolute directory".into());
            }
            let database_path = directory.join("regulatory.db");
            let signature_path = directory.join("regulatory.db.p7s");
            println!("cargo:rerun-if-changed={}", database_path.display());
            println!("cargo:rerun-if-changed={}", signature_path.display());
            let bytes = bounded_read(&database_path, 1024 * 1024)?;
            let signature = bounded_read(&signature_path, 64 * 1024)?;
            verify_regdb(&bytes, &signature, output)
        }
        None => verify_regdb(REGDB, REGDB_SIGNATURE, output),
    }
}

fn parse_keys(text: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut keys = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.len() != 64 || !line.is_ascii() {
            return Err(format!(
                "line {}: expected a 64-digit public key",
                line_number + 1
            ));
        }
        let mut key = [0; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&line[2 * i..2 * i + 2], 16)
                .map_err(|_| format!("line {}: invalid hex public key", line_number + 1))?;
        }
        if key == [0; 32] {
            return Err(format!("line {}: zero public key", line_number + 1));
        }
        if !keys.contains(&key) {
            keys.push(key);
        }
        if keys.len() > 32 {
            return Err("at most 32 trusted firmware public keys are allowed".into());
        }
    }
    if keys.is_empty() {
        return Err("configured trusted-key file contains no keys".into());
    }
    Ok(keys)
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=NARF_FIRMWARE_TRUSTED_KEYS");
    let keys = match env::var_os("NARF_FIRMWARE_TRUSTED_KEYS") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(
                path.is_absolute(),
                "NARF_FIRMWARE_TRUSTED_KEYS must be an absolute path"
            );
            println!("cargo:rerun-if-changed={}", path.display());
            let text = fs::read_to_string(&path).expect("read trusted firmware public keys");
            parse_keys(&text).expect("parse trusted firmware public keys")
        }
        None => Vec::new(),
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(
        output.join("trusted_keys.rs"),
        format!("const BUILD_TRUSTED_KEYS: &[[u8; 32]] = &{keys:?};\n"),
    )
    .expect("write trusted firmware public keys");
    embed_linux_regdb(&output).expect("authenticate Linux wireless regulatory database");
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = env::temp_dir().join(format!(
                "narf-regdb-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn linux_signature_authenticates_exact_embedded_bytes() {
        let directory = Directory::new();
        verify_regdb(REGDB, REGDB_SIGNATURE, &directory.0).unwrap();
        assert_eq!(
            fs::read(directory.0.join("linux-regulatory.db")).unwrap(),
            REGDB
        );
        let mut modified = REGDB.to_vec();
        *modified.last_mut().unwrap() ^= 1;
        assert!(verify_regdb(&modified, REGDB_SIGNATURE, &directory.0).is_err());
        let mut signature = REGDB_SIGNATURE.to_vec();
        *signature.last_mut().unwrap() ^= 1;
        assert!(verify_regdb(REGDB, &signature, &directory.0).is_err());
        assert!(verify_regdb(REGDB, &[], &directory.0).is_err());
    }

    #[test]
    fn certificates_inside_a_signature_cannot_add_trust() {
        let directory = Directory::new();
        let key = directory.0.join("untrusted-key.pem");
        let certificate = directory.0.join("untrusted-cert.pem");
        let payload = directory.0.join("payload.db");
        let signature = directory.0.join("untrusted.p7s");
        fs::write(&payload, REGDB).unwrap();
        // Ephemeral test-only signer: even its included self-signed
        // certificate must not authenticate an otherwise genuine database.
        let generated = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=untrusted-regdb-test",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .output()
            .unwrap();
        assert!(generated.status.success());
        let signed = Command::new("openssl")
            .args(["cms", "-sign", "-binary", "-noattr", "-md", "sha256", "-in"])
            .arg(&payload)
            .arg("-signer")
            .arg(&certificate)
            .arg("-inkey")
            .arg(&key)
            .args(["-outform", "DER", "-out"])
            .arg(&signature)
            .output()
            .unwrap();
        assert!(signed.status.success());
        assert!(verify_regdb(REGDB, &fs::read(signature).unwrap(), &directory.0).is_err());
    }

    #[test]
    fn explicit_keys_comments_and_duplicates() {
        let key = "12".repeat(32);
        assert_eq!(
            parse_keys(&format!("# deployment\n{key}\n{key} # duplicate\n")).unwrap(),
            vec![[0x12; 32]]
        );
    }

    #[test]
    fn malformed_configuration_fails_closed() {
        for value in [
            String::new(),
            "# comment".into(),
            "00".repeat(32),
            "0g".repeat(32),
            "f".repeat(63),
            "é".repeat(32),
        ] {
            assert!(parse_keys(&value).is_err());
        }
        let too_many = (1..=33).map(|n| format!("{n:064x}\n")).collect::<String>();
        assert!(parse_keys(&too_many).is_err());
    }
}
