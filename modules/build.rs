use std::{env, fs, path::PathBuf};

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
            return Err("at most 32 trusted module public keys are allowed".into());
        }
    }
    if keys.is_empty() {
        return Err("configured trusted-key file contains no keys".into());
    }
    Ok(keys)
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=NARF_MODULE_TRUSTED_KEYS");
    let keys = match env::var_os("NARF_MODULE_TRUSTED_KEYS") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(
                path.is_absolute(),
                "NARF_MODULE_TRUSTED_KEYS must be an absolute path"
            );
            println!("cargo:rerun-if-changed={}", path.display());
            let text = fs::read_to_string(&path).expect("read trusted module public keys");
            parse_keys(&text).expect("parse trusted module public keys")
        }
        None => Vec::new(),
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(
        output.join("trusted_keys.rs"),
        format!("const BUILD_TRUSTED_KEYS: &[[u8; 32]] = &{keys:?};\n"),
    )
    .expect("write trusted module public keys");
}

#[cfg(test)]
mod tests {
    use super::*;

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
