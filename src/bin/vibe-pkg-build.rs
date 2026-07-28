// SPDX-License-Identifier: MIT

use ed25519_dalek::{Signer, SigningKey};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use vibe_pkg::{MAGIC, MAX_PACKAGE_LENGTH, SIGNATURE_LENGTH, parse, valid_name, valid_version};

fn main() {
    if let Err(error) = run() {
        eprintln!("vibe-pkg-build: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let _program = args.next();
    match args.next().as_deref() {
        Some(command) if command == "keygen" => {
            let private = args.next().ok_or_else(usage)?;
            let public = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            keygen(Path::new(&private), Path::new(&public))
        }
        Some(command) if command == "pack" => {
            let private = args.next().ok_or_else(usage)?;
            let name = args.next().ok_or_else(usage)?;
            let version = args.next().ok_or_else(usage)?;
            let payload = args.next().ok_or_else(usage)?;
            let output = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            pack(
                Path::new(&private),
                name.to_str().ok_or("name is not UTF-8")?,
                version.to_str().ok_or("version is not UTF-8")?,
                Path::new(&payload),
                Path::new(&output),
            )
        }
        Some(command) if command == "verify" => {
            let public = args.next().ok_or_else(usage)?;
            let package = args.next().ok_or_else(usage)?;
            let payload = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            verify(Path::new(&public), Path::new(&package), Path::new(&payload))
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: vibe-pkg-build <keygen PRIVATE PUBLIC|pack PRIVATE NAME VERSION PAYLOAD OUTPUT|verify PUBLIC PACKAGE PAYLOAD>".to_owned()
}

fn keygen(private: &Path, public: &Path) -> Result<(), String> {
    let mut secret = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut secret))
        .map_err(|error| format!("random key: {error}"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    write_new(private, &hex(&secret), 0o600)?;
    write_new(public, &hex(&signing_key.verifying_key().to_bytes()), 0o644)
}

fn pack(
    private: &Path,
    name: &str,
    version: &str,
    payload: &Path,
    output: &Path,
) -> Result<(), String> {
    if !valid_name(name.as_bytes()) {
        return Err("invalid package name".to_owned());
    }
    if !valid_version(version.as_bytes()) {
        return Err("invalid package version".to_owned());
    }
    let secret = decode_key(&fs::read_to_string(private).map_err(|error| error.to_string())?)?;
    let signing_key = SigningKey::from_bytes(&secret);
    let payload = fs::read(payload).map_err(|error| error.to_string())?;
    let manifest = format!("name={name}\nversion={version}\npath=/bin/{name}\n");

    let total = 16_usize
        .checked_add(manifest.len())
        .and_then(|length| length.checked_add(payload.len()))
        .and_then(|length| length.checked_add(SIGNATURE_LENGTH))
        .ok_or("package is too large")?;
    if total > MAX_PACKAGE_LENGTH {
        return Err(format!("package exceeds {MAX_PACKAGE_LENGTH} bytes"));
    }

    let mut package = Vec::with_capacity(total);
    package.extend_from_slice(MAGIC);
    package.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    package.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    package.extend_from_slice(manifest.as_bytes());
    package.extend_from_slice(&payload);
    package.extend_from_slice(&signing_key.sign(&package).to_bytes());
    write_atomic(output, &package)
}

fn verify(public: &Path, package: &Path, payload: &Path) -> Result<(), String> {
    let public = decode_key(&fs::read_to_string(public).map_err(|error| error.to_string())?)?;
    let bytes = fs::read(package).map_err(|error| error.to_string())?;
    let package = parse(&bytes, &public).map_err(|error| format!("invalid package: {error:?}"))?;
    let expected = fs::read(payload).map_err(|error| error.to_string())?;
    if package.payload != expected {
        return Err("signed payload differs from the supplied build".to_owned());
    }
    println!(
        "verified {} {}",
        std::str::from_utf8(package.name).map_err(|_| "invalid package name")?,
        std::str::from_utf8(package.version).map_err(|_| "invalid package version")?
    );
    Ok(())
}

fn decode_key(value: &str) -> Result<[u8; 32], String> {
    let value = value.trim();
    if value.len() != 64 {
        return Err("private key must contain 64 hexadecimal characters".to_owned());
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(bytes)
}

fn nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("key contains non-hexadecimal characters".to_owned()),
    }
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = Vec::with_capacity(bytes.len() * 2 + 1);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize]);
        output.push(DIGITS[(byte & 15) as usize]);
    }
    output.push(b'\n');
    output
}

fn write_new(path: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn write_atomic(path: &Path, content: &[u8]) -> Result<(), String> {
    let temporary = temporary_path(path);
    let _ = fs::remove_file(&temporary);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(format!("{}: {error}", path.display()));
    }
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(".tmp");
    value.into()
}
