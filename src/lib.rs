// SPDX-License-Identifier: MIT

#![no_std]

use core::convert::TryInto;
use ed25519_dalek::{Signature, VerifyingKey};

pub const MAGIC: &[u8; 8] = b"VPKG0001";
pub const HEADER_LENGTH: usize = 16;
pub const SIGNATURE_LENGTH: usize = 64;
pub const MAX_PACKAGE_LENGTH: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageError {
    Format,
    Signature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Package<'a> {
    pub name: &'a [u8],
    pub version: &'a [u8],
    pub path: &'a [u8],
    pub payload: &'a [u8],
}

pub fn parse<'a>(bytes: &'a [u8], trusted_key: &[u8; 32]) -> Result<Package<'a>, PackageError> {
    if bytes.len() < HEADER_LENGTH + SIGNATURE_LENGTH || &bytes[..8] != MAGIC {
        return Err(PackageError::Format);
    }

    let manifest_length =
        u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| PackageError::Format)?) as usize;
    let payload_length =
        u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| PackageError::Format)?) as usize;
    let signature_start = HEADER_LENGTH
        .checked_add(manifest_length)
        .and_then(|length| length.checked_add(payload_length))
        .ok_or(PackageError::Format)?;
    if signature_start
        .checked_add(SIGNATURE_LENGTH)
        .filter(|length| *length == bytes.len())
        .is_none()
    {
        return Err(PackageError::Format);
    }

    let signature_bytes: &[u8; SIGNATURE_LENGTH] = bytes[signature_start..]
        .try_into()
        .map_err(|_| PackageError::Format)?;
    let signature = Signature::from_bytes(signature_bytes);
    let key = VerifyingKey::from_bytes(trusted_key).map_err(|_| PackageError::Signature)?;
    key.verify_strict(&bytes[..signature_start], &signature)
        .map_err(|_| PackageError::Signature)?;

    let manifest_end = HEADER_LENGTH + manifest_length;
    let manifest = &bytes[HEADER_LENGTH..manifest_end];
    let mut lines = manifest.split(|byte| *byte == b'\n');
    let name = field(lines.next(), b"name=")?;
    let version = field(lines.next(), b"version=")?;
    let path = field(lines.next(), b"path=")?;
    if lines.next() != Some(b"") || lines.next().is_some() {
        return Err(PackageError::Format);
    }
    if !valid_name(name) || !valid_version(version) || !valid_path(name, path) {
        return Err(PackageError::Format);
    }

    Ok(Package {
        name,
        version,
        path,
        payload: &bytes[manifest_end..signature_start],
    })
}

fn field<'a>(line: Option<&'a [u8]>, prefix: &[u8]) -> Result<&'a [u8], PackageError> {
    line.and_then(|line| line.strip_prefix(prefix))
        .ok_or(PackageError::Format)
}

pub fn valid_name(name: &[u8]) -> bool {
    (1..=32).contains(&name.len())
        && name[0].is_ascii_lowercase()
        && name
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

pub fn valid_version(version: &[u8]) -> bool {
    (1..=32).contains(&version.len())
        && version
            .split(|byte| *byte == b'.')
            .all(|part| !part.is_empty() && part.iter().all(u8::is_ascii_digit))
}

fn valid_path(name: &[u8], path: &[u8]) -> bool {
    path.strip_prefix(b"/bin/") == Some(name)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{HEADER_LENGTH, MAGIC, PackageError, parse};
    use ed25519_dalek::{Signer, SigningKey};
    use std::vec::Vec;

    fn package(payload: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let manifest = b"name=vibe-hello\nversion=0.1.0\npath=/bin/vibe-hello\n";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(manifest);
        bytes.extend_from_slice(payload);
        let signature = signing_key.sign(&bytes);
        bytes.extend_from_slice(&signature.to_bytes());
        assert!(bytes.len() > HEADER_LENGTH);
        (bytes, signing_key.verifying_key().to_bytes())
    }

    #[test]
    fn parses_a_signed_package() {
        let (bytes, key) = package(b"hello");
        let package = parse(&bytes, &key).unwrap();
        assert_eq!(package.name, b"vibe-hello");
        assert_eq!(package.version, b"0.1.0");
        assert_eq!(package.path, b"/bin/vibe-hello");
        assert_eq!(package.payload, b"hello");
    }

    #[test]
    fn rejects_payload_tampering() {
        let (mut bytes, key) = package(b"hello");
        bytes[HEADER_LENGTH + 55] ^= 1;
        assert_eq!(parse(&bytes, &key), Err(PackageError::Signature));
    }
}
