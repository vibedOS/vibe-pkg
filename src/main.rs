// SPDX-License-Identifier: MIT

#![no_main]
#![no_std]

use core::ffi::CStr;
use core::panic::PanicInfo;
use vibe_net::{Error as NetError, http_get};
use vibe_pkg::{MAX_PACKAGE_LENGTH, Package, parse, valid_name};
use vibe_rt::{
    Args, Env, Errno, Result, close, entry, eprintln, open_directory, open_read, open_write, print,
    read, read_directory, remove_file, rename_file, set_mode, sync_file, write_all,
};

const TRUSTED_KEY: [u8; 32] = [
    0x78, 0xd7, 0x04, 0x08, 0x69, 0x84, 0xff, 0x68, 0x84, 0x08, 0x0a, 0x24, 0x6c, 0x61, 0x30, 0x31,
    0x2d, 0x2e, 0x63, 0x82, 0xff, 0xbf, 0x9f, 0xa8, 0x4e, 0xb4, 0x4c, 0xb6, 0x19, 0xca, 0x7d, 0xf3,
];
const INSTALL_TEMP: &CStr = c"/bin/.vibe-pkg.tmp";
const RECORD_TEMP: &CStr = c"/var/lib/vibe-pkg/.tmp";
const REPOSITORY: &CStr = c"/etc/vibe-pkg/repository";

entry!(main);

fn main(mut args: Args<'_>, _env: Env<'_>) -> i32 {
    let _program = args.next();
    let status = match args.next() {
        Some(b"install" | b"upgrade") => match (args.next(), args.next()) {
            (Some(path), None) => install(path),
            _ => usage(),
        },
        Some(b"remove") => match (args.next(), args.next()) {
            (Some(name), None) => remove(name),
            _ => usage(),
        },
        Some(b"list") if args.next().is_none() => list(),
        _ => usage(),
    };
    if let Err(error) = status {
        eprintln!("vibe-pkg: errno {}", error.0);
        1
    } else {
        0
    }
}

fn usage() -> Result<()> {
    eprintln!("usage: vibe-pkg <install NAME|PACKAGE|upgrade NAME|PACKAGE|remove NAME|list>");
    Err(Errno(22))
}

fn install(argument: &[u8]) -> Result<()> {
    // ponytail: fixed package memory keeps the guest allocator-free; raise the cap when packages outgrow 256 KiB.
    let mut bytes = [0_u8; MAX_PACKAGE_LENGTH];
    let length = if valid_name(argument) {
        download_package(argument, &mut bytes)?
    } else {
        let mut path_storage = [0_u8; 4096];
        let path = c_path(argument, &mut path_storage).ok_or(Errno(36))?;
        read_file(path, &mut bytes)?
    };
    let package = parse(&bytes[..length], &TRUSTED_KEY).map_err(|_| Errno(74))?;
    if valid_name(argument) && package.name != argument {
        return Err(Errno(74));
    }

    let mut target_storage = [0_u8; 64];
    let target = c_path(package.path, &mut target_storage).ok_or(Errno(36))?;
    write_atomic(INSTALL_TEMP, target, package.payload, 0o755, c"/bin")?;

    let mut record_path = [0_u8; 64];
    let record = named_path(b"/var/lib/vibe-pkg/", package.name, &mut record_path)?;
    write_atomic(
        RECORD_TEMP,
        record,
        package.version,
        0o644,
        c"/var/lib/vibe-pkg",
    )?;

    print_package("installed", package);
    Ok(())
}

fn download_package(name: &[u8], bytes: &mut [u8]) -> Result<usize> {
    let mut repository = [0_u8; 512];
    let length = read_file(REPOSITORY, &mut repository)?;
    let repository = trim_ascii(&repository[..length]);
    if repository.is_empty() {
        return Err(Errno(22));
    }

    let mut url = [0_u8; 512];
    let separator = usize::from(!repository.ends_with(b"/"));
    let length = repository
        .len()
        .checked_add(separator)
        .and_then(|length| length.checked_add(name.len()))
        .and_then(|length| length.checked_add(5))
        .filter(|length| *length <= url.len())
        .ok_or(Errno(36))?;
    let mut offset = repository.len();
    url[..offset].copy_from_slice(repository);
    if separator == 1 {
        url[offset] = b'/';
        offset += 1;
    }
    url[offset..offset + name.len()].copy_from_slice(name);
    offset += name.len();
    url[offset..length].copy_from_slice(b".vpkg");

    vibe_rt::print!("fetching ");
    let _ = write_all(1, name);
    vibe_rt::println!();
    http_get(&url[..length], bytes).map_err(net_error)
}

fn remove(name: &[u8]) -> Result<()> {
    if !valid_name(name) {
        return Err(Errno(22));
    }
    let mut binary_path = [0_u8; 64];
    let binary = named_path(b"/bin/", name, &mut binary_path)?;
    let mut record_path = [0_u8; 64];
    let record = named_path(b"/var/lib/vibe-pkg/", name, &mut record_path)?;

    remove_if_present(binary)?;
    remove_if_present(record)?;
    sync_directory(c"/bin")?;
    sync_directory(c"/var/lib/vibe-pkg")?;
    vibe_rt::print!("removed ");
    let _ = write_all(1, name);
    vibe_rt::println!();
    Ok(())
}

fn list() -> Result<()> {
    let directory = open_directory(c"/var/lib/vibe-pkg")?;
    let result = list_directory(directory);
    let _ = close(directory);
    result
}

fn list_directory(directory: i32) -> Result<()> {
    let mut buffer = [0_u8; 4096];
    loop {
        let length = read_directory(directory, &mut buffer)?;
        if length == 0 {
            return Ok(());
        }
        let mut offset = 0;
        while offset < length {
            if length - offset < 20 {
                return Err(Errno(5));
            }
            let record_length =
                u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
            if record_length < 20 || record_length > length - offset {
                return Err(Errno(5));
            }
            let name = &buffer[offset + 19..offset + record_length];
            let name_length = name.iter().position(|byte| *byte == 0).ok_or(Errno(5))?;
            let name = &name[..name_length];
            if name != b"." && name != b".." {
                let _ = write_all(1, name);
                vibe_rt::println!();
            }
            offset += record_length;
        }
    }
}

fn read_file(path: &CStr, bytes: &mut [u8]) -> Result<usize> {
    let file = open_read(path)?;
    let mut length = 0;
    let result = loop {
        if length == bytes.len() {
            let mut extra = [0_u8; 1];
            break if read(file as usize, &mut extra)? == 0 {
                Ok(length)
            } else {
                Err(Errno(27))
            };
        }
        match read(file as usize, &mut bytes[length..])? {
            0 => break Ok(length),
            count => length += count,
        }
    };
    let _ = close(file);
    result
}

fn write_atomic(
    temporary: &CStr,
    target: &CStr,
    content: &[u8],
    mode: u32,
    directory: &CStr,
) -> Result<()> {
    // A single interactive administrator exists today, so one staging path is sufficient.
    let _ = remove_file(temporary);
    let file = open_write(temporary)?;
    let staged = write_all(file as usize, content)
        .and_then(|()| set_mode(file, mode))
        .and_then(|()| sync_file(file));
    let closed = close(file);
    if let Err(error) = staged.and(closed) {
        let _ = remove_file(temporary);
        return Err(error);
    }
    if let Err(error) = rename_file(temporary, target) {
        let _ = remove_file(temporary);
        return Err(error);
    }
    sync_directory(directory)
}

fn sync_directory(path: &CStr) -> Result<()> {
    let directory = open_directory(path)?;
    let result = sync_file(directory);
    let closed = close(directory);
    result.and(closed)
}

fn remove_if_present(path: &CStr) -> Result<()> {
    match remove_file(path) {
        Ok(()) | Err(Errno(2)) => Ok(()),
        Err(error) => Err(error),
    }
}

fn named_path<'a>(prefix: &[u8], name: &[u8], storage: &'a mut [u8]) -> Result<&'a CStr> {
    if prefix.len() + name.len() >= storage.len() {
        return Err(Errno(36));
    }
    storage[..prefix.len()].copy_from_slice(prefix);
    storage[prefix.len()..prefix.len() + name.len()].copy_from_slice(name);
    storage[prefix.len() + name.len()] = 0;
    CStr::from_bytes_with_nul(&storage[..=prefix.len() + name.len()]).map_err(|_| Errno(22))
}

fn c_path<'a>(value: &[u8], storage: &'a mut [u8]) -> Option<&'a CStr> {
    if value.len() >= storage.len() || value.contains(&0) {
        return None;
    }
    storage[..value.len()].copy_from_slice(value);
    storage[value.len()] = 0;
    CStr::from_bytes_with_nul(&storage[..=value.len()]).ok()
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn net_error(error: NetError) -> Errno {
    match error {
        NetError::Io(error) => error,
        NetError::TooLarge => Errno(27),
        NetError::InvalidUrl | NetError::InvalidHost => Errno(22),
        NetError::NameNotFound => Errno(2),
        NetError::DnsResponse | NetError::HttpResponse | NetError::HttpStatus(_) => Errno(74),
    }
}

fn print_package(action: &str, package: Package<'_>) {
    print(format_args!("{action} "), 1);
    let _ = write_all(1, package.name);
    let _ = write_all(1, b" ");
    let _ = write_all(1, package.version);
    vibe_rt::println!();
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    eprintln!("vibe-pkg panic: {info}");
    vibe_rt::exit(101)
}
