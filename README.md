# vibe-pkg

`vibe-pkg` is the signed, libc-free package manager for vibeOS.

## Package format

A v1 package contains a fixed header, a strict manifest, one executable
payload, and an Ed25519 signature over all preceding bytes. The manifest
identifies a package name, numeric dotted version, and `/bin/<name>` target.
Packages are capped at 256 KiB so verification remains allocator-free.

## Guest commands

```text
vibe-pkg install PACKAGE
vibe-pkg upgrade PACKAGE
vibe-pkg remove NAME
vibe-pkg list
```

Install and upgrade stage the executable in `/tmp`, set mode `0755`, call
`fsync`, and atomically rename it into `/bin`. Package records live in
`/var/lib/vibe-pkg`.

## Build packages

The repository includes a host-side builder:

```sh
make builder
target/release/vibe-pkg-build keygen private.key public.key
target/release/vibe-pkg-build pack private.key vibe-hello 0.1.0 ./vibe-hello ./vibe-hello.vpkg
target/release/vibe-pkg-build verify public.key ./vibe-hello.vpkg ./vibe-hello
```

Keep `private.key` outside source control. The corresponding public key must
be compiled into `vibe-pkg` as its trust root.

The current vibeOS development trust root is
`78d704086984ff6884080a246c6130312d2e6382ffbf9fa84eb44cb619ca7df3`.

## Build and test

```sh
make guest
make check
```

Rust 1.94.0 is selected by `rust-toolchain.toml`. The guest binary is
statically linked and does not use libc.

## Current scope

The v1 format intentionally installs one `/bin` executable per package.
Dependencies, remote repositories, multiple files, and key rotation are not
implemented yet.

## License

MIT
