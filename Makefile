GUEST_TARGET := x86_64-unknown-linux-gnu
CARGO ?= cargo
GUEST_RUSTFLAGS := -C link-arg=-fuse-ld=lld -C link-arg=-nostdlib \
	-C link-arg=-static -C link-arg=-no-pie \
	-C default-linker-libraries=no -C relocation-model=static
GUEST := target/$(GUEST_TARGET)/release/vibe-pkg

.PHONY: all guest builder check clean

all: guest builder

guest:
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang \
		RUSTFLAGS="$(GUEST_RUSTFLAGS)" \
		$(CARGO) build --release --target $(GUEST_TARGET) --bin vibe-pkg

builder:
	$(CARGO) build --release --features builder --bin vibe-pkg-build

check:
	$(CARGO) fmt -- --check
	$(CARGO) clippy --release --lib --tests -- -D warnings
	$(CARGO) clippy --release --features builder --bin vibe-pkg-build -- -D warnings
	$(CARGO) test
	$(MAKE) guest
	! readelf -l $(GUEST) | grep -q INTERP
	! readelf -d $(GUEST) | grep -q NEEDED

clean:
	$(CARGO) clean
