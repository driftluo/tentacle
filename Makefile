MOLC    := moleculec
MOLC_VERSION := 0.7.0

MOL_FILES := \
  tentacle/src/protocol_select/protocol_select.mol \
  secio/src/handshake/handshake.mol \

MOL_RUST_FILES := $(patsubst %.mol,%_mol.rs,${MOL_FILES})

Change_Work_Path := cd tentacle

GRCOV_EXCL_START = ^\s*(((log)::)?(trace|debug|info|warn|error)|(debug_)?assert(_eq|_ne|_error_eq))!\($$
GRCOV_EXCL_STOP  = ^\s*\)(;)?$$
GRCOV_EXCL_LINE = \s*(((log)::)?(trace|debug|info|warn|error)|(debug_)?assert(_eq|_ne|_error_eq))!\(.*\)(;)?$$

fmt:
	cargo fmt --all -- --check

clippy:
	$(Change_Work_Path) && RUSTFLAGS='-W warnings' cargo clippy --all --tests --features ws,unstable,tls -- -D clippy::let_underscore_must_use

test:
	$(Change_Work_Path) && RUSTFLAGS='-W warnings' RUST_BACKTRACE=full cargo test --all --features ws,unstable,tls,upnp

fuzz:
	cargo +nightly fuzz run secio_crypto_decrypt_cipher -- -max_total_time=60
	cargo +nightly fuzz run secio_crypto_encrypt_cipher -- -max_total_time=60
	cargo +nightly fuzz run yamux_frame_codec           -- -max_total_time=60

build:
	$(Change_Work_Path) && RUSTFLAGS='-W warnings' cargo build --all --features ws
	$(Change_Work_Path) && RUSTFLAGS='-W warnings' cargo build --all --features tls
	$(Change_Work_Path) && RUSTFLAGS='-W warnings' cargo build --all --features ws,unstable

examples:
	$(Change_Work_Path) && cargo build --examples --all --features unstable

features-check:
	$(Change_Work_Path) && cargo build --features tls
	$(Change_Work_Path) && cargo build --features parking_lot
	$(Change_Work_Path) && cargo build --features unstable
	$(Change_Work_Path) && cargo build --features tokio-runtime,generic-timer,unstable --no-default-features
	$(Change_Work_Path) && cargo build --features async-runtime,generic-timer,unstable --no-default-features
	$(Change_Work_Path) && cargo build --features async-runtime,async-timer,unstable --no-default-features
	# required wasm32-unknown-unknown target
	$(Change_Work_Path) && cargo build --features wasm-timer,unstable --no-default-features --target=wasm32-unknown-unknown

bench_p2p:
	cd bench && cargo run --release

ci: fmt clippy test examples bench_p2p features-check
	git diff --exit-code Cargo.lock

check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

%_mol.rs: %.mol check-moleculec-version
	${MOLC} --language rust --schema-file $< | rustfmt > $@

gen-mol: $(MOL_RUST_FILES)

clean-mol:
	rm -f $(MOL_RUST_FILES)

cov-install-tools:
	rustup component add llvm-tools-preview --toolchain nightly
	grcov --version || cargo +nightly install grcov

cov: cov-install-tools
	rm -f "tentacle-cov/*.profraw"; mkdir -p tentacle-cov
	RUSTFLAGS="-Zinstrument-coverage" LLVM_PROFILE_FILE="tentacle-cov/tentacle-cov-%p-%m.profraw" cargo +nightly test --all --features ws,tls,unstable
	RUSTUP_TOOLCHAIN=nightly grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./tentacle-cov \
	--ignore "*/*_mol.rs" \
	--ignore "bench/*" \
	--ignore "multiaddr/*" \
	--excl-br-start "${GRCOV_EXCL_START}" --excl-br-stop "${GRCOV_EXCL_STOP}" \
	--excl-start    "${GRCOV_EXCL_START}" --excl-stop    "${GRCOV_EXCL_STOP}" \
	--excl-br-line  "${GRCOV_EXCL_LINE}" \
	--excl-line     "${GRCOV_EXCL_LINE}" 


.PHONY: fmt clippy test fuzz build examples ci check-moleculec-version gen-mol clean-mol cov cov-install-tools
