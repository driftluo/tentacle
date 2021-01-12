MOLC    := moleculec
MOLC_VERSION := 0.6.0

MOL_FILES := \
  src/protocol_select/protocol_select.mol \
  secio/src/handshake/handshake.mol \

MOL_RUST_FILES := $(patsubst %.mol,%_mol.rs,${MOL_FILES})

Change_Work_Path := cd tentacle

fmt:
	cargo fmt --all -- --check

clippy:
	$(Change_Work_Path) && RUSTFLAGS='-F warnings' cargo clippy --all --tests --features ws,unstable -- -D clippy::let_underscore_must_use

test:
	$(Change_Work_Path) && RUSTFLAGS='-F warnings' RUST_BACKTRACE=full cargo test --all --features ws,unstable

fuzz:
	cargo +nightly fuzz run secio_crypto_decrypt_cipher -- -max_total_time=60
	cargo +nightly fuzz run secio_crypto_encrypt_cipher -- -max_total_time=60
	cargo +nightly fuzz run yamux_frame_codec           -- -max_total_time=60

build:
	$(Change_Work_Path) && RUSTFLAGS='-F warnings' cargo build --all --features ws
	$(Change_Work_Path) && RUSTFLAGS='-F warnings' cargo build --all --features ws,unstable

examples:
	$(Change_Work_Path) && cargo build --examples --all --features unstable

features-check:
	# remove yamux default features
	sed -i 's/"tokio-timer"//g' yamux/Cargo.toml
	$(Change_Work_Path) && cargo build --features unstable
	$(Change_Work_Path) && cargo build --features tokio-runtime,generic-timer,unstable --no-default-features
	$(Change_Work_Path) && cargo build --features async-runtime,generic-timer,unstable --no-default-features
	$(Change_Work_Path) && cargo build --features async-runtime,async-timer,unstable --no-default-features
	# required wasm32-unknown-unknown target
	$(Change_Work_Path) && cargo build --features wasm-timer,unstable --no-default-features --target=wasm32-unknown-unknown
	git checkout .

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


.PHONY: fmt clippy test fuzz build examples ci check-moleculec-version gen-mol clean-mol
