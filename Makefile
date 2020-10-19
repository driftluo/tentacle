FLATC := flatc
CFBC := cfbc
MOLC    := moleculec
MOLC_VERSION := 0.6.0

FBS_FILES := \
  src/protocol_select/protocol_select.fbs \
  secio/src/handshake/handshake.fbs \

MOL_FILES := \
  src/protocol_select/protocol_select.mol \
  secio/src/handshake/handshake.mol \

FLATC_RUST_FILES := $(patsubst %.fbs,%_generated.rs,${FBS_FILES})
FLATBUFFERS_VERIFIER_FILES := $(patsubst %.fbs,%_generated_verifier.rs,${FBS_FILES})
MOL_RUST_FILES := $(patsubst %.mol,%_mol.rs,${MOL_FILES})

Change_Work_Path := cd tentacle

fmt:
	cargo fmt --all -- --check

clippy:
	$(Change_Work_Path) && RUSTFLAGS='-F warnings' cargo clippy --all --tests --features molc,ws -- -D clippy::let_underscore_must_use
	$(Change_Work_Path) && RUSTFLAGS='-F warnings' cargo clippy --all --tests --features flatc -- -D clippy::let_underscore_must_use

test:
	$(Change_Work_Path) && RUSTFLAGS='-F warnings' RUST_BACKTRACE=full cargo test --all --features molc,ws
	$(Change_Work_Path) && RUSTFLAGS='-F warnings' RUST_BACKTRACE=full cargo test --all --features flatc

fuzz:
	cargo +nightly fuzz run secio_crypto_decrypt_cipher -- -max_total_time=60
	cargo +nightly fuzz run secio_crypto_encrypt_cipher -- -max_total_time=60
	cargo +nightly fuzz run yamux_frame_codec           -- -max_total_time=60

build:
	$(Change_Work_Path) && RUSTFLAGS='-F warnings' cargo build --all --features molc,ws
	$(Change_Work_Path) && RUSTFLAGS='-F warnings' cargo build --all --features flatc

examples:
	$(Change_Work_Path) && cargo build --examples --all --features molc
	$(Change_Work_Path) && cargo build --examples --all --features flatc

features-check:
	# remove yamux default features
	sed -i 's/"tokio-timer"//g' yamux/Cargo.toml
	$(Change_Work_Path) && cargo build --features molc
	$(Change_Work_Path) && cargo build --features molc,tokio-runtime,generic-timer --no-default-features
	$(Change_Work_Path) && cargo build --features molc,async-runtime,generic-timer --no-default-features
	$(Change_Work_Path) && cargo build --features molc,async-runtime,async-timer --no-default-features
	git checkout .

bench_p2p:
	cd bench && cargo run --release --features molc
	cd bench && cargo run --release --features flatc

ci: fmt clippy test examples bench_p2p features-check
	git diff --exit-code Cargo.lock

check-cfbc-version:
	test "$$($(CFBC) --version)" = 0.1.9

%_generated_verifier.rs: %.fbs check-cfbc-version
	$(FLATC) -b --schema -o $(shell dirname $@) $<
	$(CFBC) -o $(shell dirname $@) $*.bfbs
	rm -f $*_builder.rs $*.bfbs

%_generated.rs: %.fbs
	$(FLATC) -r -o $(shell dirname $@) $<

gen-fb: $(FLATC_RUST_FILES) $(FLATBUFFERS_VERIFIER_FILES)

clean-fb:
	rm -f $(FLATC_RUST_FILES) $(FLATBUFFERS_VERIFIER_FILES)

check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

%_mol.rs: %.mol check-moleculec-version
	${MOLC} --language rust --schema-file $< | rustfmt > $@

gen-mol: $(MOL_RUST_FILES)

clean-mol:
	rm -f $(MOL_RUST_FILES)


.PHONY: fmt clippy test fuzz build examples ci gen-fb clean-fb check-cfbc-version check-moleculec-version gen-mol clean-mol
