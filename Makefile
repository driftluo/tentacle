FLATC := flatc
CFBC := cfbc
MOLC    := moleculec
MOLC_VERSION := 0.2.5

FBS_FILES := \
  src/protocol_select/protocol_select.fbs \
  secio/src/handshake/handshake.fbs \
  protocols/identify/src/protocol.fbs \
  protocols/ping/src/protocol.fbs \
  protocols/discovery/src/protocol.fbs

MOL_FILES := \
  src/protocol_select/protocol_select.mol \
  secio/src/handshake/handshake.mol \
  protocols/identify/src/protocol.mol \
  protocols/ping/src/protocol.mol \
  protocols/discovery/src/protocol.mol

FLATC_RUST_FILES := $(patsubst %.fbs,%_generated.rs,${FBS_FILES})
FLATBUFFERS_VERIFIER_FILES := $(patsubst %.fbs,%_generated_verifier.rs,${FBS_FILES})
MOL_RUST_FILES := $(patsubst %.mol,%_mol.rs,${MOL_FILES})


fmt:
	cargo fmt --all -- --check
	cd protocols/ping && cargo fmt -- --check
	cd protocols/discovery && cargo fmt -- --check
	cd protocols/identify && cargo fmt -- --check

clippy:
	RUSTFLAGS='-F warnings' cargo clippy --all --tests --features molc
	RUSTFLAGS='-F warnings' cargo clippy --all --tests --features flatc
	cd protocols/ping && RUSTFLAGS='-F warnings' cargo clippy --all --tests --features molc \
	    && RUSTFLAGS='-F warnings' cargo clippy --all --tests --features flatc
	cd protocols/identify && RUSTFLAGS='-F warnings' cargo clippy --all --tests --features molc \
	    && RUSTFLAGS='-F warnings' cargo clippy --all --tests --features flatc
	cd protocols/discovery && RUSTFLAGS='-F warnings' cargo clippy --all --tests --features molc \
	    && RUSTFLAGS='-F warnings' cargo clippy --all --tests --features flatc

test:
	RUSTFLAGS='-F warnings' RUST_BACKTRACE=full cargo test --all --features molc
	RUSTFLAGS='-F warnings' RUST_BACKTRACE=full cargo test --all --features flatc

examples:
	cargo build --examples --all --features molc
	cargo build --examples --all --features flatc

bench_p2p:
	cd bench && cargo run --release --features molc
	cd bench && cargo run --release --features flatc

ci: fmt clippy test examples bench_p2p
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


.PHONY: fmt clippy test examples ci gen-fb clean-fb check-cfbc-version check-moleculec-version gen-mol clean-mol
