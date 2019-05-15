FLATC := flatc
CFBC := cfbc

FBS_FILES := \
  src/protocol_select/protocol_select.fbs \
  secio/src/handshake/handshake.fbs \
  protocols/identify/src/protocol.fbs \
  protocols/ping/src/protocol.fbs \
  protocols/discovery/src/protocol.fbs

FLATC_RUST_FILES := $(patsubst %.fbs,%_generated.rs,${FBS_FILES})
FLATBUFFERS_VERIFIER_FILES := $(patsubst %.fbs,%_generated_verifier.rs,${FBS_FILES})

fmt:
	cargo fmt --all -- --check

clippy:
	RUSTFLAGS='-F warnings' cargo clippy --all --tests

test:
	RUSTFLAGS='-F warnings' RUST_BACKTRACE=full cargo test --all

examples:
	cargo build --examples --all

bench_p2p:
	cd bench && cargo run --release && cd ..

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


.PHONY: fmt clippy test examples ci gen-fb clean-fb check-cfbc-version
