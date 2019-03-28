
fmt:
	cargo fmt --all -- --check

clippy:
	RUSTFLAGS='-F warnings' cargo clippy --all --tests

test:
	RUSTFLAGS='-F warnings' cargo test --all

examples:
	cargo build --examples --all

ci: fmt clippy test examples
	git diff --exit-code Cargo.lock
