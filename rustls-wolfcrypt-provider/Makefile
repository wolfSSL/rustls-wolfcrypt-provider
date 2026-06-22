.PHONY: test
test:
	@cargo test

.PHONY: test-quic
test-quic:
	@cargo test --features quic

.PHONY: build
build:
	@cargo build --release
	@strip target/release/librustls_wolfcrypt_provider.rlib 2>/dev/null || echo "Strip failed"

.PHONY: clean
clean:
	@cargo clean
