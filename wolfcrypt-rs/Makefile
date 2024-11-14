.PHONY: test
test: 
	@cargo test

.PHONY: build
build:
	@cargo build --release
	@strip target/release/libwolfcrypt_rs.rlib 2>/dev/null || echo "Strip failed"

.PHONY: clean
clean:
	@cargo clean
	@rm -rf wolfssl-*
