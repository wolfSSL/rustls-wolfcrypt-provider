# rustls-wolfcrypt-provider

Code that lets you use `wolfCrypt` as a crypto provider for `Rustls`,
built with `no_std` support as its foundation. The `std` library is pulled in
only for testing and during the `build.rs` binding generation; the core crypto
provider itself operates independently of `std`.

## Status

This is in an alpha stage, particularly because the Rustls API is not yet stable.  
This code currently works with Rustls = 0.23.16.

## Repo Structure

- **rustls-wolfcrypt-provider**: Crate containing the code that lets you use rustls with wolfcrypt as a crypto provider.
- **wolfcrypt-rs**: Low-level unsafe bindings for wolfcrypt generated using bindgen.

## Cipher Suites (Currently) Supported

### TLS 1.3:
- `TLS13_CHACHA20_POLY1305_SHA256`
- `TLS13_AES_128_GCM_SHA256`
- `TLS13_AES_256_GCM_SHA384`

### TLS 1.2:
- `TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`

For more details about the supported curves, verification/signing methods, and algorithms, please consult the respective folders.

## Usage

### Initial Setup and Installation
*Rustc 1.77+ is required.*

1. Clone the repository:
   ```
   git clone --depth=1 git@github.com:wolfssl/rustls-wolfcrypt-provider.git
   cd rustls-wolfcrypt-provider/
   ```

2. Build the wolfcrypt-rs crate to correctly generate the bindings and make sure
   the build was successful by running the sanity check(s):
   ```
   cd wolfcrypt-rs/
   make build
   make test
   ```

   Then change the current directory to the rustls-wolfcrypt-provider, build 
   the crate, followed by running the test to make sure everything is running
   smoothly:
   ```
   cd ../rustls-wolfcrypt-provider/
   make build
   make test
   ```

### Example Usage
For `Rustls` usage, consult the `examples` folder in this repository. Each example
demonstrates setting up and using `rustls-wolfcrypt-provider` with specific
cipher suites and configurations.
