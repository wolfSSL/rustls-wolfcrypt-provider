# rustls-wolfcrypt-provider

Code that lets you use `wolfCrypt` as a crypto provider for `Rustls`, with
`no_std` support by default (**still WIP**). The `std` library is only used in tests and the
`build.rs` file for binding generation; the core crypto provider itself does
not depend on `std`.

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

1. Clone the repository:
   ```
   git clone --depth=1 git@github.com:gasbytes/rustls-wolfcrypt-provider.git
   cd rustls-wolfcrypt-provider/
   ```

2. Run the build script to set up `wolfSSL` and `Rustls`:
   ```
   ./build.sh
   ```
This script performs the following steps:

* Builds `wolfSSL` and generates the necessary bindings.
* Installs `wolfSSL` to `/opt/wolfssl-rs` (requires sudo).
* Runs sanity tests for `wolfcrypt-rs` to ensure installation was successful.
* Builds `rustls-wolfcrypt-provider` with `wolfCrypt` as the crypto provider.
* Runs tests to confirm the setup for `Rustls` with `wolfCrypt`.

3. Verify Installation
* To confirm that everything is installed correctly, run:
   ```
   make test
   ```
* You should see output indicating successful test completion.

### Example Usage
For `Rustls` usage, consult the `examples` folder in this repository. Each example
demonstrates setting up and using `rustls-wolfcrypt-provider` with specific
cipher suites and configurations.
