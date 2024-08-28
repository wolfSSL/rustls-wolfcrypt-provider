
# rustls-wolfcrypt-provider

Code that lets you use [wolfcrypt](https://github.com/wolfSSL/wolfssl/tree/master/wolfcrypt) as crypto provider for [rustls](https://github.com/rustls/rustls).

# Status
**This is very much in an alpha stage, particularly because the Rustls API is not yet stable.**
**This code currently works with Rustls = 0.23.9.**

# Cipher suites (currently) supported
- tls 1.3: 
    - `TLS13_CHACHA20_POLY1305_SHA256`;
    - `TLS13_AES_128_GCM_SHA256`;
    - `TLS13_AES_256_GCM_SHA384`;
- tls 1.2: 
    - `TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`;
    - `TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256`;
    - `TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384`;
    - `TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`;
    - `TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`;
    - `TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`;
For more details about the supported curves, verification/signing methods, and algorithms in general, [please consult the respective folders](https://github.com/gasbytes/rustls-wolfcrypt-provider/tree/main/rustls-wolfcrypt-provider/src).

# Usage

## Setup wolfssl and generate bindings

Clone the repository and cd into it:
```
git clone --depth=1 git@github.com:gasbytes/rustls-wolfcrypt-provider.git
cd rustls-wolfcrypt-provider/
```

Build wolfssl and generate bindings:
```
cd wolfcrypt-rs/
cargo build
```
Enter sudo password (requested to run `sudo make install`), the final installation of wolfssl
will be located in `/opt/wolfcrypt-rs/`, built with this configuration:

```
./configure --enable-all --enable-all-crypto --disable-shared --prefix=/opt/wolfssl-rs/
```

To check if everything went smoothly, run `cargo test` to run the sanity checks in `wolfcrypt-rs`.

## Setup rustls

```
cd ../rustls-wolfcrypt-provider
cargo build
cargo test
```

For rustls usage consult the `examples` folder. 
