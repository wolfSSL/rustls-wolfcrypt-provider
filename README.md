# rustls-wolfcrypt-provider

Code that let you use wolfcrypt as crypto provider for rustls.

# Status
**(WIP)**

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

To check if everything went well, run `cargo test`.

## Setup rustls

```
cd ../rustls-wolfcrypt-provider
cargo build
cargo test
```

For rustls usage consult the `tests/e2e.rs` file. 
