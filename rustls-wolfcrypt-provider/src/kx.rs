use alloc::boxed::Box;
use crypto::SupportedKxGroup;
use rustls::crypto;

mod sec256r1;
mod sec384r1;
mod sec521r1;
mod x25519;

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &SECP256R1, &SECP384R1, &SECP521R1];

macro_rules! define_kx_group {
    ($name:ident, $kx_type:ty, $kx_func:ident, $named_group:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl crypto::SupportedKxGroup for $name {
            fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
                Ok(Box::new(<$kx_type>::$kx_func()?))
            }

            fn name(&self) -> rustls::NamedGroup {
                $named_group
            }
        }
    };
}

// Define Supported KeyExchange groups
define_kx_group!(
    X25519,
    x25519::KeyExchangeX25519,
    use_curve25519,
    rustls::NamedGroup::X25519
);
define_kx_group!(
    SECP256R1,
    sec256r1::KeyExchangeSecP256r1,
    use_secp256r1,
    rustls::NamedGroup::secp256r1
);
define_kx_group!(
    SECP384R1,
    sec384r1::KeyExchangeSecP384r1,
    use_secp384r1,
    rustls::NamedGroup::secp384r1
);
define_kx_group!(
    SECP521R1,
    sec521r1::KeyExchangeSecP521r1,
    use_secp521r1,
    rustls::NamedGroup::secp521r1
);
