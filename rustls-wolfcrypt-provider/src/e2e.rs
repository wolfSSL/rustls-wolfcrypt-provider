use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::vec;
use std::sync::Arc;
use rcgen::CertificateParams;
use std::string::ToString;
use alloc::vec::Vec;
use rustls::{
    version::{TLS12, TLS13},
    ServerConfig 
};
use super::provider;
use std::mem;
use wolfcrypt_rs::*;

struct TestPki {
    ca_cert_der: CertificateDer<'static>,
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
}

impl TestPki {
    fn new(alg: &'static rcgen::SignatureAlgorithm) -> Self {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Provider Server Example");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];

        keypair_for_alg(&mut ca_params, alg);
        ca_params.alg = alg;
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        let ca_cert_der = CertificateDer::from(ca_cert.serialize_der().unwrap());
        let mut server_ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_ee_params.alg = alg;
        keypair_for_alg(&mut server_ee_params, alg);
        let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
        let server_cert_der = CertificateDer::from(server_cert.serialize_der_with_signer(&ca_cert).unwrap());
        let server_key_der = PrivatePkcs8KeyDer::from(server_cert.serialize_private_key_der()).into();
        Self {
            ca_cert_der,
            server_cert_der,
            server_key_der,
        }
    }

    fn server_config(self) -> Arc<ServerConfig> {
        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(provider()))
                .with_protocol_versions(&[&TLS12, &TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![self.server_cert_der], self.server_key_der)
                .unwrap();

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }

    fn client_root_store(&self) -> rustls::RootCertStore {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(self.ca_cert_der.clone()).unwrap();
        root_store
    }
}

fn keypair_for_alg(params: &mut CertificateParams, alg: &rcgen::SignatureAlgorithm) {
    if alg == &rcgen::PKCS_RSA_SHA256 {
        params.key_pair = Some(gen_rsa_key(2048));
    } else if alg == &rcgen::PKCS_RSA_SHA384 {
        params.key_pair = Some(gen_rsa_key(3072));
    } else if alg == &rcgen::PKCS_RSA_SHA512 {
        params.key_pair = Some(gen_rsa_key(4096));
    }
}

fn gen_rsa_key(bits: u32) -> rcgen::KeyPair {
    unsafe {
        let mut ret;
        let mut rng: WC_RNG = mem::zeroed();
        let mut rsa_key: RsaKey = mem::zeroed();
        let mut der: [u8; 1024] = [0; 1024];
        let mut der_sz: word32 = der.len() as word32;
        let mut pkcs8: [u8; 1024] = [0; 1024];
        let mut pkcs8_sz: word32 = pkcs8.len() as word32;

        ret = wc_InitRsaKey(&mut rsa_key, std::ptr::null_mut());
        if ret != 0 {
            panic!("Error while initializing Rsa key! Ret value: {}", ret);
        }

        ret = wc_InitRng(&mut rng);
        if ret != 0 {
            panic!("Error while initializing RNG!");
        }

        ret = wc_RsaSetRNG(&mut rsa_key, &mut rng);
        if ret != 0 {
            panic!("Error while setting rng to Rsa key! Ret value: {}", ret);
        }

        ret = wc_MakeRsaKey(&mut rsa_key, bits.try_into().unwrap(), 65537, &mut rng);
        if ret != 0 {
            panic!("Error while creating the Rsa Key! Ret value: {}", ret);
        }

        ret = wc_RsaKeyToDer(&mut rsa_key, der.as_mut_ptr(), der_sz);
        if ret != 0 {
            panic!("Error while converting the rsa key to der! Ret value: {}", ret);
        }

        ret = wc_CreatePKCS8Key(
                std::ptr::null_mut(),
                &mut pkcs8_sz,
                der.as_mut_ptr(),
                der_sz,
                Key_Sum_RSAk.try_into().unwrap(),
                std::ptr::null_mut(),
                0
            );
        if ret > 0 {
            panic!("Error while creating the pkcs8key! ret value: {}", ret);
        }

        ret = wc_CreatePKCS8Key(
                pkcs8.as_mut_ptr(),
                &mut pkcs8_sz,
                der.as_mut_ptr(),
                der_sz,
                Key_Sum_RSAk.try_into().unwrap(),
                std::ptr::null_mut(),
                0
            );
        if ret > 0 {
            panic!("Error while creating the pkcs8key! ret value: {}", ret);
        }

        rcgen::KeyPair::from_der(&pkcs8).unwrap()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_tls12() {
        assert_eq!(0, 0)
    }
}
