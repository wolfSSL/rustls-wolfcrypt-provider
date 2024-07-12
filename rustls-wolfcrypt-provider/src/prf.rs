use rustls::crypto;
use std::boxed::Box;
use wolfcrypt_rs::*;
use std::mem;

pub struct PrfTls12;

impl crypto::tls12::Prf for PrfTls12 {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let secret = kx.complete(peer_pub_key)?;

        Ok(prf(output, secret.secret_bytes(), label, seed)?)
    }

    fn for_secret(
       &self, 
       output: &mut [u8], 
       secret: &[u8], 
       label: &[u8], 
       seed: &[u8]) -> () {
        prf(output, secret, label, seed).expect("failed to calculate prf in for_secret")
    }
}

fn prf(
   output: &mut [u8],
   secret: &[u8],
   label: &[u8],
   seed: &[u8],
) -> Result<(), rustls::Error> {
    unsafe {
        let ret;
        let use_at_least_sha_256: std::os::raw::c_int = 1;
        
        ret = wc_PRF_TLS(
            output.as_mut_ptr(),
            output.len() as word32,
            secret.as_ptr(),
            secret.len() as word32,
            label.as_ptr(),
            label.len() as word32,
            seed.as_ptr(),
            seed.len() as word32,
            use_at_least_sha_256,
            wc_MACAlgorithm_sha256_mac.try_into().unwrap(),
            std::ptr::null_mut(),
            INVALID_DEVID
        );
        if ret != 0 {
            panic!("failed while calling wc_PRF_TLS, ret value: {}", ret);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls12_prf() {
        unsafe {
            let preMasterSecret: [&[u8]; 3] = [
                "D06F9C19BFF49B1E91E4EFE97345D089".as_bytes(),
                "4E6C2E6C34A165B24540E2970875D641".as_bytes(),
                "2AA6515871B389B4C199BB8389C71CED".as_bytes()
            ];

            let helloRandom: [&[u8]; 4] = [
                "162B81EDFBEAE4F25240320B87E7651C".as_bytes(),
                "865564191DD782DB0B9ECA275FBA1BB9".as_bytes(),
                "5A1DA3DF436D68DA86C5E7B4B4A36E46".as_bytes(),
                "B977C61767983A31BE270D74517BD0F6".as_bytes()
            ];

            let masterSecret: [u8; 3] = [
                "EB38B8D89B98B1C266DE44BB3CA14E83".as_bytes(),
                "C32F009F9955B1D994E61D3C51EE8760".as_bytes(),
                "90B4EF89CC7AF42F46E72201BFCC7977".as_bytes()
            ];

            let label = "master secret".as_bytes();

            let pms: [u8; 48] = mem::zeroed();
            let seed: [u8; 64] = mem::zeroed();
            let ms: [u8; 48] = mem::zeroed();
            let mut result: [u8; 48] = mem::zeroed();

            let pmsSz: word32 = pms.len() as word32;
            let seedSz: word32 = seed.len() as word32;
            let msSz: word32 = ms.len() as word32;
            let mut ret;

            ret = Base16_Decode(
                preMasterSecret,
                preMasterSecret.len(), 
                pms, 
                pmsSz);
            if ret != 0 {
                panic!("failed while calling Base16_Decode, with ret value: {}", ret);
            }

            ret = Base16_Decode(
                helloRandom,
                helloRandom.len(), 
                seed, 
                seedSz);
            if ret != 0 {
                panic!("failed while calling Base16_Decode, with ret value: {}", ret);
            }

            ret = Base16_Decode(
                masterSecret.as_ptr(),
                masterSecret.len(), 
                ms.as_mut_ptr(), 
                msSz);
            if ret != 0 {
                panic!("failed while calling Base16_Decode, with ret value: {}", ret);
            }

            ret = wc_PRF_TLS(
                result.as_mut_ptr(), 
                msSz, 
                pms.as_ptr(), 
                pmsSz,
                label.as_ptr(), 
                label.len() as word32, 
                seed.as_ptr(), 
                seedSz,
                1, 
                wc_MACAlgorithm_sha256_mac.try_into().unwrap(),
                std::ptr::null_mut(), 
                INVALID_DEVID);
            if ret != 0 {
                panic!("failed while calling wc_PRF_TLS, with ret value: {}", ret);
            }

            assert_eq!(result, ms);
        }
    }
}
