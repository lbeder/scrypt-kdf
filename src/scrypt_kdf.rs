use libsodium_sys::crypto_pwhash_scryptsalsa208sha256_ll;
use libc::{size_t};

use std::default::Default;

#[derive(PartialEq, Debug)]
pub struct ScryptKDFOptions {
    pub n: u64,
    pub r: u32,
    pub p: u32,
    pub iterations: u32,
    pub keysize: usize,
}

#[derive(PartialEq, Debug)]
pub struct TestScryptKDFOptions {
    pub opts: ScryptKDFOptions,
    pub secret: &'static str,
}

impl Default for ScryptKDFOptions {
    fn default() -> Self {
        Self {
            n: 1048576,
            r: 8,
            p: 1,
            iterations: 100,
            keysize: 16,
        }
    }
}

const TEST_VECTORS: &[&TestScryptKDFOptions] = &[
    &TestScryptKDFOptions {
        opts: ScryptKDFOptions {
            n: 16384,
            r: 8,
            p: 1,
            iterations: 1,
            keysize: 128,
        },
        secret: "",
    },
    &TestScryptKDFOptions {
        opts: ScryptKDFOptions {
            n: 16384,
            r: 8,
            p: 1,
            iterations: 3,
            keysize: 128,
        },
        secret: "Hello World",
    },
];

const MAX_KDF_SIZE: usize = 128;

pub struct ScryptKDF<'a> {
    opts: &'a ScryptKDFOptions,
}

impl<'a> ScryptKDF<'a> {
    pub fn new(opts: &'a ScryptKDFOptions) -> Self {
        ScryptKDF { opts }
    }

    pub fn test_vectors() -> &'static [&'static TestScryptKDFOptions] {
        &TEST_VECTORS
    }

    pub fn max_kdf_size() -> usize {
        MAX_KDF_SIZE
    }

    pub fn derive_test_vectors() -> Vec<Vec<u8>> {
        let mut results: Vec<Vec<u8>> = vec![];
        for test_vector in Self::test_vectors() {
            let kdf = Self::new(&test_vector.opts);
            results.push(kdf.derive_key("", &test_vector.secret));
        }

        results
    }

    fn derive(&self, salt: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut dk = vec![0; self.opts.keysize];

        let res = unsafe {
            crypto_pwhash_scryptsalsa208sha256_ll(
                secret.as_ptr(),
                secret.len() as size_t,
                salt.as_ptr(),
                salt.len() as size_t,
                self.opts.n as u64,
                self.opts.r,
                self.opts.p,
                dk.as_mut_ptr(),
                dk.len() as size_t)
        };

        assert!(res == 0, format!("crypto_pwhash_scryptsalsa208sha256_ll has failed with {}", &res));

        dk.to_vec()
    }

    pub fn derive_key_with_callback<F: FnMut()>(&self, salt: &str, secret: &str, mut callback: F) -> Vec<u8> {
        let mut res: Vec<u8> = secret.as_bytes().to_vec();
        let salt_bytes = salt.as_bytes();
        for _ in 0..self.opts.iterations {
            res = self.derive(salt_bytes, &res);
            callback();
        }

        res
    }

    pub fn derive_key(&self, salt: &str, secret: &str) -> Vec<u8> {
        self.derive_key_with_callback(salt, secret, || {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_vectors() {
        let test_vectors = ScryptKDF::test_vectors();
        assert_eq!(test_vectors, TEST_VECTORS);
    }

    #[test]
    fn test_max_kdf_size() {
        let max_kdf_size = ScryptKDF::max_kdf_size();
        assert_eq!(max_kdf_size, MAX_KDF_SIZE);
    }

    #[test]
    fn test_derive_test_vectors() {
        let test_keys = ScryptKDF::derive_test_vectors();
        assert_eq!(test_keys[0], hex::decode("d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e73ee37c31f4c4b571f4719fa8e3589f12db8dcb57ea9f56764bb7d58f64cf705f1f64bdd91c35da954a6fb7896f1839e6ba03f68f08b686527f9f1588ab103c22152046258e2d679842252afeb3cd6eb4e01fe9c285eb916da7e4b7a39ee5eba").unwrap());
        assert_eq!(test_keys[1], hex::decode("38f3b062f703aa0c958fc8944c9f005f1bd03a056048d5cdc6186979e4c178504050580fab8744c0272253f7df87a2e2f9bb5449a2361f0fed5105ea549e86e41f68d8b160cda5ca91e020067b0c53fc20ae19993e1f40db60d8963ec8c7c0fe74d48a44f1f78a4259f0376f6d7dd2c07d2e7aaae023b8bdfa87ddbf503fe9a3").unwrap());
    }

    macro_rules! derive_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (options, salt, secret, expected) = $value;
                let kdf = ScryptKDF::new(&options);
                let key = kdf.derive_key(salt, secret);
                assert_eq!(key, hex::decode(expected).unwrap());
            }
        )*
        }
    }

    derive_tests! {
    test_data_0: (ScryptKDFOptions {
        n: 16384,
        r: 8,
        p: 1,
        iterations: 1,
        keysize: 128
    }, "salt", "test",
    "72f47a5f6bcb1b96a9d77b2c2f1463395d4a3a325fada6290fc0fef7bcddb58e\
     b46e36a0d944613790c2e7bc9ea0e8447b9c4b493734c43526a14963e4a56bdc\
     bf50dead892d3e63104433f3f763a867f6a46e1745169517b0d82f5173a80ccf\
     fd9c2ed0aaa89cedde6b18a9351645cf4006531e637d8cab49f61a451f3f16a6"),

    test_data_1: (ScryptKDFOptions {
        n: 4096,
        r: 8,
        p: 1,
        iterations: 10,
        keysize: 32
    }, "salt", "test",
    "e419dac917d02f544469a5164c797ed0066cea15568958f6acc58411df5ac17e"),

    test_data_2: (ScryptKDFOptions {
        n: 1048576,
        r: 8,
        p: 1,
        iterations: 4,
        keysize: 64
    }, "salt", "test",
    "bd13f3cba884d87aeb68ca53efcd65175af1ee9d60907cf71d91e6bbddfa95ee\
     7fb4d48442e54c8a28ac1d02298cdd793618827755ca69704b6cb9ec2b1e2f8e"),

    test_data_3: (ScryptKDFOptions {
        n: 32768,
        r: 8,
        p: 1,
        iterations: 4,
        keysize: 64
    }, "", "test",
    "8c18f4925f57caa69143d178e48d9a559963b045e413dc30ff02fd1c3c9ba1c5\
     a5bf684aaf2aceb4fbc2eef11f4f9ac71b837b68797dc9c19062653b3e96664a"),

    test_data_4: (ScryptKDFOptions {
        n: 32768,
        r: 8,
        p: 1,
        iterations: 4,
        keysize: 64
    }, "", "",
    "7cb7f9c94b25bbf9afa023d20340bff9164658ccce3f09b164b5ce7130aaf84e\
     c8fccbfc9d9de76a133218b7220da069430f40c58ef4bc53c639d5ea72b4437a"),

    test_data_5: (ScryptKDFOptions {
        n: 32768,
        r: 8,
        p: 1,
        iterations: 4,
        keysize: 128
    }, "salt", "",
    "9e64f92ebbb0e4d70202cf9be66d8344c9b1b571801e28e69f733ea9d0abc285\
     92fd3c0020a8a5b2a9d653751aa4528acb74887ff93699d38bf54d0714f08f65\
     cb63396a4a339707ca37ebfe50140f9c8bcf8ab3f845ead69669c0e6234d1748\
     3723d01f52a47f352e184887f09cf04b0e0078125a5a223dec641f0961545aea"),

    test_data_6: (ScryptKDFOptions {
        n: 32768,
        r: 8,
        p: 1,
        iterations: 10,
        keysize: 128
    }, "salt", "test",
    "d6fd2f35ef5240b780f993ab60401853a9f223fcc4698eeaa25f9b92345ac22b\
     37cdb3aa3232e9f1a684d7151dd37f97d71f7e491e66a4927323d74f14d7270e\
     7a7c78b3d5cdabf8893d7caa1e8c4857aa75487476f7fbf3745dd71070e15e14\
     be640bd364935fb173c097fbbc5e5e0b4dae4b81ba6ba5a0534818aea029af63"),

    test_data_7: (ScryptKDFOptions {
        n: 32768,
        r: 8,
        p: 1,
        iterations: 10,
        keysize: 128
    }, "salt2", "test",
    "b24e225031bd88ff836b82a361abcf2c1f6e937938dad79403deeff75b7f11e9\
     2c314baca202625239f1f3ff0223c543332c277019777da3c2b5a36514e1ab41\
     0ec25752e438e702b0a3ce7ee3906485d51e913d6c06621ac324b08a504077d7\
     6557833781dac6753f10268b22ed01fc12094c0d7aadf5be1a4937c63ce0d80c"),

    test_data_8: (ScryptKDFOptions {
        n: 32768,
        r: 8,
        p: 1,
        iterations: 10,
        keysize: 128
    }, "salt", "test2",
    "2bcaf7caa9fbc6b9ac7ce88ac95612ac1c994c8a1b3f87ef826fea09cc4ca663\
     2bb41944028b52208004eb14904481a8bca5f6b20e49f130b0f58340f8313e26\
     df302dd797107610b222e7769a5afb6eef11cb27b9240eceeb1d2a29628d8d10\
     5e32d5e7b84edd951b85f4b3e04651574e9e000f09b076bbce3781383892b708"),
    }
}
