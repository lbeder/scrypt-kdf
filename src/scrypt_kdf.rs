use crypto::scrypt::{scrypt, ScryptParams};

#[derive(Debug)]
pub struct ScryptKDFOptions {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    pub iterations: u32,
    pub keysize: usize
}

pub struct TestScryptKDFOptions {
    pub opts: ScryptKDFOptions,
    pub secret: &'static str
}

const DEFAULT_OPTIONS: ScryptKDFOptions = ScryptKDFOptions {
    log_n: 20,
    r: 8,
    p: 1,
    iterations: 100,
    keysize: 16
};

const TEST_VECTORS: &'static [&'static TestScryptKDFOptions] = &[
    &TestScryptKDFOptions {
        opts: ScryptKDFOptions {
            log_n: 14,
            r: 8,
            p: 1,
            iterations: 1,
            keysize: 128
        },
        secret: ""
    },
    &TestScryptKDFOptions {
        opts: ScryptKDFOptions {
            log_n: 14,
            r: 8,
            p: 1,
            iterations: 3,
            keysize: 128
        },
        secret: "Hello World"
    }
];

const MAX_KDF_SIZE: usize = 128;

pub struct ScryptKDF<'a> {
    opts: &'a ScryptKDFOptions,
}

impl<'a> ScryptKDF<'a> {
    pub fn new(opts: &ScryptKDFOptions) -> ScryptKDF {
        ScryptKDF { opts: opts }
    }

    pub fn default_options() -> &'static ScryptKDFOptions {
        &DEFAULT_OPTIONS
    }

    pub fn test_vectors() -> &'static [&'static TestScryptKDFOptions] {
        TEST_VECTORS
    }

    pub fn max_kdf_size() -> usize {
        MAX_KDF_SIZE
    }

    pub fn derive_test_vectors() -> Vec<Vec<u8>> {
        let mut results: Vec<Vec<u8>> = vec![];
        for test_vector in ScryptKDF::test_vectors() {
            let kdf = Self::new(&test_vector.opts);
            results.push(kdf.derive_key("", &test_vector.secret));
        }

        results
    }

    fn derive(&self, salt: &[u8], secret: &Vec<u8>) -> Vec<u8> {
        let mut dk = vec![0; self.opts.keysize];
        let params: ScryptParams = ScryptParams::new(self.opts.log_n, self.opts.r, self.opts.p);
        scrypt(secret, salt, &params, &mut dk);

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
