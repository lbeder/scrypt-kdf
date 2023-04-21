use scrypt::{scrypt, Params};

#[derive(PartialEq, Debug)]
pub struct ScryptKDFOptions {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    pub iterations: u32,
    pub len: usize,
}

#[derive(PartialEq, Debug)]
pub struct TestScryptKDFOptions {
    pub opts: ScryptKDFOptions,
    pub salt: &'static str,
    pub secret: &'static str,
}

pub const DEFAULT_SCRYPT_KDF_OPTIONS: ScryptKDFOptions = ScryptKDFOptions {
    log_n: 20,
    r: 8,
    p: 1,
    iterations: 100,
    len: 16,
};

pub const TEST_VECTORS: &[&TestScryptKDFOptions] = &[
    &TestScryptKDFOptions {
        opts: ScryptKDFOptions {
            log_n: 14,
            r: 8,
            p: 1,
            iterations: 1,
            len: 64,
        },
        salt: "",
        secret: "",
    },
    &TestScryptKDFOptions {
        opts: ScryptKDFOptions {
            log_n: 14,
            r: 8,
            p: 1,
            iterations: 3,
            len: 64,
        },
        salt: "",
        secret: "Hello World",
    },
];

pub const MAX_KDF_LEN: usize = 64;

pub struct ScryptKDF<'a> {
    opts: &'a ScryptKDFOptions,
}

impl<'a> ScryptKDF<'a> {
    pub fn new(opts: &'a ScryptKDFOptions) -> Self {
        if opts.len > MAX_KDF_LEN {
            panic!("length {} is greater than the max length of {MAX_KDF_LEN}", opts.len);
        }

        ScryptKDF { opts }
    }

    fn derive(&self, salt: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut dk = vec![0; self.opts.len];

        scrypt(
            secret,
            salt,
            &Params::new(self.opts.log_n, self.opts.r, self.opts.p, dk.len()).unwrap(),
            &mut dk,
        )
        .unwrap();

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
    use rstest::rstest;

    #[rstest]
    #[case(&TEST_VECTORS[0].opts, TEST_VECTORS[0].salt, TEST_VECTORS[0].secret, "d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e73ee37c31f4c4b571f4719fa8e3589f12db8dcb57ea9f56764bb7d58f64cf705")]
    #[case(&TEST_VECTORS[1].opts, TEST_VECTORS[1].salt, TEST_VECTORS[1].secret, "1487e1ac9c7a63e785b1f3e9560ea749913d50c9797dc6ca8d0db953fe03df1c66af878bd6dcce79884e8b7e3e29f39cb709cd63b7e7f4099d82ab199664eab3")]
    #[case(& ScryptKDFOptions {
        log_n: 14,
        r: 8,
        p: 1,
        iterations: 1,
        len: 64
    }, "salt", "test",
    "72f47a5f6bcb1b96a9d77b2c2f1463395d4a3a325fada6290fc0fef7bcddb58eb46e36a0d944613790c2e7bc9ea0e8447b9c4b493734c43526a14963e4a56bdc")]
    #[case(& ScryptKDFOptions {
        log_n: 12,
        r: 8,
        p: 1,
        iterations: 10,
        len: 32
    }, "salt", "test",
    "e419dac917d02f544469a5164c797ed0066cea15568958f6acc58411df5ac17e")]
    #[case(& ScryptKDFOptions {
        log_n: 20,
        r: 8,
        p: 1,
        iterations: 4,
        len: 64
    }, "salt", "test",
    "bd13f3cba884d87aeb68ca53efcd65175af1ee9d60907cf71d91e6bbddfa95ee7fb4d48442e54c8a28ac1d02298cdd793618827755ca69704b6cb9ec2b1e2f8e")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 4,
        len: 64
    }, "", "test",
    "8c18f4925f57caa69143d178e48d9a559963b045e413dc30ff02fd1c3c9ba1c5a5bf684aaf2aceb4fbc2eef11f4f9ac71b837b68797dc9c19062653b3e96664a")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 4,
        len: 64
    }, "", "",
    "7cb7f9c94b25bbf9afa023d20340bff9164658ccce3f09b164b5ce7130aaf84ec8fccbfc9d9de76a133218b7220da069430f40c58ef4bc53c639d5ea72b4437a")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 4,
        len: 64
    }, "salt", "",
    "9843308b393a354dd7166eab6a3da12cf324c88417899e195bc9231004acacab26c75bd0ac6b1e6d48f6f12ffd0869e485a67f4d98dd54d1d36384e94abfc11f")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 10,
        len: 64
    }, "salt", "test",
    "e409d625547cb5702ade6e74460e3b90768164e0771975f3548dda809bfadcb1ae4484ca0c7c659bc9e6d9753c28dc7d1ddb9ebfadde8375045dd3cbbaa2eac7")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 10,
        len: 64
    }, "salt2", "test",
    "d885f5c4c1196fc99eb97f5a08ae318d7a525dbbfdac2d5e8c8c210eb0ef2c58994cdef063463ba37caf47b6fc94693cced3ab03fefc9baf2cb05707d75767d2")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 10,
        len: 64
    }, "salt", "test2",
    "ff71c6680cd2e221a6a0d13d4527cddea71da1649d721a8392d969cc5f3bf7bc41d58cc2001296b9d985ea319473aa24813065bbaa675cb135372b1133f71d5c")]
    fn derive_test(
        #[case] options: &ScryptKDFOptions, #[case] salt: &str, #[case] secret: &str, #[case] expected: &str,
    ) {
        let kdf = ScryptKDF::new(options);
        let key = kdf.derive_key(salt, secret);
        assert_eq!(key, hex::decode(expected).unwrap());
    }
}
