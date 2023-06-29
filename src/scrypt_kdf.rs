use scrypt::{scrypt, Params};

#[derive(PartialEq, Debug)]
pub struct ScryptKDFOptions {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    pub iterations: u32,
    pub length: u8,
}

#[derive(PartialEq, Debug)]
pub struct TestScryptKDFOptions {
    pub opts: ScryptKDFOptions,
    pub salt: Vec<u8>,
    pub secret: Vec<u8>,
    pub offset: u32,
}

pub const DEFAULT_SCRYPT_KDF_OPTIONS: ScryptKDFOptions = ScryptKDFOptions {
    log_n: 20,
    r: 8,
    p: 1,
    iterations: 100,
    length: 16,
};

lazy_static! {
    pub static ref TEST_VECTORS: Vec<TestScryptKDFOptions> = vec![
        TestScryptKDFOptions {
            opts: ScryptKDFOptions {
                log_n: 14,
                r: 8,
                p: 1,
                iterations: 1,
                length: 64,
            },
            salt: Vec::new(),
            secret: Vec::new(),
            offset: 0,
        },
        TestScryptKDFOptions {
            opts: ScryptKDFOptions {
                log_n: 14,
                r: 8,
                p: 1,
                iterations: 3,
                length: 64,
            },
            salt: Vec::new(),
            secret: "Hello World".as_bytes().to_vec(),
            offset: 0,
        },
    ];
}

pub const MIN_KDF_LEN: u8 = 10;
pub const MAX_KDF_LEN: u8 = 64;

pub struct ScryptKDF<'a> {
    opts: &'a ScryptKDFOptions,
}

impl<'a> ScryptKDF<'a> {
    pub fn new(opts: &'a ScryptKDFOptions) -> Self {
        if opts.length < MIN_KDF_LEN {
            panic!("length {} is lower than the min length of {MIN_KDF_LEN}", opts.length);
        }

        if opts.length > MAX_KDF_LEN {
            panic!("length {} is greater than the max length of {MAX_KDF_LEN}", opts.length);
        }

        ScryptKDF { opts }
    }

    fn derive(&self, salt: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut dk = vec![0; self.opts.length as usize];

        scrypt(
            secret,
            salt,
            &Params::new(self.opts.log_n, self.opts.r, self.opts.p, dk.len()).unwrap(),
            &mut dk,
        )
        .unwrap();

        dk.to_vec()
    }

    pub fn derive_key_with_callback<F: FnMut(u32, &Vec<u8>)>(
        &self, salt: &[u8], data: &[u8], offset: u32, mut callback: F,
    ) -> Vec<u8> {
        let mut res: Vec<u8> = data.to_vec();

        for i in 0..(self.opts.iterations - offset) {
            res = self.derive(salt, &res);
            callback(i, &res);
        }

        res
    }

    pub fn derive_key(&self, salt: &[u8], data: &[u8], start: u32) -> Vec<u8> {
        self.derive_key_with_callback(salt, data, start, |_, _| {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(&TEST_VECTORS[0].opts, &TEST_VECTORS[0].salt, &TEST_VECTORS[0].secret, TEST_VECTORS[0].offset, "d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e73ee37c31f4c4b571f4719fa8e3589f12db8dcb57ea9f56764bb7d58f64cf705")]
    #[case(&TEST_VECTORS[1].opts, &TEST_VECTORS[1].salt, &TEST_VECTORS[1].secret, TEST_VECTORS[1].offset, "1487e1ac9c7a63e785b1f3e9560ea749913d50c9797dc6ca8d0db953fe03df1c66af878bd6dcce79884e8b7e3e29f39cb709cd63b7e7f4099d82ab199664eab3")]
    #[case(& ScryptKDFOptions {
        log_n: 14,
        r: 8,
        p: 1,
        iterations: 1,
        length: 64
    }, &"salt".as_bytes(), &"test".as_bytes(), 0,
    "72f47a5f6bcb1b96a9d77b2c2f1463395d4a3a325fada6290fc0fef7bcddb58eb46e36a0d944613790c2e7bc9ea0e8447b9c4b493734c43526a14963e4a56bdc")]
    #[case(& ScryptKDFOptions {
        log_n: 12,
        r: 8,
        p: 1,
        iterations: 10,
        length: 32
    }, &"salt".as_bytes(), &"test".as_bytes(), 0,
    "e419dac917d02f544469a5164c797ed0066cea15568958f6acc58411df5ac17e")]
    #[case(& ScryptKDFOptions {
        log_n: 20,
        r: 8,
        p: 1,
        iterations: 4,
        length: 64
    }, &"salt".as_bytes(), &"test".as_bytes(), 0,
    "bd13f3cba884d87aeb68ca53efcd65175af1ee9d60907cf71d91e6bbddfa95ee7fb4d48442e54c8a28ac1d02298cdd793618827755ca69704b6cb9ec2b1e2f8e")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 4,
        length: 64
    }, &Vec::new(), &"test".as_bytes(), 0,
    "8c18f4925f57caa69143d178e48d9a559963b045e413dc30ff02fd1c3c9ba1c5a5bf684aaf2aceb4fbc2eef11f4f9ac71b837b68797dc9c19062653b3e96664a")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 4,
        length: 64
    }, &Vec::new(), &Vec::new(), 0,
    "7cb7f9c94b25bbf9afa023d20340bff9164658ccce3f09b164b5ce7130aaf84ec8fccbfc9d9de76a133218b7220da069430f40c58ef4bc53c639d5ea72b4437a")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 4,
        length: 64
    }, &"salt".as_bytes(), &"".as_bytes(), 0,
    "9843308b393a354dd7166eab6a3da12cf324c88417899e195bc9231004acacab26c75bd0ac6b1e6d48f6f12ffd0869e485a67f4d98dd54d1d36384e94abfc11f")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 10,
        length: 64
    }, &"salt".as_bytes(), &"test".as_bytes(), 0,
    "e409d625547cb5702ade6e74460e3b90768164e0771975f3548dda809bfadcb1ae4484ca0c7c659bc9e6d9753c28dc7d1ddb9ebfadde8375045dd3cbbaa2eac7")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 10,
        length: 64
    }, &"salt2".as_bytes(), &"test".as_bytes(), 0,
    "d885f5c4c1196fc99eb97f5a08ae318d7a525dbbfdac2d5e8c8c210eb0ef2c58994cdef063463ba37caf47b6fc94693cced3ab03fefc9baf2cb05707d75767d2")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 10,
        length: 64
    }, &"salt".as_bytes(), &"test2".as_bytes(), 0,
    "ff71c6680cd2e221a6a0d13d4527cddea71da1649d721a8392d969cc5f3bf7bc41d58cc2001296b9d985ea319473aa24813065bbaa675cb135372b1133f71d5c")]
    #[case(& ScryptKDFOptions {
        log_n: 12,
        r: 8,
        p: 1,
        iterations: 10,
        length: 32
    }, &"salt".as_bytes(), &hex::decode("881958a1b9fd93fc81c7bdc92a384199a558426c06b9c1374e3d9e155d43a436").unwrap(), 1,
    "e419dac917d02f544469a5164c797ed0066cea15568958f6acc58411df5ac17e")]
    #[case(& ScryptKDFOptions {
        log_n: 15,
        r: 8,
        p: 1,
        iterations: 10,
        length: 64
    }, &"salt".as_bytes(), &hex::decode("cf327a4f6f7809a453bab78aaa645bcd79a505728191df2f8c9149dd6c92ee0ae4d63400cb6f20ee8a9c42ef1a2c5c596e71f04b18c0f9bf0df75ab060e75436").unwrap(), 5,
    "e409d625547cb5702ade6e74460e3b90768164e0771975f3548dda809bfadcb1ae4484ca0c7c659bc9e6d9753c28dc7d1ddb9ebfadde8375045dd3cbbaa2eac7")]

    fn derive_test(
        #[case] options: &ScryptKDFOptions, #[case] salt: &[u8], #[case] data: &[u8], #[case] offset: u32,
        #[case] expected: &str,
    ) {
        let kdf = ScryptKDF::new(options);
        let key = kdf.derive_key(salt, data, offset);
        assert_eq!(hex::encode(key), expected);
    }
}
