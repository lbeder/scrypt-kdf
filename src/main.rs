extern crate getopts;
extern crate pbr;
extern crate hex;
#[macro_use] extern crate text_io;

use std::env;
use std::path::Path;
use std::process::exit;
use std::io::{self, Write};
use std::time::{Duration, Instant};
use getopts::Options;
use pbr::ProgressBar;
use crypto::scrypt::{scrypt, ScryptParams};
use humantime::format_duration;

#[derive(Debug)]
struct ScryptKDFOptions {
    log_n: u8,
    r: u32,
    p: u32,
    iterations: u32,
    keysize: usize
}

struct TestScryptKDFOptions {
    opts: ScryptKDFOptions,
    secret: &'static str
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

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

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} v{} [options]", program, VERSION);
    print!("{}", opts.usage(&brief));
}

fn print_version(program: &str) {
    print!("{} v{}", program, VERSION);
}

fn get_options() -> Options {
    let mut opts = Options::new();
    opts.optopt("i", "iterations", &format!("set the number of required iterations (default: {})",
        DEFAULT_OPTIONS.iterations), "ITER");
    opts.optopt("n", "logn", &format!("set the log2 of the work factor (default: {})", DEFAULT_OPTIONS.log_n), "LOGN");
    opts.optopt("r", "blocksize", &format!("set the blocksize parameter (default: {})", DEFAULT_OPTIONS.r), "R");
    opts.optopt("p", "parallel", &format!("set the parallelization parameter (default: {})", DEFAULT_OPTIONS.p), "P");
    opts.optopt("k", "keysize", &format!("set the length of the derived (default: {})", DEFAULT_OPTIONS.keysize), "SIZE");
    opts.optflag("t", "test", "print test vectors");
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("v", "version", "print version information");

    opts
}

fn parse_options() -> ScryptKDFOptions {
    let opts = get_options();
    let args: Vec<String> = env::args().collect();
    let program = Path::new(&args[0]).file_name().unwrap().to_str().unwrap();

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if matches.opt_present("v") {
        print_version(&program);
        exit(0);
    }

    if matches.opt_present("h") {
        print_usage(&program, &opts);
        exit(0);
    }

    if matches.opt_present("t") {
        print_test_vectors();
        exit(0);
    }

    let iterations = matches.opt_str("i")
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(DEFAULT_OPTIONS.iterations);

    let log_n = matches.opt_str("n")
        .and_then(|o| o.parse::<u8>().ok())
        .unwrap_or(DEFAULT_OPTIONS.log_n);

    let r = matches.opt_str("r")
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(DEFAULT_OPTIONS.r);

    let p = matches.opt_str("p")
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(DEFAULT_OPTIONS.p);

    let keysize = matches.opt_str("k")
        .and_then(|o| o.parse::<usize>().ok())
        .unwrap_or(DEFAULT_OPTIONS.keysize);
    if keysize > MAX_KDF_SIZE {
        println!("Keysize ({}) must be lower than {}", keysize, MAX_KDF_SIZE);
        exit(-1);
    }

    ScryptKDFOptions {
        log_n: log_n,
        r: r,
        p: p,
        iterations: iterations,
        keysize: keysize
    }
}

fn get_salt() -> String {
    print!("Enter your salt: ");
    io::stdout().flush().unwrap();

    read!()
}

fn get_secret() -> String {
    let pass = rpassword::prompt_password_stdout("Enter your secret: ").unwrap();
    let pass2 = rpassword::prompt_password_stdout("Enter your secret again: ").unwrap();

    println!();

    if pass != pass2 {
        println!("Secrets don't match!");
        exit(-1);
    }

    String::from(pass)
}

fn print_test_vectors() {
    println!("Printing test vectors...");
    println!();

    for test_vector in TEST_VECTORS {
        let key = derive(&test_vector.opts, "", &test_vector.secret);

        println!("Key for test vector \"{}\" is: \n{}", test_vector.secret, hex::encode(&key as &[u8]));
        println!();
    }
}

fn derive(opts: &ScryptKDFOptions, salt: &str, secret: &str) -> Vec<u8> {
    println!("Deriving with settings: log_n={}, r={}, p={}, iterations={}, keysize={}", opts.log_n, opts.r, opts.p,
        opts.iterations, opts.keysize);

    let mut pb = ProgressBar::new(opts.iterations as u64);
    pb.show_speed = false;

    let mut res: Vec<u8> = secret.as_bytes().to_vec();

    let start = Instant::now();
    for _ in 0..opts.iterations {
        pb.message("Processing: ");
        pb.tick();

        res = derive_scrypt(&opts, salt.as_bytes(), &res);

        pb.inc();
    }

    pb.finish_println(&format!("Finished in {}\n", format_duration(Duration::new(start.elapsed().as_secs(), 0))
        .to_string()));

    res
}

fn derive_scrypt(opts: &ScryptKDFOptions, salt: &[u8], secret: &Vec<u8>) -> Vec<u8> {
    let mut dk = vec![0; opts.keysize];
    let params: ScryptParams = ScryptParams::new(opts.log_n, opts.r, opts.p);
    scrypt(secret, salt, &params, &mut dk);

    dk.to_vec()
}

fn main() {
    let opts = parse_options();

    let salt = get_salt();
    let secret = get_secret();

    let key = derive(&opts, &salt, &secret);
    println!("Key is: {}", hex::encode(&key as &[u8]));
    println!();
}
