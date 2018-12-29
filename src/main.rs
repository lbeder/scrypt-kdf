extern crate getopts;
extern crate pbr;
extern crate hex;
#[macro_use] extern crate text_io;

use getopts::Options;
use std::env;
use std::path::Path;
use std::process::exit;
use std::io::{self, Write};
use pbr::ProgressBar;
use crypto::scrypt::{scrypt, ScryptParams};

#[derive(Debug)]
struct ScryptKDFOptions {
    log_n: u8,
    r: u32,
    p: u32,
    iterations: u32
}

const VERSION: &'static str = "0.1.0";

const DEFAULT_OPTIONS: ScryptKDFOptions = ScryptKDFOptions {
    log_n: 15,
    r: 8,
    p: 1,
    iterations: 50
};

const TEST_OPTIONS: ScryptKDFOptions = ScryptKDFOptions {
    log_n: 14,
    r: 8,
    p: 1,
    iterations: 1
};

const TEST_VECTORS: &'static [&'static str] = &["", "Hello World"];

const KDF_SIZE: usize = 128;

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

    ScryptKDFOptions {
        log_n: log_n,
        r: r,
        p: p,
        iterations: iterations
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

    for test in TEST_VECTORS {
        let key = derive(&TEST_OPTIONS, "", test);

        println!("Key for test vector \"{}\" is: \n{}", test, hex::encode(&key as &[u8]));
        println!();
    }
}

fn derive(opts: &ScryptKDFOptions, salt: &str, secret: &str) -> [u8; KDF_SIZE] {
    println!("Deriving with settings: {:?}", opts);

    let mut pb = ProgressBar::new(opts.iterations as u64);
    pb.show_speed = false;

    let mut res = secret.as_bytes();
    let mut next_res = [0u8; KDF_SIZE];
    for _ in 0..opts.iterations {
        pb.message("Processing: ");
        pb.tick();

        next_res = derive_scrypt(&opts, salt.as_bytes(), &res);
        res = &next_res[..];

        pb.inc();
    }

    pb.finish_println("");

    next_res
}

fn derive_scrypt(opts: &ScryptKDFOptions, salt: &[u8], secret: &[u8]) -> [u8; KDF_SIZE] {
    let mut dk = [0u8; KDF_SIZE];
    let params: ScryptParams = ScryptParams::new(opts.log_n, opts.r, opts.p);
    scrypt(secret, salt, &params, &mut dk);

    dk
}

fn main() {
    let opts = parse_options();

    let salt = get_salt();
    let secret = get_secret();

    let key = derive(&opts, &salt, &secret);
    println!("Key is: \n{}", hex::encode(&key as &[u8]));
    println!();
}
