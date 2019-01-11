extern crate getopts;
extern crate pbr;
extern crate hex;
extern crate crossterm;

mod scrypt_kdf;

use std::env;
use std::path::Path;
use std::process::exit;
use std::time::{Duration, Instant};
use getopts::Options;
use pbr::ProgressBar;
use humantime::format_duration;
use crossterm::{terminal::{terminal}, input, style::{Color, style}};

use crate::scrypt_kdf::{ScryptKDF, ScryptKDFOptions};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} v{} [options]", program, VERSION);
    println!("{}", opts.usage(&brief));
}

fn print_version(program: &str) {
    println!("{} v{}", program, VERSION);
}

fn get_options() -> Options {
    let default_options = ScryptKDF::default_options();
    let mut opts = Options::new();
    opts.optopt("i", "iterations", &format!("set the number of required iterations (default: {})",
        default_options.iterations), "ITER");
    opts.optopt("n", "logn", &format!("set the log2 of the work factor (default: {})",
        default_options.log_n), "LOGN");
    opts.optopt("r", "blocksize", &format!("set the blocksize parameter (default: {})",
        default_options.r), "R");
    opts.optopt("p", "parallel", &format!("set the parallelization parameter (default: {})",
        default_options.p), "P");
    opts.optopt("k", "keysize", &format!("set the length of the derived (default: {})",
        default_options.keysize), "SIZE");
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

    let default_options = ScryptKDF::default_options();

    let iterations = matches.opt_str("i")
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(default_options.iterations);

    let log_n = matches.opt_str("n")
        .and_then(|o| o.parse::<u8>().ok())
        .unwrap_or(default_options.log_n);

    let r = matches.opt_str("r")
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(default_options.r);

    let p = matches.opt_str("p")
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(default_options.p);

    let keysize = matches.opt_str("k")
        .and_then(|o| o.parse::<usize>().ok())
        .unwrap_or(default_options.keysize);

    let max_kdf_size = ScryptKDF::max_kdf_size();
    if keysize > max_kdf_size {
        println!("Keysize ({}) must be lower than {}", keysize, max_kdf_size);
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
    terminal().write("Enter your salt: ").unwrap();
    input().read_line().unwrap()
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

    let test_vectors = ScryptKDF::test_vectors();
    let test_keys = ScryptKDF::derive_test_vectors();
    for (i, key) in test_keys.iter().enumerate() {
        println!("Key for test vector \"{}\" is: \n{}\n", test_vectors[i].secret, hex::encode(&key as &[u8]));
    }
}

fn derive(opts: &ScryptKDFOptions, salt: &str, secret: &str) -> Vec<u8> {
    println!("Deriving with settings: log_n={}, r={}, p={}, iterations={}, keysize={}", opts.log_n, opts.r, opts.p,
        opts.iterations, opts.keysize);

    let mut pb = ProgressBar::new(opts.iterations as u64);
    pb.show_speed = false;
    pb.message("Processing: ");
    pb.tick();

    let start = Instant::now();
    let kdf = ScryptKDF::new(&opts);
    let res = kdf.derive_key_with_callback(&salt, &secret, || {
        pb.inc();
    });

    pb.finish_println(&format!("Finished in {}\n", format_duration(Duration::new(start.elapsed().as_secs(), 0))
        .to_string()));

    res
}

fn main() {
    let opts = parse_options();

    let salt = get_salt();
    let secret = get_secret();

    let key = derive(&opts, &salt, &secret);

    print!("Key is (please highlight to see): ");
    println!("{}", style(hex::encode(&key as &[u8])).with(Color::Black).on(Color::Black));
}
