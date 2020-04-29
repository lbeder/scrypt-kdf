extern crate crossterm;
extern crate getopts;
extern crate hex;
extern crate pbr;

mod scrypt_kdf;

use crossterm::style::{style, Color};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    Result,
};
use getopts::Options;
use humantime::format_duration;
use pbr::ProgressBar;
use std::{
    env,
    path::Path,
    process::exit,
    time::{Duration, Instant},
};

use crate::scrypt_kdf::{ScryptKDF, ScryptKDFOptions};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options]\nVersion: {}", program, VERSION);
    println!("{}", opts.usage(&brief));
}

fn print_version(program: &str) {
    println!("{} v{}", program, VERSION);
}

fn get_options() -> Options {
    let kdf_options: ScryptKDFOptions = Default::default();
    let mut opts = Options::new();
    opts.optopt(
        "i",
        "iterations",
        &format!(
            "set the number of required iterations (default: {})",
            kdf_options.iterations
        ),
        "ITER",
    );
    opts.optopt(
        "n",
        "logn",
        &format!("set the log2 of the work factor (default: {})", kdf_options.log_n),
        "LOGN",
    );
    opts.optopt(
        "r",
        "blocksize",
        &format!("set the blocksize parameter (default: {})", kdf_options.r),
        "R",
    );
    opts.optopt(
        "p",
        "parallel",
        &format!("set the parallelization parameter (default: {})", kdf_options.p),
        "P",
    );
    opts.optopt(
        "k",
        "keysize",
        &format!("set the length of the derived (default: {})", kdf_options.keysize),
        "SIZE",
    );
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
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
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

    let mut kdf_options: ScryptKDFOptions = Default::default();

    if matches.opt_present("i") {
        kdf_options.iterations = matches
            .opt_str("i")
            .and_then(|o| o.parse::<u32>().ok())
            .unwrap_or(kdf_options.iterations);
    }

    if matches.opt_present("n") {
        kdf_options.log_n = matches
            .opt_str("n")
            .and_then(|o| o.parse::<u8>().ok())
            .unwrap_or(kdf_options.log_n);
    }

    if matches.opt_present("r") {
        kdf_options.r = matches
            .opt_str("r")
            .and_then(|o| o.parse::<u32>().ok())
            .unwrap_or(kdf_options.r);
    }

    if matches.opt_present("p") {
        kdf_options.p = matches
            .opt_str("p")
            .and_then(|o| o.parse::<u32>().ok())
            .unwrap_or(kdf_options.p);
    }

    if matches.opt_present("k") {
        kdf_options.keysize = matches
            .opt_str("k")
            .and_then(|o| o.parse::<usize>().ok())
            .unwrap_or(kdf_options.keysize);
    }

    let max_kdf_size = ScryptKDF::max_kdf_size();

    if kdf_options.keysize > max_kdf_size {
        println!("Keysize ({}) must be lower than {}", kdf_options.keysize, max_kdf_size);
        exit(-1);
    }

    kdf_options
}

fn read_line() -> Result<String> {
    let mut line = String::new();
    while let Event::Key(KeyEvent { code, .. }) = event::read()? {
        match code {
            KeyCode::Enter => {
                break;
            }
            KeyCode::Char(c) => {
                line.push(c);
            }
            _ => {}
        }
    }

    return Ok(line);
}
fn get_salt() -> String {
    print!("Enter your salt: ");
    read_line().unwrap()
}

fn get_secret() -> String {
    let pass = rpassword::prompt_password_stdout("Enter your secret: ").unwrap();
    let pass2 = rpassword::prompt_password_stdout("Enter your secret again: ").unwrap();

    println!();

    if pass != pass2 {
        println!("Secrets don't match!");
        exit(-1);
    }

    pass
}

fn print_test_vectors() {
    println!("Printing test vectors...");
    println!();

    let test_vectors = ScryptKDF::test_vectors();
    let test_keys = ScryptKDF::derive_test_vectors();
    for (i, key) in test_keys.iter().enumerate() {
        println!(
            "Key for test vector \"{}\" is: \n{}\n",
            test_vectors[i].secret,
            hex::encode(&key as &[u8])
        );
    }
}

fn derive(opts: &ScryptKDFOptions, salt: &str, secret: &str) -> Vec<u8> {
    println!(
        "Deriving with settings: log_n={}, r={}, p={}, iterations={}, keysize={}",
        opts.log_n, opts.r, opts.p, opts.iterations, opts.keysize
    );

    let mut pb = ProgressBar::new(u64::from(opts.iterations));
    pb.show_speed = false;
    pb.message("Processing: ");
    pb.tick();

    let start = Instant::now();
    let kdf = ScryptKDF::new(&opts);
    let res = kdf.derive_key_with_callback(&salt, &secret, || {
        pb.inc();
    });

    pb.finish_println(&format!(
        "Finished in {}\n",
        format_duration(Duration::new(start.elapsed().as_secs(), 0)).to_string()
    ));

    res
}

fn main() {
    let opts = parse_options();

    let salt = get_salt();
    let secret = get_secret();

    let key = derive(&opts, &salt, &secret);

    print!("Key is (please highlight to see): ");
    println!(
        "{}",
        style(hex::encode(&key as &[u8])).with(Color::Black).on(Color::Black)
    );
}
