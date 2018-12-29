extern crate getopts;
use getopts::Options;
use std::env;
use std::path::Path;
use std::process::exit;

static VERSION: &'static str = "0.1.0";
static DEFAULT_ITERATIONS: u32 = 100;
static DEFAULT_N: u32 = 1048576;
static DEFAULT_R: u32 = 8;
static DEFAULT_P: u32 = 1;

#[derive(Debug)]
struct ScryptKDFOptions {
    n: u32,
    r: u32,
    p: u32,
    iterations: u32,
    salt: String
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} v{} [options]", program, VERSION);
    print!("{}", opts.usage(&brief));
}

fn print_version(program: &str) {
    print!("{} v{}", program, VERSION);
}

fn get_options() -> Options {
    let mut opts = Options::new();
    opts.optopt("i", "iterations", "set the number of required iterations", "ITER");
    opts.optopt("s", "salt", "set the salt to protect against Rainbow table attacks", "SALT");
    opts.optopt("n", "work-factor", "set the work factor", "N");
    opts.optopt("r", "blocksize", "set the blocksize parameter", "R");
    opts.optopt("p", "parallelization", "set the parallelization parameter", "P");
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
        exit(-1);
    }

    if matches.opt_present("h") {
        print_usage(&program, opts);
        exit(-1);
    }

    let iterations = matches.opt_str("i")
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(DEFAULT_ITERATIONS);
    let salt = match matches.opt_str("s") {
        Some(s) => s,
        None => {
            print_usage(&program, opts);
            exit(-1);
        }
    };
    let n = matches.opt_str("n")
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(DEFAULT_N);
    let r = matches.opt_str("r")
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(DEFAULT_R);
    let p = matches.opt_str("p")
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(DEFAULT_P);

    ScryptKDFOptions {
        n: n,
        r: r,
        p: p,
        iterations: iterations,
        salt: salt
    }
}

fn get_secret() -> String {
    let pass = rpassword::prompt_password_stdout("Enter your secret: ").unwrap();
    let pass2 = rpassword::prompt_password_stdout("Enter your secret again: ").unwrap();

    if pass != pass2 {
        println!("Secrets don't match!");
        exit(-1);
    }

    String::from(pass)
}

fn main() {
    let opts = parse_options();
    println!("Working with {:?}", opts);

    let secret = get_secret();
    println!("Your secret is {}", secret);
}
