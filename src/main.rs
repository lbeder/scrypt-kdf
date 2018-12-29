extern crate getopts;
use getopts::Options;
use std::env;
use std::path::Path;
use std::process::exit;

static VERSION: &'static str = "0.1.0";
static DEFAULT_ITERATIONS: usize = 100;
static DEFAULT_N: usize = 1048576;
static DEFAULT_R: usize = 8;
static DEFAULT_P: usize = 1;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} v{} [options]", program, VERSION);
    print!("{}", opts.usage(&brief));
}

fn print_version(program: &str) {
    print!("{} v{}", program, VERSION);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = Path::new(&args[0]).file_name().unwrap().to_str().unwrap();

    let mut opts = Options::new();
    opts.optopt("i", "iterations", "set the number of required iterations", "ITER");
    opts.optopt("s", "salt", "set the salt to protect against Rainbow table attacks", "SALT");
    opts.optopt("n", "work-factor", "set the work factor", "N");
    opts.optopt("r", "blocksize", "set the blocksize parameter", "R");
    opts.optopt("p", "parallelization", "set the parallelization parameter", "P");
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("v", "version", "print version information");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if matches.opt_present("v") {
        print_version(&program);
        return;
    }

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let iterations = matches.opt_str("i")
        .and_then(|o| o.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ITERATIONS);
    let salt = match matches.opt_str("s") {
        Some(s) => s,
        None => {
            print_usage(&program, opts);
            exit(-1);
        }
    };
    let n = matches.opt_str("n")
        .and_then(|o| o.parse::<usize>().ok())
        .unwrap_or(DEFAULT_N);
    let r = matches.opt_str("r")
        .and_then(|o| o.parse::<usize>().ok())
        .unwrap_or(DEFAULT_R);
    let p = matches.opt_str("p")
        .and_then(|o| o.parse::<usize>().ok())
        .unwrap_or(DEFAULT_P);

    println!("Working with parameters: n={}, r={}, p={}, iterations={}", n, r, p, iterations);
}
