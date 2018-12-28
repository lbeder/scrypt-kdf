extern crate getopts;
use getopts::Options;
use std::env;
use std::path::Path;

static VERSION: &'static str = "0.1.0";
static DEFAULT_ITERATIONS: u32 = 100;

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
        .and_then(|o| o.parse::<u32>().ok())
        .unwrap_or(DEFAULT_ITERATIONS);

    println!("Iterations {}", iterations);
}
