extern crate hex;
extern crate pbr;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod scrypt_kdf;

use crate::scrypt_kdf::{ScryptKDF, ScryptKDFOptions, TEST_VECTORS};
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    style::Stylize,
    Result,
};
use humantime::format_duration;
use pbr::ProgressBar;
use scrypt_kdf::{DEFAULT_SCRYPT_KDF_OPTIONS, MAX_KDF_LEN, MIN_KDF_LEN};
use std::{
    env,
    io::{self, Write},
    process::exit,
    time::{Duration, Instant},
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help = true, disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Derive a key using Scrypt KDF")]
    Derive {
        #[arg(short, long, default_value = DEFAULT_SCRYPT_KDF_OPTIONS.iterations.to_string(), help = format!("Number of iterations (must be greater than 0 and less than or equal to {})", u32::MAX))]
        iterations: u32,

        #[arg(short = 'n', default_value = DEFAULT_SCRYPT_KDF_OPTIONS.log_n.to_string(), help = format!("CPU/memory cost parameter (must be less than {})", usize::BITS))]
        log_n: u8,

        #[arg(short, default_value = DEFAULT_SCRYPT_KDF_OPTIONS.r.to_string(), help = format!("Block size parameter, which fine-tunes sequential memory read size and performance (must be greater than 0 and less than or equal to {})", u32::MAX))]
        r: u32,

        #[arg(short, default_value = DEFAULT_SCRYPT_KDF_OPTIONS.p.to_string(), help = format!("Parallelization parameter (must be greater than 0 and less than {})", u32::MAX))]
        p: u32,

        #[arg(short, long, default_value = DEFAULT_SCRYPT_KDF_OPTIONS.len.to_string(), help = format!("Length of the derived result (must be greater than {} and less than or equal to {})", MIN_KDF_LEN - 1, MAX_KDF_LEN))]
        length: u8,
    },

    #[command(about = "Print test vectors")]
    Test {},
}

fn read_line() -> Result<String> {
    let mut line = String::new();
    while let Event::Key(KeyEvent { code, .. }) = event::read()? {
        match code {
            KeyCode::Enter => {
                break;
            },
            KeyCode::Char(c) => {
                line.push(c);
            },
            _ => {},
        }
    }

    Ok(line)
}

fn get_salt() -> String {
    print!("Enter your salt: ");

    io::stdout().flush().unwrap();

    read_line().unwrap()
}

fn get_secret() -> String {
    let pass = rpassword::prompt_password("Enter your secret: ").unwrap();
    let pass2 = rpassword::prompt_password("Enter your secret again: ").unwrap();

    println!();

    if pass != pass2 {
        println!("Secrets don't match!");
        exit(-1);
    }

    pass
}

fn main() {
    better_panic::install();
    color_backtrace::install();

    println!("Scrypt KDF v{VERSION}\n");

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Derive {
            iterations,
            log_n,
            r,
            p,
            length,
        }) => {
            println!(
                "Parameters: {} (log_n: {}, r: {}, p: {}, len: {})\n",
                "Scrypt".yellow(),
                log_n.to_string().cyan(),
                r.to_string().cyan(),
                p.to_string().cyan(),
                length.to_string().cyan(),
            );

            let salt = get_salt();
            let secret = get_secret();

            let mut pb = ProgressBar::new(u64::from(*iterations));
            pb.show_speed = false;
            pb.message("Processing: ");
            pb.tick();

            let start = Instant::now();

            let opts = ScryptKDFOptions {
                log_n: *log_n,
                r: *r,
                p: *p,
                len: *length,
                iterations: *iterations,
            };
            let kdf = ScryptKDF::new(&opts);

            let res = kdf.derive_key_with_callback(&salt, &secret, || {
                pb.inc();
            });

            println!("Key is (please highlight to see): ");
            println!("{}", hex::encode(&res as &[u8]).black().on_black());

            pb.finish_println(&format!(
                "Finished in {}\n",
                format_duration(Duration::new(start.elapsed().as_secs(), 0))
                    .to_string()
                    .cyan()
            ));
        },

        Some(Commands::Test {}) => {
            for test_vector in TEST_VECTORS.iter() {
                println!(
                    "Test vector parameters: {} (log_n: {}, r: {}, p: {}, iterations: {}, len: {}), salt: \"{}\", secret: \"{}\"",
                    "Scrypt".yellow(),
                    test_vector.opts.log_n.to_string().cyan(),
                    test_vector.opts.r.to_string().cyan(),
                    test_vector.opts.p.to_string().cyan(),
                    test_vector.opts.iterations.to_string().cyan(),
                    test_vector.opts.len.to_string().cyan(),
                    test_vector.salt.to_string().cyan(),
                    test_vector.secret.to_string().cyan(),
                );

                let kdf = ScryptKDF::new(&test_vector.opts);
                let key = kdf.derive_key(test_vector.salt, test_vector.secret);

                println!("Derived key: {}", hex::encode(&key).cyan());

                println!();
            }
        },
        None => {},
    }
}
