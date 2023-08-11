extern crate hex;
extern crate pbr;

#[macro_use]
extern crate lazy_static;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod scrypt_kdf;

use crate::scrypt_kdf::{ScryptKDF, ScryptKDFOptions, TEST_VECTORS};
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    style::Stylize,
};
use humantime::format_duration;
use pbr::ProgressBar;
use scrypt_kdf::{DEFAULT_SCRYPT_KDF_OPTIONS, MAX_KDF_LEN, MIN_KDF_LEN};
use std::{
    env,
    io::{self, Result, Write},
    process::exit,
    sync::{Arc, Mutex},
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

        #[arg(short, long, default_value = DEFAULT_SCRYPT_KDF_OPTIONS.length.to_string(), help = format!("Length of the derived result (must be greater than {} and less than or equal to {})", MIN_KDF_LEN - 1, MAX_KDF_LEN))]
        length: u8,

        #[arg(
            long,
            default_value = "0",
            help = "Start the derivation from this index. In order to use it, you also have to specify the intermediary offset data in hex format"
        )]
        offset: u32,

        #[arg(long, help = "Start the derivation with this intermediary data in hex format")]
        offset_data: Option<String>,
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

fn get_salt() -> Vec<u8> {
    print!("Enter your salt: ");

    io::stdout().flush().unwrap();

    read_line().unwrap().as_bytes().to_vec()
}

fn get_secret() -> Vec<u8> {
    let pass = rpassword::prompt_password("Enter your secret: ").unwrap();
    let pass2 = rpassword::prompt_password("Enter your secret again: ").unwrap();

    if pass != pass2 {
        println!();
        println!("Secrets don't match!");

        exit(-1);
    }

    pass.as_bytes().to_vec()
}

fn main() {
    better_panic::install();
    color_backtrace::install();

    println!("Scrypt KDF v{VERSION}");
    println!();

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Derive {
            iterations,
            log_n,
            r,
            p,
            length,
            offset,
            offset_data,
        }) => {
            println!(
                "Parameters: {} (log_n: {}, r: {}, p: {}, length: {})",
                "Scrypt".yellow(),
                log_n.to_string().cyan(),
                r.to_string().cyan(),
                p.to_string().cyan(),
                length.to_string().cyan(),
            );
            println!();

            // Register a termination handler to output intermediary results
            let last_iteration_ref = Arc::new(Mutex::new(0));
            let last_result_ref = Arc::new(Mutex::new(String::new()));

            let last_iteration = last_iteration_ref.clone();
            let last_result = last_result_ref.clone();

            ctrlc::set_handler(move || {
                println!();
                println!();
                println!(
                    "Terminated. To resume, please specify --offset {} and --offset-data (please highlight to see) {}",
                    *last_iteration.lock().unwrap() + 1,
                    last_result.lock().unwrap().clone().black().on_black()
                );

                exit(-1);
            })
            .expect("Error setting termination handler");

            let salt = get_salt();

            let data: Vec<u8>;
            if *offset != 0 {
                data = match offset_data {
                    Some(data) => {
                        println!();
                        println!("Resuming from iteration {offset} with intermediary offset data {data}. Secret input isn't be required");
                        println!();

                        hex::decode(data).unwrap()
                    },

                    None => {
                        panic!("Missing intermediary offset data");
                    },
                }
            } else {
                data = get_secret();

                println!();
            }

            let mut pb = ProgressBar::new(u64::from(*iterations - *offset));
            pb.show_speed = false;
            pb.message("Processing: ");
            pb.tick();

            let start_time = Instant::now();

            let opts = ScryptKDFOptions {
                log_n: *log_n,
                r: *r,
                p: *p,
                length: *length,
                iterations: *iterations,
            };
            let kdf = ScryptKDF::new(&opts);

            let last_iteration2 = last_iteration_ref;
            let last_result2 = last_result_ref;
            let res = kdf.derive_key_with_callback(&salt, &data, *offset, |i, res| {
                *last_iteration2.lock().unwrap() = i;
                *last_result2.lock().unwrap() = hex::encode(res);

                pb.inc();
            });

            println!();
            println!();
            println!(
                "Key is (please highlight to see): {}",
                hex::encode(res).black().on_black()
            );

            pb.finish_println(&format!(
                "Finished in {}\n",
                format_duration(Duration::new(start_time.elapsed().as_secs(), 0))
                    .to_string()
                    .cyan()
            ));
        },

        Some(Commands::Test {}) => {
            for test_vector in TEST_VECTORS.iter() {
                println!(
                    "Test vector parameters: {} (log_n: {}, r: {}, p: {}, iterations: {}, length: {}), salt: \"{}\", secret: \"{}\"",
                    "Scrypt".yellow(),
                    test_vector.opts.log_n.to_string().cyan(),
                    test_vector.opts.r.to_string().cyan(),
                    test_vector.opts.p.to_string().cyan(),
                    test_vector.opts.iterations.to_string().cyan(),
                    test_vector.opts.length.to_string().cyan(),
                    hex::encode(&test_vector.salt).cyan(),
                    hex::encode(&test_vector.secret).cyan(),
                );

                let kdf = ScryptKDF::new(&test_vector.opts);
                let key = kdf.derive_key(&test_vector.salt, &test_vector.secret, 0);

                println!("Derived key: {}", hex::encode(&key).cyan());

                println!();
            }
        },
        None => {},
    }
}
