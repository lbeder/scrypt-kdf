# scrypt-kdf

[![Build Status](https://github.com/lbeder/scrypt-kdf/actions/workflows/ci.yml/badge.svg)](https://github.com/lbeder/scrypt-kdf/actions/workflows/ci.yml)

Scrypt Key Derivation Function in Rust

## Usage

### General

```sh
Usage: scrypt-kdf [COMMAND]

Commands:
  derive  Derive a value using Scrypt KDF
  test    Print test vectors

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Deriving

```sh
Derive a key using Scrypt KDF

Usage: scrypt-kdf derive [OPTIONS]

Options:
  -i, --iterations <ITERATIONS>    Number of iterations (must be greater than 0 and less than or equal to 4294967295) [default: 100]
  -n <LOG_N>                       CPU/memory cost parameter (must be less than 64) [default: 20]
  -r <R>                           Block size parameter, which fine-tunes sequential memory read size and performance (must be greater than 0 and less than or equal to 4294967295) [default: 8]
  -p <P>                           Parallelization parameter (must be greater than 0 and less than 4294967295) [default: 1]
  -l, --length <LENGTH>            Length of the derived result (must be greater than 9 and less than or equal to 64) [default: 16]
      --offset <OFFSET>            Start the derivation from this index. In order to use it, you also have to specify the intermediary offset data in hex format [default: 0]
      --offset-data <OFFSET_DATA>  Start the derivation with this intermediary data in hex format
      --base64                     Output the result in Base64 (in addition to hex)
      --base58                     Output the result in Base58 (in addition to hex)
  -h, --help                       Print help
```

### Printing Test Vectors

```sh
Print test vectors

Usage: scrypt-kdf test

Options:
  -h, --help  Print help
```

## Build

### Mac OS

```sh
git clone https://github.com/lbeder/scrypt-kdf
cd scrypt-kdf

cargo build --release
```

Depending on whether you are using x64 or arm64, you might need to add either the `x86_64-apple-darwin` or the `aarch64-apple-darwin` target accordingly:

```sh
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
```

### Linux x86_x64

In order to get stuff working later, use the `nightly` branch of Rust:

```sh
rustup override set nightly
```

Install a standard Linux target on a Mac (note, that the opposite is currently impossible):

```sh
rustup target add x86_64-unknown-linux-musl
```

Use `homebrew` to install a community-provided macOS cross-compiler toolchains:

```sh
brew tap messense/macos-cross-toolchains
brew install x86_64-unknown-linux-musl
```

Now you can build it:

```sh
export CC_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-g++
export AR_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-gcc
CROSS_COMPILE=x86_64-linux-musl- cargo build --target=x86_64-unknown-linux-musl
cargo build --target=x86_64-unknown-linux-musl
```

### For Windows

In order to get stuff working later, use the `nightly` branch of Rust:

```sh
rustup override set nightly
```

Install the standard Windows target on a Mac (note, that the opposite is currently impossible):

```sh
rustup target add x86_64-pc-windows-gnu
```

Use `homebrew` to install mingw-w64:

```sh
brew install mingw-w64
```

Now you can build it:

```sh
cargo build --release --target=x86_64-pc-windows-gnu
```

## Examples

Let's try to derive the key for the secret `test`, using the salt `salt`:

> scrypt-kdf derive

```sh
Parameters: Scrypt (log_n: 20, r: 8, p: 1, length: 16)

Enter your salt: salt
Enter your secret: 🔑
Enter your secret again: 🔑

Processing: 12 / 100 [==============>--------------------------------------------------------------------------------------------------------------] 12.00 % 4m
```

Final result:

```sh
Enter your salt: salt
Enter your secret: 🔑
Enter your secret again: 🔑

Processing: 100 / 100 [=======================================================================================================================================] 100.00 %

Key (hex) is (please highlight to see): ff08101f061aa670158601bf5be5efa6

Finished in 3m 29s
```

### Resuming Previous Derivation

To help with resuming previously stopped derivations, we're registering a `CTRL_C`, `CTRL_BREAK`, `SIGINT`, `SIGTERM`, and `SIGHUP` termination handler which will output the intermediary result (if possible).

For example, if we will abort the previous derivation after the `60th` iteration, the tool will output:

```sh
Parameters: Scrypt (log_n: 20, r: 8, p: 1, length: 16)

Enter your salt: salt
Enter your secret: 🔑
Enter your secret again: 🔑

Processing: 60 / 100 [==========================================================================>-------------------------------------------------] 60.00 % 1m

Terminated. To resume, please specify --offset 60 and --offset-data (please highlight to see) 2262d7c10e3806a4926a895f7cf9502b
```

You can then use this output to resume the previous derivation by specifying a starting offset and data like so:

> scrypt-kdf derive --offset 60 --offset-data 2262d7c10e3806a4926a895f7cf9502b

```sh
Parameters: Scrypt (log_n: 20, r: 8, p: 1, length: 16)

Enter your salt: salt

Resuming from iteration 60 with intermediary offset data 2262d7c10e3806a4926a895f7cf9502b. Secret input isn't be required

Processing: 40 / 40 [===============================================================================================================================] 100.00 %

Key (hex) is (please highlight to see): ff08101f061aa670158601bf5be5efa6

Finished in 1m 25s
```

## Test Vectors

In order to verify the validity of the Scrypt calculation, you can pass the `-t/--test` flag.

Test vectors:

### #1

* Secret: "" (the empty string)
* Salt: empty
* Parameters:
  * log_n: 14
  * r: 8
  * p: 1
  * length: 64
* Iterations: 1

### #2

* Secret: "Hello World"
* Salt: empty
* Parameters:
  * log_n: 14
  * r: 8
  * p: 1
  * length: 64
* Iterations: 3

Results should be:

```sh
Test vector parameters: Scrypt (log_n: 14, r: 8, p: 1, iterations: 1, length: 64), salt: "", secret: ""
Derived key: d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e73ee37c31f4c4b571f4719fa8e3589f12db8dcb57ea9f56764bb7d58f64cf705

Test vector parameters: Scrypt (log_n: 14, r: 8, p: 1, iterations: 3, length: 64), salt: "", secret: "Hello World"
Derived key: 1487e1ac9c7a63e785b1f3e9560ea749913d50c9797dc6ca8d0db953fe03df1c66af878bd6dcce79884e8b7e3e29f39cb709cd63b7e7f4099d82ab199664eab3
```

## License

MIT License

Copyright (c) 2018 Leonid Beder

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
