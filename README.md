# scrypt-kdf

[![Build Status](https://github.com/lbeder/scrypt-kdf/actions/workflows/ci.yml/badge.svg)](https://github.com/lbeder/scrypt-kdf/actions/workflows/ci.yml)

Scrypt Key Derivation Function in Rust

## Usage

### General

```sh
Usage: scrypt-kdf [COMMAND]

Commands:
  derive        Derive a value using Scrypt KDF
  test-vectors  Print test vectors

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Deriving

```sh
Derive a value using Scrypt KDF

Usage: scrypt-kdf derive --iterations <ITERATIONS> --log-n <LOG_N> --r <R> --p <P> --l <L>

Options:
  -i, --iterations <ITERATIONS>  Number of iterations [default: 100]
  -l, --log-n <LOG_N>            Work factor [default: 20]
  -r, --r <R>                    Block size [default: 8]
  -p, --p <P>                    Parallelization parameter [default: 1]
  -l, --l <L>                    Length of the derived result [default: 16]
  -h, --help                     Print help
```

### Printing Test Vectors

```sh
Print test vectors

Usage: scrypt-kdf test-vectors

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

## Example

Let's try to derive the key for the secret `test`, using the salt `salt`:

> scrypt-kdf derive

```sh
Scrypt KDF v0.10.0

Parameters: Scrypt (log_n: 20, r: 8, p: 1, len: 16)

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

Key is (please highlight to see):
16e27a594f879ec5edbc3c1995907b49

Finished in 3m 29s
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
Printing test vectors...

Deriving with settings:
    CPU/memory cost parameter (log(n)): 14
    Block size parameter (r): 8
    Parallelization parameter (p): 1
    Iterations: 1
    Length: 64

Key for test vector "" is:
d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e73ee37c31f4c4b571f4719fa8e3589f12db8dcb57ea9f56764bb7d58f64cf705f1f64bdd91c35da954a6fb7896f1839e6ba03f68f08b686527f9f1588ab103c22152046258e2d679842252afeb3cd6eb4e01fe9c285eb916da7e4b7a39ee5eba

Deriving with settings:
    CPU/memory cost parameter (log(n)): 14
    Block size parameter (r): 8
    Parallelization parameter (p): 1
    Iterations: 3
    Length: 64

Key for test vector "Hello World" is:
38f3b062f703aa0c958fc8944c9f005f1bd03a056048d5cdc6186979e4c178504050580fab8744c0272253f7df87a2e2f9bb5449a2361f0fed5105ea549e86e41f68d8b160cda5ca91e020067b0c53fc20ae19993e1f40db60d8963ec8c7c0fe74d48a44f1f78a4259f0376f6d7dd2c07d2e7aaae023b8bdfa87ddbf503fe9a3

Test vector parameters: Scrypt (log_n: 14, r: 8, p: 1, iterations: 1, len: 64)
Key for test vector "" is: d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e73ee37c31f4c4b571f4719fa8e3589f12db8dcb57ea9f56764bb7d58f64cf705

Test vector parameters: Scrypt (log_n: 14, r: 8, p: 1, iterations: 3, len: 64)
Key for test vector "Hello World" is: 1487e1ac9c7a63e785b1f3e9560ea749913d50c9797dc6ca8d0db953fe03df1c66af878bd6dcce79884e8b7e3e29f39cb709cd63b7e7f4099d82ab199664eab3

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
