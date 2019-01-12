# scrypt-kdf

Scrypt Key Derivation Function in Rust

## Usage

```bash
Usage: scrypt-kdf v0.3.3 [options]

Options:
    -i, --iterations ITER
                        set the number of required iterations (default: 100)
    -n, --logn LOGN     set the log2 of the work factor (default: 20)
    -r, --blocksize R   set the blocksize parameter (default: 8)
    -p, --parallel P    set the parallelization parameter (default: 1)
    -k, --keysize SIZE  set the length of the derived (default: 16)
    -t, --test          print test vectors
    -h, --help          print this help menu
    -v, --version       print version information
```

## Build

### Mac OS

```bash
git clone https://github.com/lbeder/scrypt-kdf
cd scrypt-kdf

cargo build --release
```

### Linux x86_x64

In order to get stuff working later, use the `nightly` branch of Rust:

```bash
rustup override set nightly
```

Install a standard Linux target on a Mac (note, that the opposite is currently impossible):

```bash
rustup target add x86_64-unknown-linux-musl
```

Use `homebrew` to download a community-provided binary for `musl` cross-compilation:

```bash
brew install FiloSottile/musl-cross/musl-cross
```

Now you can build it:

```bash
CROSS_COMPILE=x86_64-linux-musl- cargo build --target=x86_64-unknown-linux-musl
```

## Example

Let's try to derive the key for the secret `test`, using the salt `salt`:

> ./target/release/scrypt-kdf

Progress status:

```bash
Enter your salt: salt
Enter your secret: 🔑
Enter your secret again: 🔑

Deriving with settings: log_n=20, r=8, p=1, iterations=100, keysize=16
Processing: 3 / 100 [======>-----------------------------------------------------------------------------------------------------] 6.00 % 7m
```

Final result:

```bash
Enter your salt: salt
Enter your secret: 🔑
Enter your secret again: 🔑

Deriving with settings: log_n=20, r=8, p=1, iterations=100, keysize=16
Processing: 100 / 100 [=======================================================================================================================================] 100.00 %
Finished in 5m 6s
Key is (please highlight to see): ff08101f061aa670158601bf5be5efa6
```

## Test Vectors

In order to verify the validity of the Scrypt calculation, you can pass the `-t/--test` flag.

Test vectors:

### #1

* Secret: "" (the empty string)
* Salt: empty
* Parameters:
  * Log N: 14
  * R: 8
  * P: 1
  * Key size: 128
* Iterations: 1

### #2

* Secret: "Hello World"
* Salt: empty
* Parameters:
  * Log N: 14
  * R: 8
  * P: 1
  * Key size: 128
* Iterations: 3

Results should be:

```bash
Printing test vectors...

Deriving with settings: log_n=14, r=8, p=1, iterations=1, keysize=128
Processing: 1 / 1 [=============================================================================================================] 100.00 %
Finished in 4s
Key for test vector "" is:
d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e73ee37c31f4c4b571f4719fa8e3589f12db8dcb57ea9f56764bb7d58f64cf705f1f64bdd91c35da954a6fb7896f1839e6ba03f68f08b686527f9f1588ab103c22152046258e2d679842252afeb3cd6eb4e01fe9c285eb916da7e4b7a39ee5eba

Deriving with settings: log_n=14, r=8, p=1, iterations=3, keysize=128
Processing: 3 / 3 [=============================================================================================================] 100.00 %
Finished in 14s
Key for test vector "Hello World" is:
38f3b062f703aa0c958fc8944c9f005f1bd03a056048d5cdc6186979e4c178504050580fab8744c0272253f7df87a2e2f9bb5449a2361f0fed5105ea549e86e41f68d8b160cda5ca91e020067b0c53fc20ae19993e1f40db60d8963ec8c7c0fe74d48a44f1f78a4259f0376f6d7dd2c07d2e7aaae023b8bdfa87ddbf503fe9a3
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
