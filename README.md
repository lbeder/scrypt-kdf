# scrypt-kdf

Scrypt Key Derivation Function in Rust

## Build

```bash
git clone https://github.com/lbeder/scrypt-kdf
cd scrypt-kdf

cargo build --release
```

## Usage

```bash
Usage: scrypt-kdf v0.1.1 [options]

Options:
    -i, --iterations ITER
                        set the number of required iterations (default: 50)
    -n, --logn LOGN     set the log2 of the work factor (default: 15)
    -r, --blocksize R   set the blocksize parameter (default: 8)
    -p, --parallel P    set the parallelization parameter (default: 1)
    -k, --keysize SIZE  set the length of the derived (default: 16)
    -t, --test          print test vectors
    -h, --help          print this help menu
    -v, --version       print version information
```

## Example

Let's try to derive the key for the secret `test`, using the salt `salt`:

> ././target/release/scrypt-kdf

Progress status:

```bash
Enter your salt: salt
Enter your secret:
Enter your secret again:

Deriving with settings: log_n=15, r=8, p=1, iterations=50, , keysize=16
Processing: 3 / 50 [======>-----------------------------------------------------------------------------------------------------] 6.00 % 7m
```

Final result:

```bash
Enter your salt: salt
Enter your secret:
Enter your secret again:

Deriving with settings: log_n=15, r=8, p=1, iterations=50, keysize=16
Processing: 50 / 50 [===========================================================================================================] 100.00 %
Key is: 762a2496890c831a63f2094a95d1b699
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
Key for test vector "" is:
d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e73ee37c31f4c4b571f4719fa8e3589f12db8dcb57ea9f56764bb7d58f64cf705f1f64bdd91c35da954a6fb7896f1839e6ba03f68f08b686527f9f1588ab103c22152046258e2d679842252afeb3cd6eb4e01fe9c285eb916da7e4b7a39ee5eba

Deriving with settings: log_n=14, r=8, p=1, iterations=3, keysize=128
Processing: 3 / 3 [=============================================================================================================] 100.00 %
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
