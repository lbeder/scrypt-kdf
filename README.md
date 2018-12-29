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

Test settings:

* Log N: 14
* R: 8
* P: 1
* Salt: empty

Test vectors:

* "" (the empty string)
* "Hello World"

Result should be:

```bash
Printing test vectors...

Deriving with settings: log_n=14, r=8, p=1, iterations=1, keysize=128
Processing: 1 / 1 [=============================================================================================================] 100.00 %
Key for test vector "" is:
d72c87d0f077c7766f2985dfab30e8955c373a13a1e93d315203939f542ff86e73ee37c31f4c4b571f4719fa8e3589f12db8dcb57ea9f56764bb7d58f64cf705f1f64bdd91c35da954a6fb7896f1839e6ba03f68f08b686527f9f1588ab103c22152046258e2d679842252afeb3cd6eb4e01fe9c285eb916da7e4b7a39ee5eba

Deriving with settings: log_n=14, r=8, p=1, iterations=1, keysize=128
Processing: 1 / 1 [=============================================================================================================] 100.00 %
Key for test vector "Hello World" is:
d6aae043efe8db5bd7cf851ae2099b7a599d6e133bfdd0e70e41407a3097cdf47e381e0392afbdc76f2875ecf969b72d1b483d893660d2764272b07002f0b81b3b710f4ae66d4fa260e9fc6c62b911b6ce7b6095a2a5ac4eb0f63b2f52e689ee33d5278498549c6d87d567ec6cb9580762c421669d07b79188d35af0508ea54e
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
