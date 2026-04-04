# Cryptopals Crypto Challenges in C

Solutions to the [Cryptopals Crypto Challenges](https://cryptopals.com/) written in C.

Uses CMake and GTest. Developed on Linux.

## Build & Test

```bash
mkdir build && cd build
cmake ..
make
ctest --output-on-failure
```

## Project structure

```
├── CMakeLists.txt
├── include/           # headers (.h)
├── src/               # source code (.c)
├── tests/             # tests (.cpp)
└── notes/             # explanations
```

## Challenges

### Set 1 — Basics
| # | Challenge |
|---|-----------|
| 1 | Hex to Base64 |
| 2 | Fixed XOR |
| 3 | Single-byte XOR cipher |
| 4 | Detect single-char XOR |
| 5 | Repeating-key XOR |
| 6 | Break repeating-key XOR |
| 7 | AES in ECB mode |
| 8 | Detect AES in ECB |

### Set 2 — Block Crypto
| # | Challenge |
|---|-----------|
| 9 | PKCS#7 padding |
| 10 | Implement CBC mode |
| 11 | ECB/CBC detection oracle |
| 12 | Byte-at-a-time ECB decryption |
