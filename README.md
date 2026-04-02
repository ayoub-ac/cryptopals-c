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
