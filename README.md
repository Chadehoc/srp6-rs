# Secure Remote Password SRP 6a implementation

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Implementation of the secure remote password authentication and key-exchange
protocol SRP version 6a as in [RFC5054].

This is a heavily reworked fork of <https://github.com/valpaq/srp6-rs>, which was
itself a fork of <https://github.com/sassman/srp6-rs>, which was published as the
[srp6-rs crate](https://docs.rs/srp6).

Constant-time computations are done using [crypto-bigint], at the price of a high
performance penalty.

Since then I found there is a [srp crate](https://docs.rs/srp/latest/srp/index.html)
maintained by the [Rust Crypto](https://github.com/RustCrypto) group; however
constant-time computations are not yet available there.

## Documentation

The best documentation currently is to
look at the examples and generate the Rustdoc documentation.

## Features

- `emp`: using the [crypto-bigint] crate for constant-time computations
  brings a substantial performance penalty, especially for SRP-4096. This
  feature is intended to isolate micro-optimisations that were only empirically
  validated (fuzzing included).

## Fuzzing

The provided `srp` target (`cargo +nightly fuzz run srp`) is used with the `emp`
feature activated, and SRP-2048 only.

## License

- **[MIT License](LICENSE)**
- Copyright 2021 © [Sven Assmann](https://www.d34dl0ck.me)
- Copyright 2025 © Chadehoc

[RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054#appendix-A
[crypto-bigint]: https://docs.rs/crypto-bigint/latest/crypto_bigint/index.html
