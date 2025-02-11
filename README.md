# Secure Remote Password SRP 6a implementation

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Implementation of the secure remote password authentication and key-exchange
protocol (SRP version 6a).

This is a heavily reworked fork of <https://github.com/valpaq/srp6-rs>, which was
itself a fork of <https://github.com/sassman/srp6-rs>, which was published as the
[srp6-rs crate](https://docs.rs/srp6), which is flawed.

Features:

- Client and server implementation of SRP 6a as in [RFC5054]
- Pure Rust, free of unsafe code
- No openssl dependencies
- Constant-time computations using [crypto-bigint]

## About SRP

> The Secure Remote Password protocol performs secure remote authentication of
> short human-memorizable passwords and resists both passive and active network
> attacks. Because SRP offers this unique combination of password security, user
> convenience, and freedom from restrictive licenses, it is the most widely
> standardized protocol of its type, and as a result is being used by
> organizations both large and small, commercial and open-source, to secure
> nearly every type of human-authenticated network traffic on a variety of
> computing platforms.

Read more at [srp.stanford.edu](http://srp.stanford.edu) and in [RFC2945] that
describes in detail an earlier version of the Secure remote password protocol.

The current implementation follows the enhanced [RFC5054].

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

[RFC2945]: https://datatracker.ietf.org/doc/html/rfc2945
[RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054#appendix-A
[crypto-bigint]: https://docs.rs/crypto-bigint/latest/crypto_bigint/index.html
