# Secure Remote Password (SRP 6 / 6a)

**This is a fork of a fork (<https://github.com/valpaq/srp6-rs>), the original
published repository is (<https://github.com/sassman/srp6-rs>).**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Implementation of the secure remote password authentication and key-exchange
protocol (SRP version 6a).

The first fork had flaws for use in a real client-server setting:
illogical serialization directions, funny constants for 2048 version,
changes in protocol, big/little-endian errors...

The second fork fixed many things, but remained incomplete and not directly
usable with a true client and server (instead of a simulation in examples).

## About SRP

> The Secure Remote Password protocol performs secure remote authentication of
> short human-memorizable passwords and resists both passive and active network
> attacks. Because SRP offers this unique combination of password security, user
> convenience, and freedom from restrictive licenses, it is the most widely
> standardized protocol of its type, and as a result is being used by
> organizations both large and small, commercial and open-source, to secure
> nearly every type of human-authenticated network traffic on a variety of
> computing platforms.

read more at [srp.stanford.edu](http://srp.stanford.edu) and in [RFC2945] that describes in detail the Secure remote password protocol.

## Features

- client and server implementation of SRP 6 / 6a as in [RFC2945]
- key length of 2048 to 4096 bit provided as in [RFC5054]
- free of unsafe code
- no openssl dependencies
- rust native

## Documentation

The current crate is a fork of a fork. The best documentation currently is to
look at the examples, and especially unit test code in lib.rs.

The documentation of the original crate (<https://github.com/sassman/srp6-rs>)
is at:

- [official crate docs](https://docs.rs/srp6)
- [examples of usage](https://github.com/sassman/srp6-rs/blob/main/examples)

[RFC2945]: https://datatracker.ietf.org/doc/html/rfc2945
[RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054#appendix-A

## Test Data

Run tests with the 'norand' feature to test against the data provided in RFC 5054 appendix B.

The test is called `test_official_vectors_1024`.

## License

- **[MIT License](LICENSE)**
- Copyright 2021 © [Sven Assmann](https://www.d34dl0ck.me)
