[![Build Status](https://travis-ci.org/hashmismatch/signed_buffer.rs.svg)](https://travis-ci.org/hashmismatch/signed_buffer.rs)

# signed_buffer

A small helper to encode a byte-array payload with a prefix, buffer size, payload, checksum and a postfix marker. It can detect multiple valid signed buffers in a large byte array by skipping over all of them until finding the last valid one.

Helpful for implementing an ad-hoc config storage on a flash memory block on a MCU.

This crate doesn’t use the standard library, and so requires the nightly Rust
channel.

## Usage

Get the source:

```bash
$ git clone https://github.com/hashmismatch/signed_buffer.rs
$ cd signed_buffer
```

Then build:

```bash
$ cargo build
```

And test:

```bash
$ cargo test
```