# P2P

[![Build Status](https://api.travis-ci.org/driftluo/p2p.svg?branch=master)](https://travis-ci.org/driftluo/p2p)
![image](https://img.shields.io/badge/rustc-1.36-blue.svg)

## Overview

This is a minimal implementation for a multiplexed p2p network based on `yamux` that supports mounting custom protocols.

## Architecture

1. Data stream transmission

```rust
+----+      +----------------+      +-----------+      +-------------+      +----------+      +------+
|user| <--> | custom streams | <--> |Yamux frame| <--> |Secure stream| <--> |TCP stream| <--> |remote|
+----+      +----------------+      +-----------+      +-------------+      +----------+      +------+
```

2. Code implementation

All data is passed through the futures channel, `yamux` splits the actual tcp stream into multiple substreams,
and the service layer wraps the yamux substream into a protocol stream.

At the same time, support for other protocol(such as websocket) is also planned, but will delay a lot.

Detailed introduction: [中文](./docs/introduction_zh.md)/[English](./docs/introduction_en.md)

> Note: It is not compatible with `libp2p`.

## Status

The API of this project is basically usable. However we still need more tests. PR is welcome.

## Usage

### From cargo

```toml
[dependencies]
tentacle = { version = "0.2", features = ["molc"] }
```

### Example

1. Clone

```bash
$ git clone https://github.com/nervosnetwork/p2p.git
```

2. On one terminal:

Listen on 127.0.0.1:1337
```bash
$ RUST_LOG=simple=info,tentacle=debug cargo run --example simple --features molc -- server
```

3. On another terminal:

```bash
$ RUST_LOG=simple=info,tentacle=debug cargo run --example simple --features molc
```

4. Now you can see some data interaction information on the terminal.

You can see more detailed example in these two repos: [ckb](https://github.com/nervosnetwork/ckb)/[cita](https://github.com/cryptape/cita).

## Why?

Because when I use `rust-libp2p`, I have encountered some difficult problems,
and it is difficult to locate whether it is my problem or the library itself,
it is better to implement one myself.
