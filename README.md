# Tentacle

[![Build Status](https://github.com/nervosnetwork/tentacle/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/nervosnetwork/tentacle/actions/workflows/ci.yaml/badge.svg?branch=master)
![image](https://img.shields.io/badge/rustc-1.81.0-blue.svg)

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

All data is passed through the futures channel, `yamux` splits the actual tcp/websocket stream into multiple substreams,
and the service layer wraps the yamux substream into a protocol stream.

Detailed introduction: [中文](./docs/introduction_zh.md)/[English](./docs/introduction_en.md)

> Note: It is not compatible with `libp2p`.

## Status

The API of this project is basically usable. However we still need more tests. PR is welcome.

The codes in the `protocols/` directory are no longer maintained and only used as reference

## Usage

### From cargo

```toml
[dependencies]
tentacle = { version = "0.6.0" }
```

### Example

1. Clone

```bash
$ git clone https://github.com/nervosnetwork/tentacle.git
```

2. On one terminal:

Listen on 127.0.0.1:1337
```bash
$ RUST_LOG=simple=info,tentacle=debug cargo run --example simple --features ws -- server
```

3. On another terminal:

```bash
$ RUST_LOG=simple=info,tentacle=debug cargo run --example simple
```

4. Now you can see some data interaction information on the terminal.

You can see more detailed example in these three repos:

- [ckb](https://github.com/nervosnetwork/ckb)
- [cita](https://github.com/cryptape/cita)
- [muta](https://github.com/nervosnetwork/muta)
- [axon](https://github.com/nervosnetwork/axon)
- [godwoken](https://github.com/nervosnetwork/godwoken)

### Run on browser and test

1. setup a ws server:
```
$ cd tentacle && RUST_LOG=info cargo run --example simple --features ws -- server
```

2. setup a browser client
```
$ cd simple_wasm && wasm-pack build
$ npm install && npm run serve
```

all wasm code generate from [book](https://rustwasm.github.io/docs/book/game-of-life/hello-world.html)

3. Use a browser to visit http://localhost:8080/

4. Now you can see the connection on the server workbench or on browser's console

## Event Order Guarantees

Tentacle provides the following guarantees regarding event ordering:

1. All protocol events **always occur after** the initial `SessionOpen` event
2. The `SessionClose` event is guaranteed to be the final event in a session's lifecycle
3. When multiple protocols are opened simultaneously, no specific ordering is guaranteed between their events
4. Critical errors such as `SessionTimeOut` or `MuxerError` will immediately trigger a `SessionClose` event, causing the connection to terminate automatically

## Other Languages

Implementations in other languages

- [Go](https://github.com/driftluo/tentacle-go)

## Why?

Because when I use `rust-libp2p`, I have encountered some difficult problems,
and it is difficult to locate whether it is my problem or the library itself,
it is better to implement one myself.
