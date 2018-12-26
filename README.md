# P2P

## Overview

This is a minimal implementation for a multiplexed p2p network based on `yamux` that supports mounting custom protocols.

## Architecture

1. Data stream transmission

```rust
+----+      +----------------+      +-----------+      +----------+      +------+
|user| <--> | custom streams | <--> |Yamux frame| <--> |TCP stream| <--> |remote|
+----+      +----------------+      +-----------+      +----------+      +------+
```

2. Code implementation

All data is passed through the futures channel, `yamux` splits the actual tcp stream into multiple substreams,
and the service layer wraps the yamux substream into a protocol stream.

Encryption is currently not supported and may be added between yamux and tcp or between costom and yamux in the future.

At the same time, support for other protocol(such as websocket) is also planned, but will delay a lot.

> Note: It is not currently compatible with `libp2p`, because the description of libp2p is not particularly clear in some places,
> so I don't know what `libp2p` is doing in some places.
> For example, when opening a custom protocol stream, how does the two parties decide which protocol to open?

## Status

The api of this project is changing dramatically, but the core ideas will hardly change much, PR is welcome.

This library still lacks a lot of stability tests and stress tests, I will try to do these things.

## Usage

### Example

1. Clone

```bash
$ git clone https://github.com/nervosnetwork/p2p.git
```

2. On one terminal:

Listen on 127.0.0.1:1337
```bash
$ RUST_LOG=simple=info,p2p=debug cargo run --example simple -- server
```

3. On another terminal:

```bash
$ RUST_LOG=simple=info,p2p=debug cargo run --example simple
```

4. Now you can see some data interaction information on the terminal.

## Why?

Because when I use `rust-libp2p`, I have encountered some difficult problems,
and it is difficult to locate whether it is my problem or the library itself,
it is better to implement one myself.
