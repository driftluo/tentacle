## P2P Introduction

- [Objective](#Objective)
- [The Idea](#The-Idea)
- [The Primary Approach](#The-Primary-Approach)
- [Introduction of library Implementation](#Introduction-of-library-Implementation)
  - [yamux](#yamux)
  - [secio](#secio)
  - [P2P](#P2P)
- [Overall Data Flow](#Overall-Data-Flow)
- [Not Compatible with libp2p](#Not-Compatible-with-libp2p)

### Objective

The P2P library is aimed at implementing a framework that light weight, simple, reliable, high performance, and friendly to users. The idea originally comes from libp2p spec, but implemented in a different way. The differences will be introduced for reference at the end.


### The Idea

First of all, from our understanding of a framework, it should be easy for users to build business logic on top of it. We consider the usability under the premise of complete function implementation so that it can be called a **framework** until it is easy to use.

Secondly, we do not plan to use lock explicitly as multithreaded data sharing. We prefer using channel for multithreaded synchronizing as a much elegant and distinct way. 

Again, the library uses tokio’s asynchronous logic at the bottom part as the performance guarantee, but asynchronous (at the moment) itself may interrupt business logic implement. For user-friendly, we provide synchronous API at the very beginning. **To be careful**, the synchronize interfaces are part of the asynchronous call. It will let the entire service in a stuck if you write blocking codes in it. So we suggest you do use asynchronous  way when you need to write any io tasks.


### The Primary Approach

As a P2P framework that capable of mounting multiple protocols, the key function is to split a underlying connection (TCP/UDP/WebSocket, etc) to multiple sub connections and assign each sub connection to each protocol, as much as possible to ensure that the **time slice occupied** by each agreement is relatively fair. That the distribution of the message is accurate, and the messages of many protocols cannot be caused by the excessive messages of one protocol. It is the key value of the library, which may look like a router.

To achieve multiplexing, we implement a multiplexing protocol `yamux` first, which specifies valid messages' type, behavior, format, etc. It’s one of the standards for implementing network protocol multiplexing as well as part of libp2p spec. The next step, we make an abstract layer on top of `yamux` protocol, binding the `yamux` multiplex to the custom protocols, thus implementing multi-protocol coexistence. Referred to libp2p, we mount an encryption protocol (`secio`) on the top of the factual connection and under `yamux`, that enables encrypted message communication. That is to say, the essential differences between encrypted and unencrypted are whether `yamux` splits connections based on factual connections or `secio`.


### Introduction of library Implementation

#### yamux

As the library's core dependence, `yamux` is implemented in full compliance with its standards, primarily for compatibility and to make it easier for other languages to implement.

We made two abstractions in Rust implementation: `Session<T>` and `StreamHandle`:

- `Session`: corresponding to the factual connection or encrypted connection, and it can output any substreams at the same time, that each substream communicates via channel and session. session is responsible for sending data to the underlying channel and forwarding data to the corresponding substream.
- `StreamHandle`: The structure is an abstraction of substream, it's a struct implement traits of `Write`, `Read`, `AsyncWrite`, and `AsyncRead`, meaning that it can be Read and Write as a file in Rust.

The rest of the library is an implementation of `yamux` protocol, for example, how `frame` encrypts and decrypts; `config` is a set of configuration items that can be adjusted (whether to Ping regularly, dynamic window size, and so on).

The entire library is built on tokio's asynchronous ecosystem.

#### secio

Encrypted communication is a bit more complicated than `yamux`; it referred to libp2p and rust-libp2p.

First, encrypted communication is bound to have an initialization process, called handshake. The purpose of a handshake is exchanging key information such as, nonce, both the public keys and encryption algorithms are supported. If the exchange is succeeded as expected (shook hands success), it should keep the temporary symmetric encrypted private keys secure enough, and to output the public keys and encrypted stream (similar to `StreamHandle` in `yamux` library) to the upper layer at the same time. The upper layer as a channel for encrypted data transmission, which transfers decrypted data automatically.

Secondly, the implementation of the encrypted stream is divided into two parts, `SecureStream` and `StreamHandle`. Both of them are implemented in the same way as `yamux`, that one is responsible to factul stream, the other is for user (upper layer) to read and write. Unlike in the `yamux` implementation, there is only a one-to-one relationship between the two structures; it cannot generate a one-to-many mapping.

#### P2P

The two libraries above are the infrastructure of P2P implementation, while P2P is the one step further that encapsulates the two libraries. It has two purposes, to abstract away a user-friendly interface, and to support multi-protocol loading. There is no protocol in yamux layer, but only a substream concept (definition). The definition and usage of custom protocols are implemented in the P2P layer. For the convenience of users, P2P imposes some simple constraints (traits) on the behavior of custom protocols.

Each protocol has its unique handle that needs to be implemented. The handle can perceive the opening, closing, communication and other behaviors of the protocol. In our opinion, the handle can be simply divided into two types: global handle and session handle. The differences are as follows:

- Global protocol handle: when the first connection is opened, as its protocol opens, there generate a globally unique protocol handle. Its life cycle is the same as Service, which means it can store various states internally, such as how many nodes are connected, what are the characteristics of each node, and so on.

- Connection-level (session) exclusive protocol handle: when each protocol is opened, it generates a session-level protocol handle. When the protocol is closed or the session is disconnected, the handle is cleared, which means that the handle is a stateless handle that unable to store the state before and after the session is opened. It only knows all the information between the opening and closing of each protocol. Very lightweight.

Any custom protocol can implement both handles at the same time, or one of them. P2P guarantees that each handle behaves the same as described.

For some possible error messages generated by the Service, we define a `ServiceHandle` separately, which is responsible for delivering the error messages to the user because we should not specify any protocol to handle global-level errors.
We also simply defined some anti-repetition connection and identity matching mechanisms in the P2P layer and built simple governance processes into the framework, which are difficult to implement in the upper layer.


### Overall Data Flow

The introduction of a data transmission process is as follows:

1. Data is sent from the user layer to the Service for unified streaming processing
2. The data is shunted into a substream of `yamux`
3. The substream sends data to the Session structure of `yamux`
4. Session sends the received substream data to `secio`'s handle
5. The handle sends data to `SecureStream`, which is encrypted and sent to the remote end
6. Remote end receive process is the opposite of the send process, and finally deliver to the user layer via Service

As you can see, for all connections, the data stream works in the form of aggregation-> scatter -> reaggregation. It would be a great help to understand the whole framework with a scenario in your mind.


### Not Compatible with libp2p

#### Handshake

1. During the handshake, exchange and propose use molecule for serialization and deserialization, libp2p uses protobuf;
2. The handshake currently supports the public key exchange of Secp256k1 algorithm;
3. The original public key and nonce determine the order, while libp2p uses the public key of protobuf bytes.

#### Multiplexing protocol

`yamux` is supported, and there is no implementation of `mplex`, which means that there is no selection handshake process for `yamux` or `mplex`.

#### Custom protocol selection process

The process of each protocol's opening is a handshake process as well, and the communication format is `molecule`. The structure is:

```
table ProtocolInfo {
    name: string;
    support_versions: [string];
}
```

The initiator of negotiation is the active dialing party (client); it starts the negotiation process of protocol opening after connected. The listener determines whether it supports it or not after receiving the negotiation information. It opens the corresponding protocol and starts communication if supported; otherwise, it notifies the other party to disconnect.
