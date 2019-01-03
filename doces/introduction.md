## P2P

这个库的理论思路与 `libp2p` 基本相同，实现时为了方便快速地搭起一个可用的框架，有几个地方与 `libp2p` 并不兼容，后续是否会往与 `libp2p` 完全兼容的方向开发，目前暂时不确定。

### 核心思路

整个库的要做的核心功能是多路复用，能够在一条连接中无障碍地挂载多个协议，并使它们能正常通信。多路复用的原理**通俗得讲就是用某种手段把一个
TCP 连接拆成多个子连接，让每个子连接认为自己都是一个真实的连接，并用这种手段将每个数据流无误地转发到对应的子流中，从而实现多协议在单连接中共存**。

实现这套思路的手段有很多，常见的有两种，一是通过锁 + index，二是通过 channel + index。不同的思路形成的代码风格也截然不同。在 `libp2p` 的实现中，有一个叫 `yamux` 的多路复用协议，它定义了每个数据包的表头、关闭、打开、ping 等行为的标准格式，本库参照 Go 版 `yamux` 的实现重新在 Rust 中实现了一遍，选择了 channel 通信的手段作为本库的核心思路，这个思路意味着我们每个子库或者是将要挂载的协议都必须遵照以 channel 为核心的思路去实现。

### 子库功能及实现介绍

#### yamux

`yamux` 是本库的核心，在实现过程中，完全依据其[标准](https://github.com/hashicorp/yamux/blob/master/spec.md)实现。

在内部，我们实现了两个主要的结构体，一个是 `Session<T>`，一个是 `StreamHandle`，Session 是对任何实现了 `AsyncWrite + AsyncRead` 的结构的封装，它可以是 `TcpStream`、`UnixStream` 等任意真实连接流，Session 实现了 Stream 每次产出一个 `StreamHandle` ，这个 `StreamHandle` 就是一个子连接，它本身实现了 `AsyncWrite + AsyncRead`，其他上层协议可以将其认为就是一个真实的流，`Session` 和 `StreamHandle` 之间通过 `channel` 进行通信，这些就是 `yamux` 的核心实现。

#### secio

库中只有一个逻辑、输出两个结构体。逻辑是加密握手逻辑，握手完成之后，输出 Remote Public Key、`StreamHandle`、Ephemeral Public Key。其实内部核心的思路与 `yamux` 一致，只有两个结构体 `SecureStream` 和 `StreamHandle`， `StreamHandle` 与 `yamux` 中的一致，就是一个 `AsyncWrite + AsyncRead` 的结构，可以获取真实的数据，`SecureStream` 是对任何实现了 `AsyncWrite + AsyncRead` 的结构的封装，它可以是 `TcpStream`、`UnixStream` 等任意真实连接流，`SecureStream` 与 `StreamHandle` 之间通过 channel 进行通信。从架构上来说，这个库与 `yamux` 的实现是一致的，只是，它不能生成多个 `StreamHandle`。

#### p2p

这个库是一个默认的对 `secio` 和 `yamux` 的封装，它将底层的真实流经过加密、`yamux` 分流之后，对外提供 `ProtocolMate`，`ProtocolHandle`， `ServiceHandle` 三个 trait 接口，用户只要对协议实现了 `ProtocolMate`，并插入 builder 中，就可以实现多协议的共存。

p2p 库的核心功能是对 `yamux` 的抽象，实现了 protocol 与 `yamux` sub stream 的消息路由分发。同时通过 `ProtocolMate` 定义了 全局协议 handle 、连接级（session）独占协议 handle 两个不同维度的自定义协议方式：

- 全局协议 handle：当第一个连接被打开时，该连接的每个协议打开的同时，会生成一个全局唯一的协议 handle，它的生命周期与 `Service` 相同，这意味着其内部可以存储各种想要的状态，比如有多少个节点被连接，每个节点的特征是什么等等；
- 连接级（session）独占协议 handle：每个协议在打开时，会生成一个 session 级别的协议 handle，当协议被关闭或者 session 被断开时，该 handle 将被清理掉，这意味着，这个 handle 是无状态的 handle，不能存储对应 session 打开之前和关闭之后的状态，它只知道每个协议打开和关闭之间的所有信息，可以说十分轻量。

上诉两个 handle 是可选实现的，如果只需要其中一个，那么就实现对应需要的级别，p2p 保证每个 handle 的行为与**描述完全相同**。

### 目前与 libp2p 的不兼容

#### 握手

1. 握手期间的 exchange 和 propose 目前使用 `bincode` 进行序列化和反序列化，libp2p 使用 protobuf；
2. 握手目前只支持 Secp256k1 算法的公钥交换；
3. order 的确定，使用原始的 public key 与 nonce，libp2p 使用 protobuf bytes 的 public key；

#### yamux or mplex

只支持 `yamux` ，并没有 `mplex` 的实现，这意味着，并没有选择 `yamux` 或者 `mplex` 的握手过程。

#### custom protocol select

每个子流协商开启哪个 protocol 的过程如下：作为主动发起连接的一方，会尝试开启自身支持的所有协议，协商的过程就是将对应的协议名称通过 `name\n` 的格式发过去，作为监听方，在接到协议名之后，查询本服务是否支持该协议，如果不支持，直接通知对方断开，如果支持，则开始正常的协议通信过程。

这个协议开启的协商过程与 `libp2p` 完全不一致。
