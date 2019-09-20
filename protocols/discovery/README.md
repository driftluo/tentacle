## Discovery
Node discovery (mainly same with bitcoin, for blockchain project)

### Discovery behavior

On the current NAT forwarding network environment, whether it is self-discovery or the discovery behavior
of the other party is not completely accurate, it is certain that the address received by
the user is not 100% available.

There are two actions in this protocol:

- When the connection is established, the requester(Client) will actively request the responder(Server) to
request the list of available addresses that the responder has stored. **WARNING**: This behavior is only
allowed once, otherwise it will be disconnected by the other peers.

- Each node periodically broadcasts hot address to its neighbor peers. The hot address refers to the listen
address of the neighbor peers that the node keeps communicating continuously, which means active connection.

### Message type

```
/// request for address list
GetNodes {
    version: Uint32,
    count: Uint32,
    listen_port: PortOpt,
}

/// response address list
Nodes {
    announce: Bool,
    items: NodeVec,
}
```
