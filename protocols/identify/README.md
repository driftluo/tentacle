## Identify
Node self-identifying protocol

### Identify behavior

Under the architecture of the Tentacle framework, if you decide to open all protocols at once,
the order of opening is undetermined. Tentacle also supports the opening of the specified protocol,
that is, control the order in which the protocols are opened by controlling the order of execution.

In some scenarios, both parties need to confirm the capabilities of the other party before opening
the application protocol. The Identify protocol can be viewed as a general handshake protocol for
the user protocol layer, it supports passing in arbitrary data for interaction, and can customize
the next behavior based on the received message.

At the same time, it tentatively transmits the observation address and the listening address.

### Message type

```
table IdentifyMessage {
    // These are the addresses on which the peer is listening as multi-addresses.
    listen_addrs: AddressVec,
    // Observed each other's ip
    observed_addr: Address,
    // Custom message to indicate self ability, such as list protocols supported
    identify: Bytes,
}
```
