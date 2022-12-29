## 0.4.2

### Features

- Sparete service handle(#364)

## yamux 0.3.7 secio 0.5.7

### Bug Fix
- Fix wrong behavior on half close(#362)

## 0.4.1

### Features
- Re-export openssl vendored

## 0.4.0

### Bug Fix
- Introduce budget model to avoid uninterrupted future(#355)
- Fixed in the implementation of poll fn, which does not call it if it returns none(#355)
- Reuse address by default(#356)
- Clippy fix(#358)

### Features
- Remove the external exposure of socket2, so that external interaction is only possible via fd(#355)

## 0.4.0-beta.5

### Features
- Re-add multi to target session(#352)

## secio 0.5.4

### Features
- Use openssl repalce ring on unix and ossl110(#350)

## 0.4.0-beta.4

### Bug Fix
- Fix `Instant` may panic on `duration_since, elapsed, sub`(#349, also patch to 0.4.0-alpha.3)

## 0.4.0-beta.3

### Features
- Make inner bound channel size configurable(#348, also patch to 0.4.0-alpha.3)

## 0.4.0-beta.2

### Bug Fix
- Fix `bind` on listen can't return Error(#347)

## 0.4.0-beta.1

### Bug Fix
- Fix listener poll(#333, also patch to 0.4.0-alpha.2)

### Features
- Change to async trait(#323)
- Use spin loop instead of thread yield(#331, also patch to 0.4.0-alpha.2)
- Support tls(#322)
- Enable use config Tcp socket(#339, #345)

## yamux 0.3.1-0.3.3 secio 0.5.1

yamux 0.3.2: edition 2018
yamux 0.3.3 and 0.3.1: edition 2021

### Bug Fix
- Fix yamux window update(#340)

## 0.4.0-alpha.1

### Features
- Upgrade tokio to 1.x(#293)
- Upgrade toolchain to 1.51.0(#315)
- Change `Multi(Vec<Id>)` to `Filter(Box<Fn(ID) -> bool)`(#312)
- Introduce `parking_lot` to tentacle priority channel(#316)
- Support `/Memory/port` to test(#318)
- Use no hash map to usize key map(#325)

## 0.3.8

### Bug Fix
- Port futures-rs fix on channel(#308)
- Don't use loop on yamux(#307)
- Fix yamux close(#309)

## 0.3.7

### Bug Fix
- Blocking session detection(#306)

## 0.3.6

### Bug Fix
- Fix random open stream fail(#298)
- yamux session flush must once a loop(#296)
- Fix config doesnt use(#300 #302)

### Features
- Perf yamux and secio(#295)
- Avoiding double loops(#294)

## 0.3.5

### Bug Fix
- Fix resolve cpu load issue of prepare_uninitialized_buffer

## 0.3.4

### Features
- Add protocol spawn feature(#278)
- Revert yamux buffer(#281)
- Remove secp256k1 wasm compatible(#282)
- Add doc(#289)

### Bug Fix
- Unified substream error output(#287)
- Fix some msg left on buffer(#288)
- Change blocking session detection(#290)

## 0.3.3

### Features
- Run on Browser(#273 #274)
- Setup Github Action(#276)
- Secio remove aes-ctr, add x25519 support(#271)

### Bug Fix
- Fix windows compatible(#275)

## 0.3.2

### Features
- Change channel api to immutable(#265)
- Enable reuse port, use to NAT penetration(#266)
- Make yamux independent of the specific runtime(#267,#268)
- Make tentacle run on async std(#269)
- Add fuzz test(#211)

## 0.3.1

### Features
- Add a feature to support websocket(#257)
- Upgrade the minimum supported Rust version to 1.46.0(#263)
- Slightly improved performance by reducing system calls(#261)
- Add more examples and optimize protocol examples

### Bug Fix
- Fix yamux stream stuck after the underlying connection is closed(#260)
- Fix yamux writeable waker to make the notification flow clearer(#262)

## 0.3.0

### Features
- Refactor secio to reduce channel overhead(#249, [#23](https://github.com/driftluo/tentacle/pull/23))
- Split listener from service struct(#238)
- Implement and replace priority channel(#240, #248)
- Removal of side-effects of set delay tasks, resulting in significant performance improvements(#241)
- Rewrite stream poll(#243)
- Rewrite buffer cache(#244, #251)
- Remove protocol on service(#239)
- Add more test

### Bug Fix
- Fix yamux leak mem(#250)
- Fix yamux send go away(#247)

## 0.3.0-alpha.5

### Features
- Reduce box new consume on listen(#230)
- Secio: reduce one copy behavior during transmission(#233)
- BreakChange: split the big `Error` enum into a several small `ErrorKind` enums(#234)
- Support parse slice to pubkey(#235)
- Add doc for `ProtocolHandle`

## 0.3.0-alpha.4

### Bug Fix

- Fix session proto open/close by user part(#220)

### Features

- Replace unsplit with assignment(#225)
- Upgrade tokio util(#224)
- Avoids unnecessary session id checking(#223)
- Check all underscore(#228)
- Use flag to control how to use `block_in_place`(#226)
- More test(#227/#220)

## 0.3.0-alpha.3

### Bug Fix

- Remove all internal loop restrictions
- upgrade molecule dep
- Fix FutureTask signals memory leak

## 0.3.0-alpha.2

### Bug Fix

- Fix overflow on be attacked on Secio
- Fix throughput issues caused by code limit

### Features

- Error type Changed

## 0.3.0-alpha.1

### Features
- Upgrade moleculec to 0.5.0
- Upgrade to async ecology

## 0.2.7

### Features

- Upgrade moleculec to 0.4.2

### Bug fix

- Add transport connection number limit on listener

## 0.2.6

### Features

- Secio removed support for `twofish-ctr`, [detail](https://github.com/nervosnetwork/tentacle/pull/191)
- Secio added support for `aes-gcm/chacha20poly1305`, [detail](https://github.com/nervosnetwork/tentacle/pull/191)
- Secio default symmetric encryption algorithm change to `aes-128-gcm`, [detail](https://github.com/nervosnetwork/tentacle/pull/191)
- Use industry standard encryption algorithms in openssl or ring, [detail](https://github.com/nervosnetwork/tentacle/pull/191)
- Upgrade molecule
- Secio bump to 0.2.0
- Change panic report road

### Bug fix

- Fix the implementation of non-standard encryption algorithms
- Fix potential overflow
- Fix handshake attack

## 0.2.5

### Features

- Upgrade molecule, use compatible mode
- Add `global_ip_only` to identify/discovery
- Add Readme to identify/discovery

### Bug fix

- Fix substream cache processing is not timely
- Fix session `set_delay` status setting error，may cause an invalid call

## 0.2.4

### Features

- Remove `fnv` dependence
- Support handshake on molecule with features
- Handle panic shutdown mechanism
- Discovery only publish public ip and "0.0.0.0"

### Bug fix

- Fix error output on listen error
- Fix discovery ipaddr conditions
- Fix yamux possible security issues on malicious attack

## 0.2.3

### Features

- Record pending data size in SessionContext

## 0.2.2

### Refactor

- Use blocking thread to avoid the problem that the reactor is not timely

### Bug Fix

- Allow dns resolver on current thread runtime
- Listen address update too frequently

## 0.2.1

### Features

- Support UPNP #161
- Add open protocols interface #164

### Refactor

- Refactor identify protocol #162

    BREAK CHANGE:

    API does not break, but the communication message of identify break

### Bug Fix

- Fix bug on protocol open command send by control #164

## 0.2.0

This is the first truly usable version
