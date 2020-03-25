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

- Secio removed support for `twofish-ctr`, [detail](https://github.com/nervosnetwork/p2p/pull/191)
- Secio added support for `aes-gcm/chacha20poly1305`, [detail](https://github.com/nervosnetwork/p2p/pull/191)
- Secio default symmetric encryption algorithm change to `aes-128-gcm`, [detail](https://github.com/nervosnetwork/p2p/pull/191)
- Use industry standard encryption algorithms in openssl or ring, [detail](https://github.com/nervosnetwork/p2p/pull/191)
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
