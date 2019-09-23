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
