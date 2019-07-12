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
