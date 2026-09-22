# doover-tunnel

The client half of Doover tunnels: the wire protocol a relay session speaks,
the device role (serve a pinned target on the device) and the user role
(forward a localhost port), plus the `doover-tunnel` binary that the `doover`
CLI runs as `doover tunnel` / `doover ssh`.

Everything that decides who may connect lives on the server side. The relay
verifies each leg's bearer token against Doover, a device may only serve its
own sessions, a user needs tunnel permission on the device, and a session is
pinned to one target. This crate contains no credentials and no authorisation
logic; publishing it discloses the message format and nothing else.

## Layout

- `proto/` — session record, hello/open/close messages (MessagePack,
  length-prefixed), relay audit events, WebSocket byte-stream adapter.
- `dial`, `mux` — connect to a relay with a role and token; yamux over it.
- `client` — local listener / stdio forwarding with the user's token.
- `device` — serve the pinned target with the device agent's token.
- `bin/doover-tunnel.rs` (feature `cli`) — the user binary.

## Building

```
cargo build --release --features cli   # the doover-tunnel binary
cargo test --all-features
```

## Packaging

The binary ships to PyPI as the `doover-tunnel` wheel, built with maturin
from `pyproject.toml` (`bindings = "bin"`); `doover-cli` depends on it and
execs it. Wheels only are published, never an sdist.

## Licence

Apache-2.0.
