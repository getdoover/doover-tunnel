# doover-tunnel

The client half of [Doover](https://doover.com) tunnels: the wire protocol a
relay session speaks, the device role (serve a target on the device) and the
user role (forward a localhost port), plus the `doover-tunnel` binary that the
`doover` CLI runs as `doover tunnel` and `doover ssh`.

## Using it

Install the Doover CLI, which depends on this package:

```
uv tool install doover-cli    # or: pipx install doover-cli
doover login
doover tunnel <device>        # private tunnel to the device, forwarded to localhost
doover ssh <device>           # the same, straight into ssh
```

## Building

```
cargo build --release --features cli   # the doover-tunnel binary
cargo test --all-features
```

The binary ships to PyPI as the `doover-tunnel` wheel, built with maturin
from `pyproject.toml`. Wheels only are published, never an sdist.

## Contact

Questions, bugs or ideas: open an issue here, or reach the maintainers at
hello@doover.com.

## License

Apache License 2.0. See [LICENSE](LICENSE).
