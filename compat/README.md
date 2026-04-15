# Minecraft Wire Compatibility

This directory contains Python compatibility checks run through `uv`.

Run from this directory:

```sh
uv run python -m unittest discover -s tests -v
```

The status ping test starts the Rust `mc_status_compat_server` example, then uses a pure
Python Minecraft pinger to send a real status handshake, status request, and ping. The
Python side parses the `net`-encoded status response and pong without using Rust codec
logic.
