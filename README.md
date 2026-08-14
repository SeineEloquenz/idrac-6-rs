# idrac6-kvm

A modern, Java-free replacement for the Dell iDRAC 6 KVM console (PowerEdge R710). It speaks
iDRAC 6's native `APCP` protocol directly and re-exposes the remote console either as a standard
**RFB/VNC** server (any VNC client works) or as a **self-serve web console**: a browser login
page that authenticates with the iDRAC credentials themselves and serves noVNC. In web mode no
secret is stored on the server — the iDRAC credentials entered in the browser are the only
credential. noVNC assets come from nixpkgs, not bundled into the binary.

Scope: **KVM console** — video + keyboard + mouse. No virtual media / power / serial-over-LAN.

## Status

Working end to end against a real R710:

- Legacy TLS (OpenSSL, SECLEVEL 0) + `APCP` handshake — validated live
- Automated auth: iDRAC web login → one-time KVM token → dual-channel login → logout
- Video: decodes the RLE/RGB555 stream to a framebuffer — pixel-perfect
- Output: minimal RFB 3.8 server — verified with an independent VNC client
- Input: keyboard + absolute-pointer mouse → APCP (packet types 512/513)
- Web mode: browser login gate + noVNC over an in-process RFB-over-WebSocket bridge

## Build

```sh
nix build            # -> ./result/bin/idrac6-kvm
nix develop          # dev shell: cargo, rustc, openssl
nix develop .#capture   # extra tools for the M0 capture spike (tigervnc, tshark)

cargo build --no-default-features   # lean RFB/VNC proxy: drops the web UI + axum/tower/serde
```

A Cargo workspace under `crates/`: `idrac6-kvm` (a library plus the thin CLI binary) and the pure,
dependency-free video codec crate `idrac6-video`. The self-serve web UI is behind the default-on
`web` feature; disable it for a smaller RFB-only proxy.

## Use

```sh
# Web console: browser login with iDRAC credentials, serves noVNC. No secret on the CLI.
NOVNC=$(nix build nixpkgs#novnc --no-link --print-out-paths)/share/webapps/novnc
idrac6-kvm web --host <idrac-ip> --listen 127.0.0.1:8080 --novnc-root "$NOVNC"
# then open http://127.0.0.1:8080/ and log in with the iDRAC account.

# Live console over plain RFB/VNC (for native VNC clients; the tool mints the KVM token itself).
IDRAC_PASSWORD='…' idrac6-kvm serve --host <idrac-ip> --user root --listen 127.0.0.1:5900
# then: vncviewer 127.0.0.1:5900

# Debug: log the handshake + typed packets, optionally dumping the video for offline work.
IDRAC_PASSWORD='…' idrac6-kvm capture --host <idrac-ip> --seconds 15 --dump frames.bin

# Offline: decode a dump to a PPM, or serve it over RFB without touching the iDRAC.
idrac6-kvm decode --input frames.bin --out frame.ppm
idrac6-kvm serve  --replay frames.bin --listen 127.0.0.1:5900
```

`web` serves plain HTTP: bind it to localhost behind a TLS reverse proxy, or to a trusted
network — the browser sends the iDRAC credentials to it. For `serve`/`capture`, instead of
`--host/--user/--password` you can pass `--jnlp viewer.jnlp` to use a token from a downloaded
Virtual Console descriptor.

## NixOS module

```nix
# flake.nix: inputs.idrac6-kvm.url = "path:/home/alexa/Projects/idrac-6";
# configuration.nix:
services.idrac6-kvm = {
  enable = true;
  host = "192.0.2.10";        # non-secret; credentials are entered in the browser
  user = "root";              # pre-filled on the login form
  listen = "127.0.0.1:8080";  # plain HTTP — front with a TLS reverse proxy
  idleTimeout = 600;          # release the KVM session after 10 min idle
};
```

Front it with nginx/Caddy for TLS, e.g. `services.nginx.virtualHosts."kvm.example"` proxying to
`http://127.0.0.1:8080` (pass through the `/websockify` WebSocket upgrade).

## How it works

`serve` logs into the iDRAC web UI to mint a one-time KVM token, opens the APCP control
channel (TLS) and authenticates, then opens the media channel and drives the video handshake.
Incoming `hb` tiles are RLE/RGB555-decoded (`crates/idrac6-video`, ported from the applet's
`com/avocent/kvm/d/b.java` + `d/c.java`) into a shared framebuffer that the RFB server streams
to clients. RFB key/pointer events are translated to APCP keyboard (`f`, type 512) and mouse
(`gc`, type 513) packets.

Keyboard: RFB key events carry X11 keysyms (characters), mapped to USB HID usages for a **US**
guest layout. Shift is synthesized for characters that need it (uppercase, `!@#`, `_+{}|:"<>?~`)
so on-screen/mobile keyboards, which send the character without a Shift event, still work. Set
the guest console keymap to US so the characters land correctly (a non-US console will mis-map
symbols, since VNC is character-based, not position-based).

## Origin

Reverse-engineered from the decompiled `avctKVM.jar` for interoperability with hardware you own.
The video codec and protocol are pure-Java in the applet (the shipped `.so` files are only X11
keyboard-passthrough and local drive access, neither needed here).
