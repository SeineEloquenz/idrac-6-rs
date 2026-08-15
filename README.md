# idrac6-kvm

idrac6-kvm is a modern, Java-free replacement for the remote console of Dell's iDRAC 6 (PowerEdge
R710 and friends). The stock console ships only as a signed Java 7 applet that no current browser or
JRE will run, which leaves the out-of-band console effectively dead. This tool speaks iDRAC 6's
native `APCP` protocol directly and re-exposes the console as a plain VNC server or a self-serve web
app, so any VNC client, or just a browser, gets you back to the screen.

Scope is the KVM console, meaning video, keyboard and mouse. There is no virtual media, power control
or serial-over-LAN.

Features (non-exhaustive):
* Plain RFB/VNC server that works with any VNC client
* Self-serve web console with noVNC, where the iDRAC credentials are entered in the browser and no secret is stored on the server
* Full software decode of the iDRAC 6 RLE/RGB555 video stream
* Keyboard and absolute-pointer mouse, with Shift synthesis so on-screen and mobile keyboards work
* Clipboard paste into the guest
* Automatic reconnection with one-time-token re-minting
* Zlib-compressed, dirty-rectangle framebuffer updates
* Legacy TLS for the appliance's ancient stack, with no system-wide crypto downgrade
* Nix packages, OCI images and NixOS modules for both the proxy and the web app

## Installation

The project builds with [Nix](https://nixos.org). There are two flavours, a lean `serve` proxy and
the `web` app.

```sh
nix build github:SeineEloquenz/idrac-6-rs#serve   # RFB/VNC proxy
nix build github:SeineEloquenz/idrac-6-rs#web     # self-serve web console
```

Container images are published to GHCR on every push to `main`.

```sh
# Web console, then open http://localhost:8080 and log in with the iDRAC account.
docker run -p 8080:8080 -e IDRAC_HOST=192.0.2.10 \
  ghcr.io/seineeloquenz/idrac-6-rs/web-image

# RFB/VNC proxy, then: vncviewer localhost:5900
docker run -p 5900:5900 -e IDRAC_HOST=192.0.2.10 -e IDRAC_PASSWORD=... \
  ghcr.io/seineeloquenz/idrac-6-rs/serve-image
```

You can also build the binary with cargo. `--no-default-features` drops the web app and its
dependencies for a smaller RFB-only proxy.

```sh
cargo build --release                          # both subcommands
cargo build --release --no-default-features    # RFB/VNC proxy only
```

## Usage

```sh
# Self-serve web console. Credentials are entered in the browser, nothing is stored.
NOVNC=$(nix build nixpkgs#novnc --no-link --print-out-paths)/share/webapps/novnc
idrac6-kvm web --host 192.0.2.10 --listen 127.0.0.1:8080 --novnc-root "$NOVNC"

# Plain RFB/VNC for native clients. The tool mints the KVM token itself.
IDRAC_PASSWORD=... idrac6-kvm serve --host 192.0.2.10 --user root --listen 127.0.0.1:5900
```

Both listen on plain, unauthenticated transports, so bind them to localhost behind a TLS reverse
proxy, reach them over an SSH tunnel, or bind only to a trusted network. `IDRAC_HOST`, `IDRAC_USER`,
`IDRAC_PASSWORD` and `IDRAC_LISTEN` work in place of the flags. For `serve` you can also pass `--jnlp
viewer.jnlp` with a token from a downloaded Virtual Console descriptor instead of an account
password.

Set the guest console to a US keymap. VNC keyboards are character-based rather than position-based
and the tool maps to US HID usages, so a non-US console mis-maps symbols.

## NixOS

The flake exposes `nixosModules.serve`, `nixosModules.web` and `nixosModules.default`, which imports
both.

```nix
services.idrac6-kvm-web = {
  enable = true;
  host = "192.0.2.10";        # non-secret, credentials are entered in the browser
  listen = "127.0.0.1:8080";  # plain HTTP, front with a TLS reverse proxy
};

services.idrac6-kvm-serve = {
  enable = true;
  host = "192.0.2.10";
  passwordFile = "/run/secrets/idrac";   # loaded as a systemd credential at runtime
};
```

## How it works

Both modes log into the iDRAC web UI to mint a one-time KVM token, open the APCP control channel over
legacy TLS and authenticate, then open the media channel and drive the video handshake. Incoming
tiles are RLE/RGB555-decoded into a shared framebuffer that the RFB server streams to clients, and
RFB key and pointer events are translated back to APCP keyboard and mouse packets. In web mode the
browser talks noVNC to an in-process RFB-over-WebSocket bridge.

The codec and protocol were reverse-engineered from the decompiled `avctKVM.jar` for interoperability
with hardware you own. Both are pure Java in the applet, so no native code was needed.
