# idrac6-kvm

A modern, Java-free replacement for the Dell iDRAC 6 KVM console (PowerEdge R710). It speaks
iDRAC 6's native `APCP` protocol directly and re-exposes the remote console as a standard
**RFB/VNC** server, so any VNC client works. Browser access is provided optionally, via noVNC
from nixpkgs, by the bundled NixOS module.

Scope: **KVM console** — video + keyboard + mouse. No virtual media / power / serial-over-LAN.

## Status

Working end to end against a real R710:

- Legacy TLS (OpenSSL, SECLEVEL 0) + `APCP` handshake — validated live
- Automated auth: iDRAC web login → one-time KVM token → dual-channel login → logout
- Video: decodes the RLE/RGB555 stream to a framebuffer — pixel-perfect
- Output: minimal RFB 3.8 server — verified with an independent VNC client
- Input: keyboard + absolute-pointer mouse → APCP (packet types 512/513)

## Build

```sh
nix build            # -> ./result/bin/idrac6-kvm  (~3.5 MB)
nix develop          # dev shell: cargo, rustc, openssl
nix develop .#capture   # extra tools for the M0 capture spike (tigervnc, tshark)
```

## Use

```sh
# Live console over RFB/VNC (account credentials; the tool mints the KVM token itself).
IDRAC_PASSWORD='…' idrac6-kvm serve --host <idrac-ip> --user root --listen 127.0.0.1:5900
# then: vncviewer 127.0.0.1:5900   (or the NixOS module's noVNC in a browser)

# Debug: log the handshake + typed packets, optionally dumping the video for offline work.
IDRAC_PASSWORD='…' idrac6-kvm capture --host <idrac-ip> --seconds 15 --dump frames.bin

# Offline: decode a dump to a PPM, or serve it over RFB without touching the iDRAC.
idrac6-kvm decode --input frames.bin --out frame.ppm
idrac6-kvm serve  --replay frames.bin --listen 127.0.0.1:5900
```

Instead of `--host/--user/--password`, pass `--jnlp viewer.jnlp` to use a token from a
downloaded Virtual Console descriptor.

## NixOS module

```nix
# flake.nix: inputs.idrac6-kvm.url = "path:/home/alexa/Projects/idrac-6";
# configuration.nix:
services.idrac6-kvm = {
  enable = true;
  host = "192.0.2.10";
  user = "root";
  passwordFile = "/run/secrets/idrac-password";  # kept out of the store
  listen = "127.0.0.1:5900";
  novnc.enable = true;         # optional browser frontend at 127.0.0.1:6080
};
```

## How it works

`serve` logs into the iDRAC web UI to mint a one-time KVM token, opens the APCP control
channel (TLS) and authenticates, then opens the media channel and drives the video handshake.
Incoming `hb` tiles are RLE/RGB555-decoded (`src/video/decoder.rs`, ported from the applet's
`com/avocent/kvm/d/b.java` + `d/c.java`) into a shared framebuffer that the RFB server streams
to clients. RFB key/pointer events are translated to APCP keyboard (`f`, type 512) and mouse
(`gc`, type 513) packets.

## Origin

Reverse-engineered from the decompiled `avctKVM.jar` for interoperability with hardware you own.
The video codec and protocol are pure-Java in the applet (the shipped `.so` files are only X11
keyboard-passthrough and local drive access, neither needed here).
