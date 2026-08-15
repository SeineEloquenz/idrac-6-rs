//! User-facing layer: expose the KVM session as an RFB/VNC server. The `serve_conn` entry point
//! drives the protocol over any duplex stream, so the `idrac6-kvm-web` crate reuses it for its
//! RFB-over-WebSocket bridge.

pub mod rfb;
