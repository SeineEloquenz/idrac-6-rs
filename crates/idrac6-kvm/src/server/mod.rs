//! User-facing layer: expose the KVM session as an RFB/VNC server for native clients or a
//! self-serve noVNC web app.

pub mod rfb;
#[cfg(feature = "web")]
pub mod web;
