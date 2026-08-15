//! The live KVM session. A reconnect supervisor decodes video into a shared framebuffer, and
//! client input events are translated into APCP.

pub mod input;
pub mod kvm;
