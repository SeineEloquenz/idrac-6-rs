//! The live KVM session: the reconnect supervisor that decodes video into a shared framebuffer,
//! plus translation of client input events into APCP.

pub mod input;
pub mod kvm;
