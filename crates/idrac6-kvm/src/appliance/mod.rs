//! Appliance-facing layer: reach the iDRAC over its APCP/legacy-TLS/HTTP protocols and
//! authenticate to mint a KVM session token.

pub mod auth;

pub(crate) mod apcp;
pub(crate) mod http;
pub(crate) mod tls;
