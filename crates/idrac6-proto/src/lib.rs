//! iDRAC 6 appliance protocol client. Talk to the appliance's APCP/legacy-TLS KVM console
//! ([`apcp`]) and reproduce the web-login flow that mints a one-time KVM session token
//! ([`auth`]). The HTTP/1.1 client and legacy-TLS connector are internal support.

pub mod apcp;
pub mod auth;

pub(crate) mod http;
pub(crate) mod tls;
