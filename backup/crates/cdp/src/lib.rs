//! Continuous data protection on Linux (docs/design/cdp.md).

#[cfg(target_os = "linux")]
pub mod control;
pub mod era;
pub mod journal;
