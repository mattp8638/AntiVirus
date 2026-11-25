//! SaaS backup (docs/design/saas.md): Microsoft 365, Google Workspace,
//! Salesforce and QuickBooks Online, with the customer's own app registration, service account or
//! connected app; items stored in a repository like images (store.rs).

pub mod google;
pub mod http;
pub mod m365;
pub mod quickbooks;
pub mod run;
pub mod salesforce;
pub mod store;

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn err(s: impl Into<String>) -> Error {
    Error(s.into())
}
