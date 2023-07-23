pub mod gitlab;

use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait UserProvider {
    async fn find_user_by_username_password_combo(
        &self,
        username_password: &str,
    ) -> anyhow::Result<Option<User>>;

    async fn find_user_by_ssh_key(&self, fingerprint: &str) -> anyhow::Result<Option<User>>;

    async fn fetch_token_for_user(&self, user: &User) -> anyhow::Result<String>;
}

#[async_trait]
pub trait PackageProvider {
    /// Provider-specific metadata passed between `PackageProvider` methods to
    /// figure out the path of a package.
    type CratePath: std::fmt::Debug + Send + std::hash::Hash + Clone + Eq + PartialEq + Send + Sync;

    async fn fetch_releases_for_scope<'a>(
        self: Arc<Self>,
        scope: Scope<'a>,
        do_as: &User,
    ) -> anyhow::Result<Vec<(Self::CratePath, Release)>>
    where
        Scope<'a>: 'async_trait;

    async fn fetch_metadata_for_release(
        &self,
        path: &Self::CratePath,
        version: &str,
    ) -> anyhow::Result<cargo_metadata::Metadata>;

    fn cargo_dl_uri(&self, scope: Scope, token: &str) -> anyhow::Result<String>;
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: u64,
    pub username: String,
}

pub type ReleaseName = Arc<str>;

#[derive(Debug)]
pub struct Release {
    pub name: ReleaseName,
    pub version: String,
    pub checksum: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Scope<'a> {
    Project(&'a str),
    Group(&'a str),
}
