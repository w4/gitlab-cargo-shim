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

    async fn fetch_group(self: Arc<Self>, group: &str, do_as: &User) -> anyhow::Result<Group>;

    async fn fetch_releases_for_group(
        self: Arc<Self>,
        group: &Group,
        do_as: &User,
    ) -> anyhow::Result<Vec<(Self::CratePath, Release)>>;

    async fn fetch_metadata_for_release(
        self: Arc<Self>,
        path: &Self::CratePath,
        version: &str,
    ) -> anyhow::Result<cargo_metadata::Metadata>;

    fn cargo_dl_uri(
        &self,
        path: &Self::CratePath,
        version: &str,
        token: &str,
    ) -> anyhow::Result<String>;
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: u64,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub id: u64,
    pub name: String,
}

pub type ReleaseName = Arc<str>;

#[derive(Debug)]
pub struct Release {
    pub name: ReleaseName,
    pub version: String,
    pub checksum: String,
}
