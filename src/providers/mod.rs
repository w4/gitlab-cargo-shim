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

    async fn fetch_releases_for_project(
        self: Arc<Self>,
        project: &str,
        do_as: &Arc<User>,
    ) -> anyhow::Result<Vec<(Self::CratePath, Release)>>;

    async fn fetch_metadata_for_release(
        &self,
        path: &Self::CratePath,
        version: &str,
        do_as: &Arc<User>,
    ) -> anyhow::Result<cargo_metadata::Metadata>;

    fn cargo_dl_uri(&self, project: &str, token: &str) -> anyhow::Result<String>;
}

#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: u64,
    pub username: String,
    pub token: Option<String>,
}

pub type ReleaseName = Arc<str>;

#[derive(Debug)]
pub struct Release {
    pub name: ReleaseName,
    pub version: String,
    pub checksum: String,
}
