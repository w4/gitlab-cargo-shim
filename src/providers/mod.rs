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
}

#[async_trait]
pub trait PackageProvider {
    async fn fetch_releases_for_group(
        self: Arc<Self>,
        group: &str,
        do_as: User,
    ) -> anyhow::Result<Vec<Release>>;
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: u64,
    pub username: String,
}

#[derive(Debug)]
pub struct Release {
    pub name: String,
    pub version: String,
    pub checksum: String,
    pub uri: String,
}
