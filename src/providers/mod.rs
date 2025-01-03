pub mod gitlab;

use crate::cache::{CacheKind, Cacheable, Yoked};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, io::Write, sync::Arc};
use yoke::Yokeable;

#[async_trait]
pub trait UserProvider {
    async fn find_user_by_username_password_combo(
        &self,
        username_password: &str,
    ) -> anyhow::Result<Option<User>>;

    async fn is_project_maintainer(&self, do_as: &User, project: &str) -> anyhow::Result<bool>;

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
    ) -> anyhow::Result<Vec<Yoked<Release<'static>>>>;

    async fn fetch_metadata_for_release(
        &self,
        project: &str,
        crate_name: &str,
        version: &str,
        do_as: &Arc<User>,
    ) -> anyhow::Result<cargo_metadata::Metadata>;

    async fn bust_cache(
        &self,
        project: &str,
        crate_name: &str,
        crate_version: &str,
    ) -> anyhow::Result<()>;

    fn cargo_dl_uri(&self, project: &str, token: &str) -> anyhow::Result<String>;
}

#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: u64,
    pub username: String,
    pub token: Option<String>,
}

pub type ReleaseName<'a> = Cow<'a, str>;

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq)]
pub struct EligibilityCacheKey<'a> {
    project: &'a str,
    crate_name: &'a str,
    crate_version: &'a str,
}

impl<'a> EligibilityCacheKey<'a> {
    #[must_use]
    pub fn new(project: &'a str, crate_name: &'a str, crate_version: &'a str) -> Self {
        Self {
            project,
            crate_name,
            crate_version,
        }
    }
}

#[derive(Debug, Yokeable, Deserialize, Serialize)]
pub struct Release<'a> {
    #[serde(borrow)]
    pub name: ReleaseName<'a>,
    #[serde(borrow)]
    pub version: Cow<'a, str>,
    #[serde(borrow)]
    pub checksum: Cow<'a, str>,
    #[serde(borrow)]
    pub project: Cow<'a, str>,
    pub yanked: bool,
}

impl Cacheable for Option<Release<'static>> {
    type Key<'b> = EligibilityCacheKey<'b>;
    const KIND: CacheKind = CacheKind::Eligibility;

    fn format_key(out: &mut Vec<u8>, k: Self::Key<'_>) {
        out.reserve(k.project.len() + k.crate_name.len() + k.crate_version.len() + 2);
        write!(out, "{}\0{}\0{}", k.project, k.crate_name, k.crate_version).unwrap();
    }
}
