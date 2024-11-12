// blocks_in_conditions: didn't work with `#[instrument...`` usage
#![allow(clippy::module_name_repetitions, clippy::blocks_in_conditions)]
use crate::{
    cache::{Cache, CacheKind, Cacheable, ConcreteCache, Yoked},
    config::{GitlabConfig, MetadataFormat},
    providers::{EligibilityCacheKey, Release, User},
};
use anyhow::Context;
use async_trait::async_trait;
use backoff::backoff::Backoff;
use futures::{stream::FuturesUnordered, StreamExt, TryStreamExt};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::{header, Certificate};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::{borrow::Cow, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tracing::{debug, info_span, instrument, Instrument};
use url::Url;
use yoke::{Yoke, Yokeable};

/// Number of `package_files` GETs to do in parallel.
const PARALLEL_PACKAGE_FILES_GETS: usize = 32;

pub struct Gitlab {
    client: reqwest::Client,
    base_url: Url,
    token_expiry: time::Duration,
    metadata_format: MetadataFormat,
    admin_token: Option<String>,
    cache: ConcreteCache,
    cache_releases_older_than: Duration,
}

impl Gitlab {
    pub fn new(config: &GitlabConfig, cache: ConcreteCache) -> anyhow::Result<Self> {
        let mut client_builder = reqwest::ClientBuilder::new();

        if let Some(cert_path) = &config.ssl_cert {
            let gitlab_cert_bytes = std::fs::read(cert_path)?;
            let gitlab_cert = Certificate::from_pem(&gitlab_cert_bytes)?;
            client_builder = client_builder.add_root_certificate(gitlab_cert);
        }

        Ok(Self {
            client: client_builder.build()?,
            base_url: config.uri.join("api/v4/")?,
            token_expiry: config.token_expiry,
            metadata_format: config.metadata_format,
            admin_token: config.admin_token.clone(),
            cache,
            cache_releases_older_than: config.cache_releases_older_than,
        })
    }

    /// Checks if the given release has a `metadata.json` and matching `{release-name}-{release-version}.crate`
    /// file, if it does then returns an `Ok(Some(Release))` result containing metadata about the
    /// release, otherwise `Ok(None)` will be returned meaning the release isn't eligible.
    #[instrument(skip_all, err)]
    async fn check_release_is_eligible(
        self: Arc<Self>,
        release: GitlabPackageResponse,
        do_as: &User,
    ) -> anyhow::Result<Yoked<Option<Release<'static>>>> {
        let (raw_project, package_id) = {
            let mut splitter = release.links.web_path.splitn(2, "/-/packages/");
            match (splitter.next(), splitter.next()) {
                (Some(project), Some(package)) => (&project[1..], package),
                _ => return Ok(Yoke::attach_to_cart(Vec::new(), |_| None)),
            }
        };

        // we've already verified that the user has access to this package as this function is
        // only ever called after its been seen from the API in `get_releases`
        let cache_key = EligibilityCacheKey::new(raw_project, &release.name, &release.version);
        if let Some(cached) = self
            .cache
            .get::<Option<Release<'static>>>(cache_key)
            .await
            .context("failed to lookup release cache")?
        {
            debug!("Returning cached eligibility for release");
            return Ok(cached);
        }

        debug!("Fetching eligibility for release");

        let project = utf8_percent_encode(raw_project, NON_ALPHANUMERIC);
        let package_id = utf8_percent_encode(package_id, NON_ALPHANUMERIC);

        let uri = self.base_url.join(&format!(
            "projects/{project}/packages/{package_id}/package_files",
        ))?;

        let package_files: Vec<GitlabPackageFilesResponse> = handle_error(
            self.client
                .get(uri)
                .user_or_admin_token(do_as, &self.admin_token)
                .send_retry_429()
                .await?,
        )
        .await?
        .json()
        .await?;

        // any crate releases must contain a metadata.json
        if !package_files
            .iter()
            .any(|package_file| package_file.file_name == self.metadata_format.filename())
        {
            return Ok(Yoke::attach_to_cart(Vec::new(), |_| None));
        }

        let yanked = package_files
            .iter()
            .any(|package_file| package_file.file_name == "yanked");

        let expected_file_name = format!("{}-{}.crate", release.name, release.version);

        // grab the sha256 checksum of the .crate file itself
        let Some(package_file) = package_files
            .into_iter()
            .find(|package_file| package_file.file_name == expected_file_name)
        else {
            return Ok(Yoke::attach_to_cart(Vec::new(), |_| None));
        };

        let release = Some(Release {
            name: Cow::Owned(release.name.to_string()),
            version: Cow::Owned(release.version.to_string()),
            checksum: Cow::Owned(package_file.file_sha256),
            project: Cow::Owned(raw_project.to_string()),
            yanked,
        });

        if package_file.created_at + self.cache_releases_older_than < OffsetDateTime::now_utc() {
            self.cache
                .put(cache_key, &release)
                .await
                .context("failed to write to cache")?;
        }

        Ok(Yoke::attach_to_cart(Vec::new(), |_| release))
    }
}

#[async_trait]
impl super::UserProvider for Gitlab {
    #[instrument(skip(self, username_password), err)]
    async fn find_user_by_username_password_combo(
        &self,
        username_password: &str,
    ) -> anyhow::Result<Option<User>> {
        let mut splitter = username_password.splitn(2, ':');
        let (Some(username), Some(password)) = (splitter.next(), splitter.next()) else {
            return Ok(None);
        };

        if username == "gitlab-ci-token" || username == "personal-token" {
            if username == "gitlab-ci-token" {
                let res: GitlabJobResponse = handle_error(
                    self.client
                        .get(self.base_url.join("job/")?)
                        .header("JOB-TOKEN", password)
                        .send()
                        .await?,
                )
                .await?
                .json()
                .await?;

                Ok(Some(User {
                    id: res.user.id,
                    username: res.user.username,
                    ..Default::default()
                }))
            } else {
                let res: GitlabUserResponse = handle_error(
                    self.client
                        .get(self.base_url.join("user/")?)
                        .header("PRIVATE-TOKEN", password)
                        .send()
                        .await?,
                )
                .await?
                .json()
                .await?;

                Ok(Some(User {
                    id: res.id,
                    username: res.username,
                    token: Some(password.to_string()),
                }))
            }
        } else {
            Ok(None)
        }
    }

    #[instrument(skip(self), err)]
    async fn find_user_by_ssh_key(&self, fingerprint: &str) -> anyhow::Result<Option<User>> {
        let mut url = self.base_url.join("keys")?;
        url.query_pairs_mut()
            .append_pair("fingerprint", fingerprint);

        let res: GitlabSshKeyLookupResponse = handle_error(
            self.client
                .get(url)
                .private_token(&self.admin_token)
                .send()
                .await?,
        )
        .await?
        .json()
        .await?;
        Ok(res.user.map(|u| User {
            id: u.id,
            username: u.username,
            ..Default::default()
        }))
    }

    #[instrument(skip(self), err)]
    async fn fetch_token_for_user(&self, user: &User) -> anyhow::Result<String> {
        let impersonation_token: GitlabImpersonationTokenResponse = handle_error(
            self.client
                .post(
                    self.base_url
                        .join(&format!("users/{}/impersonation_tokens", user.id))?,
                )
                .private_token(&self.admin_token)
                .json(&GitlabImpersonationTokenRequest {
                    name: env!("CARGO_PKG_NAME"),
                    expires_at: (OffsetDateTime::now_utc() + self.token_expiry)
                        .date()
                        .to_string(),
                    scopes: vec!["api"],
                })
                .send()
                .await?,
        )
        .await?
        .json()
        .await?;

        Ok(impersonation_token.token)
    }

    /// Checks if the user is a maintainer of the given project.
    #[instrument(skip(self), err)]
    async fn is_project_maintainer(&self, do_as: &User, project: &str) -> anyhow::Result<bool> {
        let uri = self.base_url.join(&format!(
            "projects/{}",
            utf8_percent_encode(project, NON_ALPHANUMERIC),
        ))?;

        let result: GitlabProject = handle_error(
            self.client
                .get(uri)
                .user_or_admin_token(do_as, &self.admin_token)
                .send_retry_429()
                .await?,
        )
        .await?
        .json()
        .await?;

        Ok(result.permissions.access_level() >= GitlabProjectAccess::MAINTAINER_ACCESS_LEVEL)
    }
}

#[async_trait]
impl super::PackageProvider for Gitlab {
    type CratePath = Arc<GitlabCratePath>;

    async fn fetch_releases_for_project(
        self: Arc<Self>,
        project: &str,
        do_as: &Arc<User>,
    ) -> anyhow::Result<Vec<Yoked<Release<'static>>>> {
        let mut next_uri = Some({
            let mut uri = self.base_url.join(&format!(
                "projects/{}/packages",
                urlencoding::encode(project)
            ))?;
            {
                let mut query = uri.query_pairs_mut();
                query.append_pair("per_page", "100");
                query.append_pair("pagination", "keyset");
                query.append_pair("sort", "asc");
                query.append_pair("order_by", "created_at");
                if do_as.token.is_none() {
                    query.append_pair("sudo", itoa::Buffer::new().format(do_as.id));
                }
            }
            uri
        });

        let fetch_concurrency = Semaphore::new(PARALLEL_PACKAGE_FILES_GETS);
        let futures = FuturesUnordered::new();

        while let Some(uri) = next_uri.take() {
            let items = if let Some(page) = self.cache.get::<PackagePage>(uri.as_str()).await? {
                let PackagePage { items, next } = page.get();
                next_uri.clone_from(next);
                items.clone()
            } else {
                let res = handle_error(
                    self.client
                        .get(uri.clone())
                        .user_or_admin_token(do_as, &self.admin_token)
                        .send_retry_429()
                        .await?,
                )
                .await?;

                let mut next = None::<Url>;
                if let Some(link_header) = res.headers().get(header::LINK) {
                    let mut link_header = parse_link_header::parse_with_rel(link_header.to_str()?)?;

                    if let Some(next_link) = link_header.remove("next") {
                        next = Some(next_link.raw_uri.parse()?);
                    }
                }

                let items: Vec<_> = res
                    .json::<Vec<GitlabPackageResponse>>()
                    .await?
                    .into_iter()
                    .filter(|release| release.package_type == "generic")
                    .collect();

                let page = PackagePage { items, next };

                // cache page if all items are older than config `cache_releases_older_than`
                // & it is not the last page
                if page.next.is_some()
                    && page.items.iter().all(|item| {
                        item.created_at + self.cache_releases_older_than < OffsetDateTime::now_utc()
                    })
                {
                    self.cache.put(uri.as_str(), &page).await?;
                }

                next_uri = page.next;
                page.items
            };

            for release in items {
                let this = Arc::clone(&self);
                let do_as = Arc::clone(do_as);
                let fetch_concurrency = &fetch_concurrency;

                futures.push(
                    async move {
                        let _guard = fetch_concurrency.acquire().await?;
                        this.clone()
                            .check_release_is_eligible(release, &do_as)
                            .await
                    }
                    .instrument(info_span!("fetch_package_files")),
                );
            }
        }

        futures
            .map_ok(|v| v.try_map_project(|res, _| res.ok_or(())))
            .filter_map(|v| async move { v.map(Result::ok).transpose() })
            .try_collect()
            .await
    }

    /// Removes the given release from the cache.
    async fn bust_cache(
        &self,
        project: &str,
        crate_name: &str,
        crate_version: &str,
    ) -> anyhow::Result<()> {
        self.cache
            .remove::<Option<Release<'static>>>(EligibilityCacheKey::new(
                project,
                crate_name,
                crate_version,
            ))
            .await?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn fetch_metadata_for_release(
        &self,
        project: &str,
        crate_name: &str,
        version: &str,
        do_as: &Arc<User>,
    ) -> anyhow::Result<cargo_metadata::Metadata> {
        let fmt = self.metadata_format;
        let url = self.base_url.join(&format!(
            "projects/{}/packages/generic/{}/{}/{}",
            utf8_percent_encode(project, NON_ALPHANUMERIC),
            utf8_percent_encode(crate_name, NON_ALPHANUMERIC),
            utf8_percent_encode(version, NON_ALPHANUMERIC),
            fmt.filename(),
        ))?;

        fmt.decode(
            self.client
                .get(url)
                .user_or_admin_token(do_as, &self.admin_token)
                .send()
                .await?,
        )
        .await
    }

    fn cargo_dl_uri(&self, project: &str, token: &str) -> anyhow::Result<String> {
        let uri = self
            .base_url
            .join("projects/")?
            .join(&format!("{}/", urlencoding::encode(project)))?;
        Ok(format!("{uri}packages/generic/{{crate}}/{{version}}/{{crate}}-{{version}}.crate?private_token={token}"))
    }
}

pub async fn handle_error(resp: reqwest::Response) -> Result<reqwest::Response, anyhow::Error> {
    if resp.status().is_success() {
        Ok(resp)
    } else {
        let status = resp.status().as_u16();
        let url = resp.url().clone();
        let text = resp.text().await.unwrap_or_else(|_| "?".into());
        let json: GitlabErrorResponse = serde_json::from_str(&text).unwrap_or_default();
        let msg = json.message.or(json.error).unwrap_or(text);

        anyhow::bail!("{url}: {status}: {msg}")
    }
}

/// The result of a `/project/[project]` call to GitLab.
#[derive(Debug, Deserialize)]
pub struct GitlabProject {
    /// The user's permissions to the current project.
    pub permissions: GitlabProjectPermissions,
}

/// The user's permissions to a project.
#[derive(Debug, Deserialize)]
pub struct GitlabProjectPermissions {
    /// The access granted to this project via direct project permissions.
    #[serde(default)]
    pub project_access: GitlabProjectAccess,
    /// The access granted to this project via group permissions.
    #[serde(default)]
    pub group_access: GitlabProjectAccess,
}

impl GitlabProjectPermissions {
    /// Grabs the highest access the user has to the project via either direct permissions or
    /// group permissions.
    #[must_use]
    pub fn access_level(&self) -> u8 {
        std::cmp::max(
            self.project_access.access_level,
            self.group_access.access_level,
        )
    }
}

/// The user's access level to a project.
#[derive(Debug, Deserialize, Default)]
pub struct GitlabProjectAccess {
    /// See <https://docs.gitlab.com/ee/api/access_requests.html#valid-access-levels>
    access_level: u8,
}

impl GitlabProjectAccess {
    /// Any users with access above this level are considered maintainers.
    ///
    /// See: <https://docs.gitlab.com/ee/api/access_requests.html#valid-access-levels>
    pub const MAINTAINER_ACCESS_LEVEL: u8 = 40;
}

#[derive(Default, Deserialize)]
pub struct GitlabErrorResponse {
    message: Option<String>,
    error: Option<String>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct GitlabCratePath {
    project: String,
    package_name: String,
}

impl GitlabCratePath {
    #[must_use]
    pub fn file_uri(&self, file: &str, version: &str) -> String {
        format!(
            "projects/{}/packages/generic/{}/{version}/{file}",
            self.project, self.package_name
        )
    }
}

#[derive(Serialize)]
pub struct GitlabImpersonationTokenRequest {
    name: &'static str,
    expires_at: String,
    scopes: Vec<&'static str>,
}

#[derive(Deserialize)]
pub struct GitlabImpersonationTokenResponse {
    pub token: String,
}

#[derive(Deserialize)]
pub struct GitlabPackageFilesResponse {
    pub file_name: SmolStr,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    pub file_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitlabPackageResponse {
    pub id: u64,
    pub name: SmolStr,
    pub version: SmolStr,
    pub package_type: SmolStr,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(rename = "_links")]
    pub links: GitlabPackageLinksResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitlabPackageLinksResponse {
    web_path: String,
}

#[derive(Deserialize)]
pub struct GitlabJobResponse {
    pub user: GitlabUserResponse,
}

#[derive(Deserialize)]
pub struct GitlabSshKeyLookupResponse {
    pub user: Option<GitlabUserResponse>,
}

#[derive(Deserialize)]
pub struct GitlabUserResponse {
    pub id: u64,
    pub username: String,
}

trait RequestBuilderExt {
    /// Add `user` PRIVATE-TOKEN header or admin token if available, in that order.
    fn user_or_admin_token(self, user: &User, admin_token: &Option<String>) -> Self;

    /// Add given PRIVATE-TOKEN header.
    fn private_token(self, token: &Option<String>) -> Self;

    /// [`reqwest::RequestBuilder::send`] send and retry 429 responses
    /// backing off exponentially between trys.
    async fn send_retry_429(self) -> anyhow::Result<reqwest::Response>;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    fn user_or_admin_token(self, user: &User, admin_token: &Option<String>) -> Self {
        match (user.token.as_deref(), admin_token.as_deref()) {
            (Some(token), _) | (None, Some(token)) => self.header("PRIVATE-TOKEN", token),
            _ => self,
        }
    }

    fn private_token(self, token: &Option<String>) -> Self {
        match token {
            Some(token) => self.header("PRIVATE-TOKEN", token),
            None => self,
        }
    }

    async fn send_retry_429(self) -> anyhow::Result<reqwest::Response> {
        let mut backoff = backoff::ExponentialBackoff::default();
        loop {
            let r = self
                .try_clone()
                .context("cannot retry request")?
                .send()
                .await?;
            if r.status().as_u16() == 429 {
                if let Some(wait) = backoff.next_backoff() {
                    debug!(url = %r.url(), "429: retrying after {wait:.1?}");
                    tokio::time::sleep(wait).await;
                    continue;
                }
            }
            return Ok(r);
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Yokeable)]
pub struct PackagePage {
    pub items: Vec<GitlabPackageResponse>,
    pub next: Option<Url>,
}

impl Cacheable for PackagePage {
    type Key<'b> = &'b str;
    const KIND: CacheKind = CacheKind::PackagePage;

    fn format_key(out: &mut Vec<u8>, k: Self::Key<'_>) {
        out.extend_from_slice(k.as_bytes());
    }
}
