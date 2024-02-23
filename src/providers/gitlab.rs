// blocks_in_conditions: didn't work with `#[instrument...`` usage
#![allow(clippy::module_name_repetitions, clippy::blocks_in_conditions)]
mod checksums;

use crate::{
    config::{GitlabConfig, MetadataFormat},
    providers::{Release, User},
};
use anyhow::Context;
use async_trait::async_trait;
use backoff::backoff::Backoff;
use checksums::ChecksumCache;
use futures::{stream::FuturesUnordered, StreamExt, TryStreamExt};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::{header, Certificate};
use serde::{Deserialize, Serialize};
use smol_str::{format_smolstr, SmolStr};
use std::{sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tracing::{debug, info_span, instrument, Instrument};
use url::Url;

/// Number of `package_files` GETs to do in parallel.
const PARALLEL_PACKAGE_FILES_GETS: usize = 32;

pub struct Gitlab {
    client: reqwest::Client,
    base_url: Url,
    token_expiry: time::Duration,
    metadata_format: MetadataFormat,
    admin_token: Option<String>,
    checksums: ChecksumCache,
    cache_checksums_older_than: Option<Duration>,
}

impl Gitlab {
    pub fn new(config: &GitlabConfig) -> anyhow::Result<Self> {
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
            checksums: <_>::default(),
            cache_checksums_older_than: config.cache_releases_older_than,
        })
    }

    async fn fetch_checksum(
        &self,
        key: checksums::Key,
        do_as: &User,
    ) -> anyhow::Result<Option<Arc<str>>> {
        if let Some(chksum) = self.checksums.get(&key) {
            return Ok(Some(chksum));
        }

        let package_files: Vec<GitlabPackageFilesResponse> = handle_error(
            self.client
                .get(key.fetch_url())
                .user_or_admin_token(do_as, &self.admin_token)
                .send_retry_429()
                .await?,
        )
        .await?
        .json()
        .await?;

        let Some(file) = package_files
            .into_iter()
            .find(|package_file| package_file.file_name == key.file_name)
        else {
            return Ok(None);
        };

        // if `cache_checksums_older_than` is configured and this file is old enough
        // cache the checksum to avoid having to fetch again
        if let Some(cache_older_than) = self.cache_checksums_older_than {
            let cache_max_created = OffsetDateTime::now_utc() - cache_older_than;
            if file.created_at < cache_max_created {
                self.checksums.set(key, Arc::clone(&file.file_sha256));
            }
        }

        Ok(Some(file.file_sha256))
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
}

#[async_trait]
impl super::PackageProvider for Gitlab {
    type CratePath = Arc<GitlabCratePath>;

    async fn fetch_releases_for_project(
        self: Arc<Self>,
        project: &str,
        do_as: &Arc<User>,
    ) -> anyhow::Result<Vec<(Self::CratePath, Release)>> {
        let mut next_uri = Some({
            let mut uri = self.base_url.join(&format!(
                "projects/{}/packages",
                urlencoding::encode(project)
            ))?;
            {
                let mut query = uri.query_pairs_mut();
                query.append_pair("per_page", itoa::Buffer::new().format(100u16));
                query.append_pair("pagination", "keyset");
                query.append_pair("sort", "asc");
                if do_as.token.is_none() {
                    query.append_pair("sudo", itoa::Buffer::new().format(do_as.id));
                }
            }
            uri
        });

        let fetch_concurrency = Semaphore::new(PARALLEL_PACKAGE_FILES_GETS);
        let futures = FuturesUnordered::new();

        while let Some(uri) = next_uri.take() {
            let res = handle_error(
                self.client
                    .get(uri)
                    .user_or_admin_token(do_as, &self.admin_token)
                    .send_retry_429()
                    .await?,
            )
            .await?;

            if let Some(link_header) = res.headers().get(header::LINK) {
                let mut link_header = parse_link_header::parse_with_rel(link_header.to_str()?)?;

                if let Some(next) = link_header.remove("next") {
                    next_uri = Some(next.raw_uri.parse()?);
                }
            }

            let res: Vec<_> = res
                .json::<Vec<GitlabPackageResponse>>()
                .await?
                .into_iter()
                .filter(|release| release.package_type == "generic")
                .collect();

            for release in res {
                let this = Arc::clone(&self);
                let do_as = Arc::clone(do_as);
                let fetch_concurrency = &fetch_concurrency;

                futures.push(
                    async move {
                        let _guard = fetch_concurrency.acquire().await?;

                        let (project, package) = {
                            let mut splitter = release.links.web_path.splitn(2, "/-/packages/");
                            match (splitter.next(), splitter.next()) {
                                (Some(project), Some(package)) => (&project[1..], package),
                                _ => return anyhow::Ok(None),
                            }
                        };

                        let package_path = Arc::new(GitlabCratePath {
                            project: utf8_percent_encode(project, NON_ALPHANUMERIC).to_string(),
                            package_name: utf8_percent_encode(&release.name, NON_ALPHANUMERIC)
                                .to_string(),
                        });

                        let key = checksums::Key {
                            base_url: this.base_url.as_str().into(),
                            project: project.into(),
                            package: package.into(),
                            file_name: format_smolstr!(
                                "{}-{}.crate",
                                release.name,
                                release.version
                            ),
                        };

                        let checksum = this.fetch_checksum(key, &do_as).await?;

                        Ok(checksum.map(|checksum| {
                            (
                                Arc::clone(&package_path),
                                Release {
                                    name: Arc::from(release.name),
                                    version: release.version,
                                    checksum,
                                },
                            )
                        }))
                    }
                    .instrument(info_span!("fetch_package_files")),
                );
            }
        }

        futures
            .err_into()
            .filter_map(|v| async { v.transpose() })
            .try_collect()
            .await
    }

    #[instrument(skip(self), err)]
    async fn fetch_metadata_for_release(
        &self,
        path: &Self::CratePath,
        version: &str,
        do_as: &Arc<User>,
    ) -> anyhow::Result<cargo_metadata::Metadata> {
        let fmt = self.metadata_format;
        let url = self
            .base_url
            .join(&path.file_uri(fmt.filename(), version))?;

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
    pub file_sha256: Arc<str>,
}

#[derive(Deserialize)]
pub struct GitlabPackageResponse {
    pub id: u64,
    pub name: String,
    pub version: String,
    pub package_type: String,
    #[serde(rename = "_links")]
    pub links: GitlabPackageLinksResponse,
}

#[derive(Deserialize)]
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
