#![allow(clippy::module_name_repetitions)]

use crate::config::GitlabConfig;
use crate::providers::{Group, Release, User};
use async_trait::async_trait;
use futures::{stream::FuturesUnordered, StreamExt, TryStreamExt};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::header;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, sync::Arc};
use tracing::Instrument;
use url::Url;

pub struct Gitlab {
    client: reqwest::Client,
    base_url: Url,
}

impl Gitlab {
    pub fn new(config: &GitlabConfig) -> anyhow::Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "PRIVATE-TOKEN",
            header::HeaderValue::from_str(&config.admin_token)?,
        );

        Ok(Self {
            client: reqwest::ClientBuilder::new()
                .default_headers(headers)
                .build()?,
            base_url: config.uri.join("api/v4/")?,
        })
    }
}

#[async_trait]
impl super::UserProvider for Gitlab {
    async fn find_user_by_username_password_combo(
        &self,
        username_password: &str,
    ) -> anyhow::Result<Option<User>> {
        let mut splitter = username_password.splitn(2, ':');
        let (username, password) = match (splitter.next(), splitter.next()) {
            (Some(username), Some(password)) => (username, password),
            _ => return Ok(None),
        };

        if username == "gitlab-ci-token" {
            let res: GitlabJobResponse = handle_error(
                // we're purposely not using `self.client` here as we don't
                // want to use our admin token for this request
                reqwest::Client::new()
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
            }))
        } else {
            Ok(None)
        }
    }

    async fn find_user_by_ssh_key(&self, fingerprint: &str) -> anyhow::Result<Option<User>> {
        let mut url = self.base_url.join("keys")?;
        url.query_pairs_mut()
            .append_pair("fingerprint", fingerprint);

        let res: GitlabSshKeyLookupResponse = handle_error(self.client.get(url).send().await?)
            .await?
            .json()
            .await?;
        Ok(res.user.map(|u| User {
            id: u.id,
            username: u.username,
        }))
    }

    async fn fetch_token_for_user(&self, user: &User) -> anyhow::Result<String> {
        let impersonation_token: GitlabImpersonationTokenResponse = handle_error(
            self.client
                .post(
                    self.base_url
                        .join(&format!("users/{}/impersonation_tokens", user.id))?,
                )
                .json(&GitlabImpersonationTokenRequest {
                    name: env!("CARGO_PKG_NAME"),
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

    async fn fetch_group(self: Arc<Self>, group: &str, do_as: &User) -> anyhow::Result<Group> {
        let mut url = self
            .base_url
            .join("groups/")?
            .join(&utf8_percent_encode(group, NON_ALPHANUMERIC).to_string())?;
        url.query_pairs_mut()
            .append_pair("sudo", itoa::Buffer::new().format(do_as.id));

        let req = handle_error(self.client.get(url).send().await?)
            .await?
            .json::<GitlabGroupResponse>()
            .await?
            .into();

        Ok(req)
    }

    async fn fetch_releases_for_group(
        self: Arc<Self>,
        group: &Group,
        do_as: &User,
    ) -> anyhow::Result<Vec<(Self::CratePath, Release)>> {
        let mut next_uri = Some({
            let mut uri = self
                .base_url
                .join(&format!("groups/{}/packages", group.id,))?;
            {
                let mut query = uri.query_pairs_mut();
                query.append_pair("per_page", itoa::Buffer::new().format(100u16));
                query.append_pair("pagination", "keyset");
                query.append_pair("sort", "asc");
                query.append_pair("sudo", itoa::Buffer::new().format(do_as.id));
            }
            uri
        });

        let futures = FuturesUnordered::new();

        while let Some(uri) = next_uri.take() {
            let res = handle_error(self.client.get(uri).send().await?).await?;

            if let Some(link_header) = res.headers().get(reqwest::header::LINK) {
                let mut link_header = parse_link_header::parse_with_rel(link_header.to_str()?)?;

                if let Some(next) = link_header.remove("next") {
                    next_uri = Some(next.raw_uri.parse()?);
                }
            }

            let res: Vec<GitlabPackageResponse> = res.json().await?;

            for release in res {
                let this = Arc::clone(&self);

                futures.push(tokio::spawn(
                    async move {
                        let (project, package) = {
                            let mut splitter = release.links.web_path.splitn(2, "/-/packages/");
                            match (splitter.next(), splitter.next()) {
                                (Some(project), Some(package)) => (&project[1..], package),
                                _ => return Ok(None),
                            }
                        };

                        let package_path = Arc::new(GitlabCratePath {
                            project: utf8_percent_encode(project, NON_ALPHANUMERIC).to_string(),
                            package_name: utf8_percent_encode(&release.name, NON_ALPHANUMERIC)
                                .to_string(),
                        });

                        let package_files: Vec<GitlabPackageFilesResponse> = handle_error(
                            this.client
                                .get(format!(
                                    "{}/projects/{}/packages/{}/package_files",
                                    this.base_url,
                                    utf8_percent_encode(project, NON_ALPHANUMERIC),
                                    utf8_percent_encode(package, NON_ALPHANUMERIC),
                                ))
                                .send()
                                .await?,
                        )
                        .await?
                        .json()
                        .await?;

                        let expected_file_name =
                            format!("{}-{}.crate", release.name, release.version);

                        Ok::<_, anyhow::Error>(
                            package_files
                                .into_iter()
                                .find(|package_file| package_file.file_name == expected_file_name)
                                .map(move |package_file| {
                                    (
                                        Arc::clone(&package_path),
                                        Release {
                                            name: Arc::from(release.name),
                                            version: release.version,
                                            checksum: package_file.file_sha256,
                                        },
                                    )
                                }),
                        )
                    }
                    .in_current_span(),
                ));
            }
        }

        futures
            .err_into()
            .filter_map(|v| async move { v.and_then(|v| v).transpose() })
            .try_collect()
            .await
    }

    async fn fetch_metadata_for_release(
        self: Arc<Self>,
        path: &Self::CratePath,
        version: &str,
    ) -> anyhow::Result<cargo_metadata::Metadata> {
        let uri = self.base_url.join(&path.metadata_uri(version))?;

        Ok(handle_error(self.client.get(uri).send().await?)
            .await?
            .json()
            .await?)
    }

    fn cargo_dl_uri(&self, group: &Group, token: &str) -> anyhow::Result<String> {
        let uri = self
            .base_url
            .join("groups/")?
            .join(&format!("{}/", group.id))?;
        Ok(format!("{uri}packages/generic/{{sha256-checksum}}/{{crate}}-{{version}}.crate?private_token={token}"))
    }
}

async fn handle_error(resp: reqwest::Response) -> Result<reqwest::Response, anyhow::Error> {
    if resp.status().is_success() {
        Ok(resp)
    } else {
        let resp: GitlabErrorResponse = resp.json().await?;
        Err(anyhow::Error::msg(
            resp.message
                .or(resp.error)
                .map_or_else(|| Cow::Borrowed("unknown error"), Cow::Owned),
        ))
    }
}

#[derive(Deserialize)]
pub struct GitlabErrorResponse {
    message: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct GitlabGroupResponse {
    id: u64,
    name: String,
}

impl From<GitlabGroupResponse> for Group {
    fn from(v: GitlabGroupResponse) -> Self {
        Self {
            id: v.id,
            name: v.name,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct GitlabCratePath {
    project: String,
    package_name: String,
}

impl GitlabCratePath {
    #[must_use]
    pub fn metadata_uri(&self, version: &str) -> String {
        format!(
            "projects/{}/packages/generic/{}/{version}/metadata.json",
            self.project, self.package_name
        )
    }
}

#[derive(Serialize)]
pub struct GitlabImpersonationTokenRequest {
    name: &'static str,
    scopes: Vec<&'static str>,
}

#[derive(Deserialize)]
pub struct GitlabImpersonationTokenResponse {
    pub token: String,
}

#[derive(Deserialize)]
pub struct GitlabPackageFilesResponse {
    pub file_name: String,
    pub file_sha256: String,
}

#[derive(Deserialize)]
pub struct GitlabPackageResponse {
    pub id: u64,
    pub name: String,
    pub version: String,
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
