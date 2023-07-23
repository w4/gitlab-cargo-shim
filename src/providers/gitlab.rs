#![allow(clippy::module_name_repetitions)]

use crate::config::GitlabConfig;
use crate::providers::{Release, Scope, User};
use async_trait::async_trait;
use futures::{stream::FuturesUnordered, StreamExt, TryStreamExt};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::{header, Certificate};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, sync::Arc};
use time::{Duration, OffsetDateTime};
use tracing::{debug, info_span, instrument, Instrument};
use url::Url;

pub struct Gitlab {
    client: reqwest::Client,
    base_url: Url,
    token_expiry: Duration,
    ssl_cert: Option<Certificate>,
}

impl Gitlab {
    pub fn new(config: &GitlabConfig) -> anyhow::Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "PRIVATE-TOKEN",
            header::HeaderValue::from_str(&config.admin_token)?,
        );

        let mut client_builder = reqwest::ClientBuilder::new().default_headers(headers);

        let ssl_cert = match &config.ssl_cert {
            Some(cert_path) => {
                let gitlab_cert_bytes = std::fs::read(cert_path)?;
                let gitlab_cert = Certificate::from_pem(&gitlab_cert_bytes)?;
                client_builder = client_builder.add_root_certificate(gitlab_cert.clone());
                Some(gitlab_cert)
            }
            _ => None,
        };

        Ok(Self {
            client: client_builder.build()?,
            base_url: config.uri.join("api/v4/")?,
            token_expiry: config.token_expiry,
            ssl_cert,
        })
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

        if username == "gitlab-ci-token" {
            // we're purposely not using `self.client` here as we don't
            // want to use our admin token for this request but still want to use any ssl cert provided.
            let mut client_builder = reqwest::Client::builder();
            if let Some(cert) = &self.ssl_cert {
                client_builder = client_builder.add_root_certificate(cert.clone());
            }
            let client = client_builder.build();
            let res: GitlabJobResponse = handle_error(
                client?
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

    #[instrument(skip(self), err)]
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

    #[instrument(skip(self), err)]
    async fn fetch_token_for_user(&self, user: &User) -> anyhow::Result<String> {
        let impersonation_token: GitlabImpersonationTokenResponse = handle_error(
            self.client
                .post(
                    self.base_url
                        .join(&format!("users/{}/impersonation_tokens", user.id))?,
                )
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

impl Gitlab {
    fn releases_uri(&self, scope: Scope) -> anyhow::Result<Url> {
        let uri = match scope {
            Scope::Project(project) => self.base_url.join(&format!(
                "projects/{}/packages?package_type=generic",
                urlencoding::encode(project)
            ))?,
            Scope::Group(group) => self.base_url.join(&format!(
                "groups/{}/packages?package_type=generic",
                urlencoding::encode(group)
            ))?,
        };
        Ok(uri)
    }
}

#[async_trait]
impl super::PackageProvider for Gitlab {
    type CratePath = Arc<GitlabCratePath>;

    async fn fetch_releases_for_scope<'a>(
        self: Arc<Self>,
        scope: Scope<'a>,
        do_as: &User,
    ) -> anyhow::Result<Vec<(Self::CratePath, Release)>>
        where
            Scope<'a>: 'async_trait,
    {
        let mut next_uri = Some({
            let mut uri = self.releases_uri(scope)?;
            uri.query_pairs_mut()
                .append_pair("per_page", itoa::Buffer::new().format(100u16))
                .append_pair("pagination", "keyset")
                .append_pair("sort", "asc")
                .append_pair("sudo", itoa::Buffer::new().format(do_as.id))
                .finish();
            uri
        });

        let futures = FuturesUnordered::new();

        while let Some(uri) = next_uri.take() {
            let res = handle_error(self.client.get(uri).send().await?).await?;

            if let Some(link_header) = res.headers().get(header::LINK) {
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
                        .instrument(info_span!("fetch_package_files")),
                ));
            }
        }

        futures
            .err_into()
            .filter_map(|v| async move { v.and_then(|v| v).transpose() })
            .try_collect()
            .await
    }

    #[instrument(skip(self), err)]
    async fn fetch_metadata_for_release(
        &self,
        path: &Self::CratePath,
        version: &str,
    ) -> anyhow::Result<cargo_metadata::Metadata> {
        let uri = self.base_url.join(&path.metadata_uri(version))?;
        debug!(%uri,"Fetching metadata");
        Ok(handle_error(self.client.get(uri).send().await?)
            .await?
            .json()
            .await?)
    }

    fn cargo_dl_uri(&self, scope: Scope, token: &str) -> anyhow::Result<String> {
        let uri = match scope {
            Scope::Project(project) => self
                .base_url
                .join("projects/")?
                .join(&format!("{}/", urlencoding::encode(project)))?
                .to_string()
            ,
            Scope::Group(group) => self
                .base_url
                .join("projects/")?
                .join(&urlencoding::encode(&format!("{group}/")))?
                .to_string()
                + "{crate}/"
            ,
        };
        Ok(format!("{uri}packages/generic/{{crate}}/{{version}}/{{crate}}-{{version}}.crate?private_token={token}"))
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
    expires_at: String,
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
