use crate::providers::{Release, User};
use async_trait::async_trait;
use futures::{stream::FuturesUnordered, StreamExt, TryStreamExt};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::header;
use serde::Deserialize;
use std::sync::Arc;

pub struct Gitlab {
    client: reqwest::Client,
    base_url: String,
}

impl Gitlab {
    pub fn new() -> anyhow::Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "PRIVATE-TOKEN",
            header::HeaderValue::from_static("token"),
        );

        Ok(Self {
            client: reqwest::ClientBuilder::new()
                .default_headers(headers)
                .build()?,
            base_url: "https://127.0.0.1/api/v4".to_string(),
        })
    }

    pub async fn get_impersonation_token_for(&self, user: &User) -> anyhow::Result<String> {
        let impersonation_token: GitlabImpersonationTokenResponse = self
            .client
            .get(format!(
                "{}/users/{}/impersonation_tokens",
                self.base_url, user.id
            ))
            .body(format!("name={};scopes=api", env!("CARGO_PKG_NAME")))
            .send()
            .await?
            .json()
            .await?;

        Ok(impersonation_token.token)
    }
}

#[async_trait]
impl super::UserProvider for Gitlab {
    async fn find_user_by_username_password_combo(
        &self,
        username_password: &str,
    ) -> anyhow::Result<Option<User>> {
        let mut splitter = username_password.splitn(2, ':');
        let (username, password) = (splitter.next().unwrap(), splitter.next().unwrap());

        if username == "gitlab-ci-token" {
            let res: GitlabJobResponse = self
                .client
                .get(format!("{}/job", self.base_url))
                .header("JOB-TOKEN", password)
                .send()
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
        let res: GitlabSshKeyLookupResponse = self
            .client
            .get(format!(
                "{}/keys?fingerprint={}",
                self.base_url, fingerprint
            ))
            .send()
            .await?
            .json()
            .await?;
        Ok(res.user.map(|u| User {
            id: u.id,
            username: u.username,
        }))
    }
}

#[async_trait]
impl super::PackageProvider for Gitlab {
    async fn fetch_releases_for_group(
        self: Arc<Self>,
        group: &str,
        do_as: User,
    ) -> anyhow::Result<Vec<Release>> {
        let impersonation_token = Arc::new(self.get_impersonation_token_for(&do_as).await?);

        let mut next_uri = Some(format!(
            "{}/groups/{}/packages?per_page=100&pagination=keyset&order_by=id&sort=asc&sudo={}",
            self.base_url,
            utf8_percent_encode(group, NON_ALPHANUMERIC),
            do_as.id
        ));

        let futures = FuturesUnordered::new();

        while let Some(uri) = next_uri.take() {
            let res = self.client.get(uri).send().await?;

            if let Some(link_header) = res.headers().get(reqwest::header::LINK) {
                let mut link_header = parse_link_header::parse_with_rel(link_header.to_str()?)?;

                if let Some(next) = link_header.remove("next") {
                    next_uri = Some(next.raw_uri);
                }
            }

            let res: Vec<GitlabPackageResponse> = res.json().await?;

            for release in res {
                let this = self.clone();
                let impersonation_token = impersonation_token.clone();

                futures.push(tokio::spawn(async move {
                    let (project, package) = {
                        let mut splitter = release.links.web_path.splitn(2, "/-/packages/");
                        match (splitter.next(), splitter.next()) {
                            (Some(project), Some(package)) => (&project[1..], package),
                            _ => return Ok(None),
                        }
                    };

                    let package_files: GitlabPackageFilesResponse = this
                        .client
                        .get(format!(
                            "{}/projects/{}/packages/{}/package_files",
                            this.base_url,
                            utf8_percent_encode(project, NON_ALPHANUMERIC),
                            utf8_percent_encode(package, NON_ALPHANUMERIC),
                        ))
                        .send()
                        .await?
                        .json()
                        .await?;

                    Ok::<_, anyhow::Error>(Some(Release {
                        uri: format!(
                            "{}/projects/{}/packages/generic/{}/{}/{}?private_token={}",
                            this.base_url,
                            utf8_percent_encode(project, NON_ALPHANUMERIC),
                            utf8_percent_encode(&release.name, NON_ALPHANUMERIC),
                            utf8_percent_encode(&release.version, NON_ALPHANUMERIC),
                            package_files.file_name,
                            impersonation_token,
                        ),
                        name: release.name,
                        version: release.version,
                        checksum: package_files.file_sha256,
                    }))
                }))
            }
        }

        futures
            .err_into()
            .filter_map(|v| async move { v.and_then(|v| v).transpose() })
            .try_collect()
            .await
    }
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
