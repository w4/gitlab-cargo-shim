#![allow(clippy::module_name_repetitions)]

use crate::providers::gitlab::handle_error;
use clap::Parser;
use serde::{de::DeserializeOwned, Deserialize};
use std::{io, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};
use url::Url;

#[derive(Parser)]
#[clap(version = clap::crate_version!(), author = clap::crate_authors!())]
pub struct Args {
    #[clap(short, long)]
    pub config: Config,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub listen_address: SocketAddr,
    pub state_directory: PathBuf,
    pub gitlab: GitlabConfig,
    #[serde(default)]
    pub cache: CacheStore,
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum CacheStore {
    #[serde(rename = "rocksdb")]
    RocksDb { path: PathBuf },
    #[default]
    InMemory,
}

impl FromStr for Config {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        from_toml_path(s)
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GitlabConfig {
    pub uri: Url,
    /// If absent personal access tokens must be provided.
    pub admin_token: Option<String>,
    // TODO use humantime-serde?
    #[serde(default = "GitlabConfig::default_token_expiry")]
    pub token_expiry: time::Duration,
    #[serde(default)]
    pub ssl_cert: Option<String>,
    /// Metadata format for fetching.
    #[serde(default)]
    pub metadata_format: MetadataFormat,
    /// Cache file checksum fetches for all release older than this value.
    ///
    /// Default zero (cache all releases).
    #[serde(default, with = "humantime_serde")]
    pub cache_releases_older_than: Duration,
}

impl GitlabConfig {
    #[must_use]
    const fn default_token_expiry() -> time::Duration {
        time::Duration::days(30)
    }
}

/// Fetch format for package metadata.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetadataFormat {
    /// Plain json.
    ///
    /// Fetches `metadata.json` files.
    #[default]
    Json,
    /// Json compressed with zstd.
    ///
    /// Fetches `metadata.json.zst` files.
    #[serde(rename = "json.zst")]
    JsonZst,
}

impl MetadataFormat {
    #[must_use]
    pub fn filename(self) -> &'static str {
        match self {
            Self::Json => "metadata.json",
            Self::JsonZst => "metadata.json.zst",
        }
    }

    pub async fn decode(self, res: reqwest::Response) -> anyhow::Result<cargo_metadata::Metadata> {
        match self {
            Self::Json => Ok(handle_error(res).await?.json().await?),
            Self::JsonZst => {
                let body = handle_error(res).await?.bytes().await?;
                tokio::task::spawn_blocking(move || {
                    Ok(serde_json::from_reader(zstd::Decoder::new(body.as_ref())?)?)
                })
                .await?
            }
        }
    }
}

pub fn from_toml_path<T: DeserializeOwned>(path: &str) -> Result<T, std::io::Error> {
    let contents = std::fs::read_to_string(path)?;
    toml::from_str(&contents).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[test]
fn deser_config() {
    let conf = r#"
        listen-address = "[::]:2222"
        state-directory = "/var/lib/gitlab-cargo-shim"
        [gitlab]
        uri = "http://127.0.0.1:3000"
        metadata-format = "json.zst"
        cache-releases-older-than = "2 days""#;

    let conf: Config = toml::from_str(conf).unwrap();
    assert_eq!(
        conf.state_directory.to_string_lossy(),
        "/var/lib/gitlab-cargo-shim"
    );
    assert_eq!(conf.listen_address.to_string(), "[::]:2222");

    let gitlab = conf.gitlab;
    assert_eq!(gitlab.uri.as_str(), "http://127.0.0.1:3000/");
    assert_eq!(gitlab.admin_token, None);
    assert_eq!(gitlab.token_expiry, GitlabConfig::default_token_expiry());
    assert_eq!(gitlab.ssl_cert, None);
    assert_eq!(gitlab.metadata_format, MetadataFormat::JsonZst);
    assert_eq!(
        gitlab.cache_releases_older_than,
        Duration::from_secs(2 * 24 * 60 * 60)
    );
}
