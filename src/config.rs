#![allow(clippy::module_name_repetitions)]

use crate::providers::gitlab::handle_error;
use clap::Parser;
use serde::{de::DeserializeOwned, Deserialize};
use std::{io, net::SocketAddr, path::PathBuf, str::FromStr};
use time::Duration;
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
    #[serde(default = "GitlabConfig::default_token_expiry")]
    pub token_expiry: Duration,
    #[serde(default)]
    pub ssl_cert: Option<String>,
    /// Metadata format for fetching.
    #[serde(default)]
    pub metadata_format: MetadataFormat,
}

impl GitlabConfig {
    #[must_use]
    const fn default_token_expiry() -> Duration {
        Duration::days(30)
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
                tokio::task::block_in_place(move || {
                    Ok(serde_json::from_reader(zstd::Decoder::new(body.as_ref())?)?)
                })
            }
        }
    }
}

pub fn from_toml_path<T: DeserializeOwned>(path: &str) -> Result<T, std::io::Error> {
    let contents = std::fs::read(path)?;
    toml::from_slice(&contents).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
