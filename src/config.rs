#![allow(clippy::module_name_repetitions)]

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
}

impl GitlabConfig {
    #[must_use]
    const fn default_token_expiry() -> Duration {
        Duration::days(30)
    }
}

pub fn from_toml_path<T: DeserializeOwned>(path: &str) -> Result<T, std::io::Error> {
    let contents = std::fs::read(path)?;
    toml::from_slice(&contents).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
