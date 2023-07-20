#![allow(clippy::module_name_repetitions)]

use clap::Parser;
use serde::{de::DeserializeOwned, Deserialize};
use std::{net::SocketAddr, path::PathBuf};
use time::Duration;
use url::Url;

#[derive(Parser)]
#[clap(version = clap::crate_version!(), author = clap::crate_authors!())]
pub struct Args {
    #[clap(short, long, parse(try_from_str = from_toml_path))]
    pub config: Config,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub listen_address: SocketAddr,
    pub state_directory: PathBuf,
    pub gitlab: GitlabConfig,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitlabConfigScope {
    Project,
    Group,
}
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GitlabConfig {
    pub uri: Url,
    #[serde(default = "GitlabConfig::default_scope")]
    pub scope: GitlabConfigScope,
    pub admin_token: String,
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

    #[must_use]
    const fn default_scope() -> GitlabConfigScope {
        GitlabConfigScope::Project
    }
}

pub fn from_toml_path<T: DeserializeOwned>(path: &str) -> Result<T, std::io::Error> {
    let contents = std::fs::read(path)?;
    toml::from_slice(&contents).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
