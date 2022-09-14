#![allow(clippy::module_name_repetitions)]

use cargo_metadata::{DependencyKind, Package};
use cargo_platform::Platform;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap};

/// Transforms metadata from `cargo metadata` to the standard one-line JSON used in cargo registries.
///
/// <https://github.com/rust-lang/cargo/blob/3bc0e6d83f7f5da0161ce445f8864b0b639776a9/src/cargo/ops/registry.rs#L183>
#[must_use]
pub fn transform(
    metadata: cargo_metadata::Metadata,
    crate_name: &str,
    cksum: String,
) -> Option<CargoIndexCrateMetadata> {
    let package: Package = metadata
        .packages
        .into_iter()
        .find(|v| v.name == crate_name)?;

    Some(CargoIndexCrateMetadata {
        name: package.name,
        vers: package.version,
        deps: package
            .dependencies
            .into_iter()
            .map(|v| {
                let (name, package) = if let Some(rename) = v.rename {
                    (rename, Some(v.name))
                } else {
                    (v.name, None)
                };

                CargoIndexCrateMetadataDependency {
                    name,
                    req: v.req,
                    features: v.features,
                    optional: v.optional,
                    default_features: v.uses_default_features,
                    target: v.target,
                    kind: v.kind,
                    registry: Some(v.registry.map_or(
                        Cow::Borrowed("https://github.com/rust-lang/crates.io-index.git"),
                        Cow::Owned,
                    )),
                    package,
                }
            })
            .collect(),
        cksum,
        features: package.features,
        yanked: false,
        links: package.links,
    })
}

#[derive(Serialize, Debug)]
pub struct CargoConfig {
    pub dl: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CargoIndexCrateMetadata {
    name: String,
    vers: Version,
    deps: Vec<CargoIndexCrateMetadataDependency>,
    cksum: String,
    features: HashMap<String, Vec<String>>,
    yanked: bool,
    links: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CargoIndexCrateMetadataDependency {
    name: String,
    req: VersionReq,
    features: Vec<String>,
    optional: bool,
    default_features: bool,
    target: Option<Platform>,
    kind: DependencyKind,
    registry: Option<Cow<'static, str>>,
    package: Option<String>,
}
