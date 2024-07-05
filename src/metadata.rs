#![allow(clippy::module_name_repetitions)]

use crate::cache::{CacheKind, Cacheable};
use cargo_metadata::{DependencyKind, Package};
use cargo_platform::Platform;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap};
use yoke::Yokeable;

/// Transforms metadata from `cargo metadata` to the standard one-line JSON used in cargo registries.
///
/// <https://github.com/rust-lang/cargo/blob/3bc0e6d83f7f5da0161ce445f8864b0b639776a9/src/cargo/ops/registry.rs#L183>
#[must_use]
pub fn transform(
    metadata: cargo_metadata::Metadata,
    crate_name: &str,
    crate_version: Option<&Version>,
    cksum: String,
) -> Option<CargoIndexCrateMetadata<'static>> {
    let package: Package = metadata.packages.into_iter().find(|v| {
        v.name == crate_name && (crate_version.is_none() || Some(&v.version) == crate_version)
    })?;

    Some(CargoIndexCrateMetadata {
        name: Cow::Owned(package.name),
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
                    name: Cow::Owned(name),
                    req: v.req,
                    features: v.features.into_iter().map(Cow::Owned).collect(),
                    optional: v.optional,
                    default_features: v.uses_default_features,
                    target: v.target,
                    kind: v.kind,
                    registry: Some(v.registry.map_or(
                        Cow::Borrowed("https://github.com/rust-lang/crates.io-index.git"),
                        Cow::Owned,
                    )),
                    package: package.map(Cow::Owned),
                }
            })
            .collect(),
        cksum,
        features: package
            .features
            .into_iter()
            .map(|(k, v)| (Cow::Owned(k), v.into_iter().map(Cow::Owned).collect()))
            .collect(),
        yanked: false,
        links: package.links.map(Cow::Owned),
    })
}

#[derive(Serialize, Debug)]
pub struct CargoConfig {
    pub dl: String,
}

#[derive(Serialize, Deserialize, Debug, Yokeable)]
pub struct CargoIndexCrateMetadata<'a> {
    #[serde(borrow)]
    name: Cow<'a, str>,
    pub vers: Version,
    #[serde(borrow)]
    deps: Vec<CargoIndexCrateMetadataDependency<'a>>,
    cksum: String,
    #[serde(borrow)]
    features: HashMap<Cow<'a, str>, Vec<Cow<'a, str>>>,
    yanked: bool,
    #[serde(borrow)]
    links: Option<Cow<'a, str>>,
}

impl Cacheable for CargoIndexCrateMetadata<'static> {
    type Key<'b> = &'b str;
    const KIND: CacheKind = CacheKind::CrateMetadata;

    fn format_key(out: &mut Vec<u8>, k: Self::Key<'_>) {
        out.extend_from_slice(k.as_bytes());
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CargoIndexCrateMetadataDependency<'a> {
    #[serde(borrow)]
    name: Cow<'a, str>,
    req: VersionReq,
    #[serde(borrow)]
    features: Vec<Cow<'a, str>>,
    optional: bool,
    default_features: bool,
    target: Option<Platform>,
    kind: DependencyKind,
    #[serde(borrow)]
    registry: Option<Cow<'a, str>>,
    #[serde(borrow)]
    package: Option<Cow<'a, str>>,
}
