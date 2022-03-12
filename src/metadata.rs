use cargo_metadata::Package;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Transforms metadata from `cargo metadata` to the standard one-line JSON used in cargo registries.
///
/// https://github.com/rust-lang/cargo/blob/3bc0e6d83f7f5da0161ce445f8864b0b639776a9/src/cargo/ops/registry.rs#L183
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
        vers: package.version.to_string(),
        deps: package
            .dependencies
            .into_iter()
            .map(|v| CargoIndexCrateMetadataDependency {
                name: v.name,
                req: v.req.to_string(),
                features: v.features,
                optional: v.optional,
                default_features: v.uses_default_features,
                target: v.target.map(|v| v.to_string()),
                kind: v.kind.to_string(),
                registry: Some(
                    v.registry
                        .unwrap_or("https://github.com/rust-lang/crates.io-index.git".to_string()),
                ),
                package: v.rename,
            })
            .collect(),
        cksum,
        features: package.features,
        yanked: false,
        links: package.links,
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CargoIndexCrateMetadata {
    name: String,
    vers: String,
    deps: Vec<CargoIndexCrateMetadataDependency>,
    cksum: String,
    features: HashMap<String, Vec<String>>,
    yanked: bool,
    links: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CargoIndexCrateMetadataDependency {
    name: String,
    req: String,
    features: Vec<String>,
    optional: bool,
    default_features: bool,
    target: Option<String>,
    kind: String,
    registry: Option<String>,
    package: Option<String>,
}
