use parking_lot::RwLock;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use smol_str::SmolStr;
use std::{collections::HashMap, sync::Arc};

/// Cache of fetched `/package_files` checksums fetched from
/// <https://docs.gitlab.com/ee/api/packages.html#list-package-files>
#[derive(Debug, Default)]
pub struct ChecksumCache {
    checksums: RwLock<HashMap<Key, Arc<str>>>,
}

impl ChecksumCache {
    pub fn get(&self, key: &Key) -> Option<Arc<str>> {
        self.checksums.read().get(key).cloned()
    }

    pub fn set(&self, key: Key, checksum: Arc<str>) {
        self.checksums.write().insert(key, checksum);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub base_url: SmolStr,
    pub project: SmolStr,
    pub package: SmolStr,
    pub file_name: SmolStr,
}

impl Key {
    pub fn fetch_url(&self) -> String {
        format!(
            "{}/projects/{}/packages/{}/package_files",
            self.base_url,
            utf8_percent_encode(self.project.as_str(), NON_ALPHANUMERIC),
            utf8_percent_encode(self.package.as_str(), NON_ALPHANUMERIC),
        )
    }
}
