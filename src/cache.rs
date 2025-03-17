use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    path::Path,
    sync::Arc,
};

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use yoke::{Yoke, Yokeable};

use crate::config::{CacheStore, Config};

pub const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

/// Marker trait for values that can be stored within the cache
pub trait Cacheable: Serialize + Send + for<'a> Yokeable<'a> {
    /// The key used to uniquely identify a cache item.
    type Key<'a>: Send + 'a;
    /// A unique kind for the `Cacheable` used to prefix the `Key`.
    const KIND: CacheKind;

    /// Builds the key to store in the cache by prefixing `Self::format_key` with `Self::KIND`.
    fn build_key(k: Self::Key<'_>) -> Vec<u8> {
        let mut key = Vec::new();
        key.push(Self::KIND as u8);
        Self::format_key(&mut key, k);
        key
    }

    /// Serializes `k` to `out`.
    fn format_key(out: &mut Vec<u8>, k: Self::Key<'_>);
}

/// A unique prefix for each type stored within the cache to prevent conflicts.
#[repr(u8)]
pub enum CacheKind {
    Eligibility = 1,
    CrateMetadata = 2,
    PackagePage = 3,
}

/// A generic-erased `Cache`.
#[derive(Clone)]
pub enum ConcreteCache {
    RocksDb(RocksDb),
    InMemory(InMemory),
}

impl ConcreteCache {
    /// Instantiates a new `Cache`.
    pub fn new(config: &Config) -> Result<Self, Error> {
        Ok(match &config.cache {
            CacheStore::RocksDb { path } => Self::RocksDb(RocksDb::new(path)?),
            CacheStore::InMemory => Self::InMemory(InMemory::default()),
        })
    }
}

#[async_trait]
impl Cache for ConcreteCache {
    async fn put<C: Cacheable + Sync>(&self, key: C::Key<'_>, value: &C) -> Result<(), Error> {
        match self {
            Self::RocksDb(r) => r.put(key, value).await,
            Self::InMemory(i) => i.put(key, value).await,
        }
    }

    async fn get<C: Cacheable + 'static>(
        &self,
        key: C::Key<'_>,
    ) -> Result<Option<Yoke<C, Vec<u8>>>, Error>
    where
        for<'a> <C as Yokeable<'a>>::Output: Deserialize<'a>,
    {
        match self {
            Self::RocksDb(r) => r.get(key).await,
            Self::InMemory(i) => i.get(key).await,
        }
    }

    async fn remove<C: Cacheable>(&self, key: C::Key<'_>) -> Result<(), Error> {
        match self {
            Self::RocksDb(r) => r.remove::<C>(key).await,
            Self::InMemory(i) => i.remove::<C>(key).await,
        }
    }
}

#[async_trait]
pub trait Cache {
    /// Inserts a value into the cache.
    async fn put<C: Cacheable + Sync>(&self, key: C::Key<'_>, value: &C) -> Result<(), Error>;

    /// Retrieves a value from the cache.
    async fn get<C: Cacheable + 'static>(
        &self,
        key: C::Key<'_>,
    ) -> Result<Option<Yoke<C, Vec<u8>>>, Error>
    where
        for<'a> <C as Yokeable<'a>>::Output: Deserialize<'a>;

    /// Removes a value from the cache.
    async fn remove<C: Cacheable>(&self, key: C::Key<'_>) -> Result<(), Error>;
}

#[derive(Clone, Default)]
#[allow(clippy::type_complexity)]
pub struct InMemory {
    db: Arc<RwLock<HashMap<Box<[u8]>, Box<[u8]>>>>,
}

#[async_trait]
impl Cache for InMemory {
    async fn put<C: Cacheable + Sync>(&self, key: C::Key<'_>, value: &C) -> Result<(), Error> {
        let serialized = bincode::serde::encode_to_vec(value, BINCODE_CONFIG)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        let key = C::build_key(key);

        self.db
            .write()
            .insert(key.into_boxed_slice(), serialized.into_boxed_slice());

        Ok(())
    }

    async fn get<C: Cacheable + 'static>(
        &self,
        key: C::Key<'_>,
    ) -> Result<Option<Yoke<C, Vec<u8>>>, Error>
    where
        for<'a> <C as Yokeable<'a>>::Output: Deserialize<'a>,
    {
        let key = C::build_key(key);
        let Some(value) = self.db.read().get(key.as_slice()).map(|v| v.to_vec()) else {
            return Ok(None);
        };

        Yoke::try_attach_to_cart(value, |v| {
            bincode::serde::borrow_decode_from_slice(v, BINCODE_CONFIG).map(|(data, _)| data)
        })
        .map(Some)
        .map_err(|e| Error::new(ErrorKind::Other, e))
    }

    async fn remove<C: Cacheable>(&self, key: C::Key<'_>) -> Result<(), Error> {
        self.db.write().remove(C::build_key(key).as_slice());
        Ok(())
    }
}

#[derive(Clone)]
pub struct RocksDb {
    rocks: Arc<rocksdb::DB>,
}

impl RocksDb {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let rocks = rocksdb::DB::open_default(path).map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(Self {
            rocks: Arc::new(rocks),
        })
    }
}

#[async_trait]
impl Cache for RocksDb {
    async fn put<C: Cacheable + Sync>(&self, key: C::Key<'_>, value: &C) -> Result<(), Error> {
        let serialized = bincode::serde::encode_to_vec(value, BINCODE_CONFIG)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let rocks = self.rocks.clone();
        let key = C::build_key(key);

        tokio::task::spawn_blocking(move || {
            rocks
                .put(key, serialized)
                .map_err(|e| Error::new(ErrorKind::Other, e))
        })
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?
    }

    async fn get<C: Cacheable + 'static>(
        &self,
        key: C::Key<'_>,
    ) -> Result<Option<Yoke<C, Vec<u8>>>, Error>
    where
        for<'a> <C as Yokeable<'a>>::Output: Deserialize<'a>,
    {
        let rocks = self.rocks.clone();
        let key = C::build_key(key);

        tokio::task::spawn_blocking(move || {
            rocks
                .get(key)
                .map_err(|e| Error::new(ErrorKind::Other, e))?
                .map(|v| {
                    Yoke::try_attach_to_cart(v, |v| {
                        bincode::serde::borrow_decode_from_slice(v, BINCODE_CONFIG)
                            .map(|(data, _)| data)
                    })
                })
                .transpose()
                .map_err(|e| Error::new(ErrorKind::Other, e))
        })
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?
    }

    async fn remove<C: Cacheable>(&self, key: C::Key<'_>) -> Result<(), Error> {
        let rocks = self.rocks.clone();
        let key = C::build_key(key);

        tokio::task::spawn_blocking(move || {
            rocks
                .delete(key)
                .map_err(|e| Error::new(ErrorKind::Other, e))
        })
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?
    }
}

pub type Yoked<T> = Yoke<T, Vec<u8>>;

#[cfg(test)]
mod test {
    use crate::{
        cache::{Cache, InMemory, RocksDb},
        providers::{EligibilityCacheKey, Release},
    };
    use std::borrow::Cow;
    use tempfile::tempdir;

    async fn test_suite<T: Cache>(cache: T) {
        let out = cache
            .get::<Option<Release<'static>>>(EligibilityCacheKey::new(
                "my-project",
                "my-crate",
                "my-crate-version",
            ))
            .await
            .unwrap();
        assert!(out.is_none());

        cache
            .put(
                EligibilityCacheKey::new("my-project", "my-crate", "my-crate-version"),
                &None,
            )
            .await
            .unwrap();
        let out = cache
            .get::<Option<Release<'static>>>(EligibilityCacheKey::new(
                "my-project",
                "my-crate",
                "my-crate-version",
            ))
            .await
            .unwrap();
        assert!(out.unwrap().get().is_none());

        cache
            .put(
                EligibilityCacheKey::new("my-project", "my-crate", "my-crate-version"),
                &Some(Release {
                    name: Cow::Borrowed("helloworld"),
                    version: Cow::Borrowed("1.0.0"),
                    checksum: Cow::Borrowed("123456"),
                    project: Cow::Borrowed("test"),
                    yanked: false,
                }),
            )
            .await
            .unwrap();
        let out = cache
            .get::<Option<Release<'static>>>(EligibilityCacheKey::new(
                "my-project",
                "my-crate",
                "my-crate-version",
            ))
            .await
            .unwrap();
        assert_eq!(
            out.unwrap().get().as_ref().unwrap().name.as_ref(),
            "helloworld"
        );

        let out = cache
            .get::<Option<Release<'static>>>(EligibilityCacheKey::new(
                "my-project",
                "my-crate",
                "my-crate-version-2",
            ))
            .await
            .unwrap();
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn rocksdb() {
        let temp_dir = tempdir().unwrap();
        let cache = RocksDb::new(temp_dir.path()).unwrap();

        test_suite(cache).await;
    }

    #[tokio::test]
    async fn in_memory() {
        let cache = InMemory::default();
        test_suite(cache).await;
    }
}
