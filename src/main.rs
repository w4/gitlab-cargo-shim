#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

pub mod config;
pub mod git_command_handlers;
pub mod metadata;
pub mod protocol;
pub mod providers;
pub mod util;

use crate::{
    config::Args,
    metadata::{CargoConfig, CargoIndexCrateMetadata},
    protocol::{
        codec::{Encoder, GitCodec},
        high_level::GitRepository,
        low_level::{HashOutput, PackFileEntry},
        packet_line::PktLine,
    },
    providers::{gitlab::Gitlab, PackageProvider, Release, ReleaseName, User, UserProvider},
    util::get_crate_folder,
};
use anyhow::anyhow;
use bytes::{BufMut, Bytes, BytesMut};
use clap::Parser;
use futures::Future;
use indexmap::IndexMap;
use parking_lot::RwLock;
use std::{
    borrow::Cow, collections::HashMap, fmt::Write, net::SocketAddr, net::SocketAddrV6, pin::Pin,
    str::FromStr, sync::Arc,
};
use thrussh::{
    server::{Auth, Session},
    ChannelId, CryptoVec,
};
use thrussh_keys::key::PublicKey;
use tokio_util::{codec::Decoder, codec::Encoder as CodecEncoder};
use tracing::{debug, error, info, info_span, instrument, Instrument, Span};
use uuid::Uuid;

const AGENT: &str = concat!(
    "agent=",
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "\n"
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::fmt();
    #[cfg(debug_assertions)]
    let subscriber = subscriber.pretty();
    subscriber.init();

    let args: Args = Args::parse();

    if !args.config.state_directory.exists() {
        std::fs::create_dir_all(&args.config.state_directory)?;
    }

    let server_private_key = args.config.state_directory.join("ssh-private-key.pem");

    let key = if server_private_key.exists() {
        let key_bytes = std::fs::read(&server_private_key)?;
        if key_bytes.len() != 64 {
            anyhow::bail!(
                "invalid private key. length = {}, expected = 64",
                key_bytes.len()
            );
        }

        let mut key = [0_u8; 64];
        key.copy_from_slice(&key_bytes);

        thrussh_keys::key::KeyPair::Ed25519(thrussh_keys::key::ed25519::SecretKey { key })
    } else {
        info!(
            "Generating new server private key to {}",
            server_private_key.display()
        );

        let key = thrussh_keys::key::KeyPair::generate_ed25519()
            .ok_or_else(|| anyhow!("failed to generate server private key"))?;
        let thrussh_keys::key::KeyPair::Ed25519(key) = key;

        std::fs::write(server_private_key, &key.key)?;

        thrussh_keys::key::KeyPair::Ed25519(key)
    };

    let thrussh_config = Arc::new(thrussh::server::Config {
        methods: thrussh::MethodSet::PUBLICKEY,
        keys: vec![key],
        ..thrussh::server::Config::default()
    });

    let gitlab = Arc::new(Gitlab::new(&args.config.gitlab)?);

    thrussh::server::run(
        thrussh_config,
        &args.config.listen_address.to_string(),
        Server {
            gitlab,
            metadata_cache: MetadataCache::default(),
        },
    )
    .await?;
    Ok(())
}

type MetadataCache = Arc<RwLock<HashMap<MetadataCacheKey<'static>, Arc<CargoIndexCrateMetadata>>>>;

struct Server<U: UserProvider + PackageProvider + Send + Sync + 'static> {
    gitlab: Arc<U>,
    // todo: we could make our commit hash stable by leaving an update time
    //  in this cache and using that as our commit time
    metadata_cache: MetadataCache,
}

impl<U: UserProvider + PackageProvider + Send + Sync + 'static> thrussh::server::Server
    for Server<U>
{
    type Handler = Handler<U>;

    fn new(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        let connection_id = Uuid::new_v4();
        let peer_addr =
            peer_addr.unwrap_or_else(|| SocketAddrV6::from_str("[::]:0").unwrap().into());
        let span = info_span!("ssh", ?peer_addr, ?connection_id);

        info!(parent: &span, "Incoming connection");

        Handler {
            codec: GitCodec::default(),
            gitlab: Arc::clone(&self.gitlab),
            user: None,
            project: None,
            input_bytes: BytesMut::new(),
            output_bytes: BytesMut::new(),
            is_git_protocol_v2: false,
            metadata_cache: Arc::clone(&self.metadata_cache),
            span,
            packfile_cache: None,
        }
    }
}

pub struct Handler<U: UserProvider + PackageProvider + Send + Sync + 'static> {
    codec: GitCodec,
    gitlab: Arc<U>,
    user: Option<Arc<User>>,
    project: Option<Arc<str>>,
    // fetcher_future: Option<JoinHandle<anyhow::Result<Vec<Release>>>>,
    input_bytes: BytesMut,
    output_bytes: BytesMut,
    is_git_protocol_v2: bool,
    metadata_cache: MetadataCache,
    span: Span,
    // Cache of the packfile generated for this user in case it's requested
    // more than once
    packfile_cache: Option<Arc<(HashOutput, Vec<PackFileEntry>)>>,
}

impl<U: UserProvider + PackageProvider + Send + Sync + 'static> Handler<U> {
    fn user(&self) -> anyhow::Result<&Arc<User>> {
        self.user
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no user set"))
    }

    fn project(&self) -> anyhow::Result<&str> {
        self.project
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no project set"))
    }

    /// Writes a Git packet line response to the buffer, this should only
    /// be used once the client opens a `shell_request`.
    fn write(&mut self, packet: PktLine<'_>) -> Result<(), anyhow::Error> {
        Encoder.encode(packet, &mut self.output_bytes)
    }

    /// Flushes the buffer out to the client
    fn flush(&mut self, session: &mut Session, channel: ChannelId) {
        session.data(
            channel,
            CryptoVec::from_slice(self.output_bytes.split().as_ref()),
        );
    }

    /// Fetches all the releases from the provider for the given project
    /// and groups them by crate.
    #[instrument(skip(self), err)]
    async fn fetch_releases_by_crate(
        &self,
    ) -> anyhow::Result<IndexMap<(U::CratePath, ReleaseName), Vec<Release>>> {
        let user = self.user()?;
        let project = self.project()?;

        let mut res = IndexMap::new();

        for (path, release) in Arc::clone(&self.gitlab)
            .fetch_releases_for_project(project, user)
            .await?
        {
            res.entry((path, Arc::clone(&release.name)))
                .or_insert_with(Vec::new)
                .push(release);
        }

        Ok(res)
    }

    /// Fetches metadata from the provider for a given crate, this is
    /// globally cache-able since it's immutable, to get to this call
    /// the user must've already fetched the crate path from the provider
    /// and hence verified they have permission to read it.
    #[instrument(skip(self), err)]
    async fn fetch_metadata(
        &self,
        path: &U::CratePath,
        checksum: &str,
        crate_name: &str,
        crate_version: &str,
    ) -> anyhow::Result<Arc<CargoIndexCrateMetadata>> {
        let key = MetadataCacheKey {
            checksum: checksum.into(),
            crate_name: crate_name.into(),
            crate_version: crate_version.into(),
        };

        // check if the crate metadata already exists in our cache, if it does
        // we'll just return that
        {
            let reader = self.metadata_cache.read();
            if let Some(cache) = reader.get(&key) {
                return Ok(Arc::clone(cache));
            }
        }

        // fetch metadata from the provider
        let metadata = Arc::clone(&self.gitlab)
            .fetch_metadata_for_release(path, crate_version)
            .await?;

        // transform the `cargo metadata` output to the cargo index
        // format
        let cksum = checksum.to_string();
        let metadata = metadata::transform(metadata, crate_name, cksum)
            .map(Arc::new)
            .ok_or_else(|| anyhow!("the supplied metadata.json did contain the released crate"))?;

        // cache the transformed value so the next user to pull it
        // doesn't have to wait for _yet another_ gitlab call
        {
            let mut writer = self.metadata_cache.write();
            writer.insert(key.into_owned(), Arc::clone(&metadata));
        }

        Ok(metadata)
    }

    // Builds the packfile for the current connection, and caches it in case
    // this function is called again (ie. the client calling `ls-ref`s before
    // `fetch` will result in two calls). The output isn't deterministic because
    // the datetime is included in the commit causing the hash to change, by
    // caching we ensure that:
    //
    //   1. the client receives the expected refs when calling `fetch`,
    //   2. we don't do the relatively expensive processing that comes with
    //      generating the packfile more than once per connection.
    #[instrument(skip(self), err)]
    async fn build_packfile(&mut self) -> anyhow::Result<Arc<(HashOutput, Vec<PackFileEntry>)>> {
        // return the cached value if we've generated the packfile for
        // this connection already
        if let Some(packfile_cache) = &self.packfile_cache {
            return Ok(Arc::clone(packfile_cache));
        }

        // create the high-level packfile generator
        let mut packfile = GitRepository::default();

        let project = self.project()?;

        // fetch the impersonation token for the user we'll embed
        // the `dl` string.
        let token = self.gitlab.fetch_token_for_user(self.user()?).await?;

        // generate the config for the user, containing the download
        // url template from gitlab and the impersonation token embedded
        let config_json = Bytes::from(serde_json::to_vec(&CargoConfig {
            dl: self.gitlab.cargo_dl_uri(project, &token)?,
        })?);

        // write config.json to the root of the repo
        packfile.insert(&[], "config.json".into(), config_json)?;

        // fetch the releases for every project within the given project
        let releases_by_crate = self.fetch_releases_by_crate().await?;

        // a reusable buffer for writing the metadata json blobs out to
        // for each package
        let mut buffer = BytesMut::new();

        for ((crate_path, crate_name), releases) in &releases_by_crate {
            for release in releases {
                let checksum = &release.checksum;
                let version = &release.version;

                debug!("Fetching metadata for {}-{}", crate_name, version);

                // parses the `cargo metadata` stored in the release, which
                // should be stored under `metadata.json`.
                let meta = self
                    .fetch_metadata(crate_path, checksum, crate_name, version)
                    .await?;

                // each crates file in the index is a metadata blob for
                // each version separated by a newline
                buffer.extend_from_slice(&serde_json::to_vec(&*meta)?);
                buffer.put_u8(b'\n');
            }

            // insert the crate version metadata into the packfile
            packfile.insert(
                &get_crate_folder(crate_name),
                Arc::clone(crate_name).into(),
                buffer.split().freeze(),
            )?;
        }

        // build a commit for all of our inserted files and build
        // into its lower-level `Vec<PackFileEntry>` counter-part.
        let packfile = Arc::new(packfile.commit(
            env!("CARGO_PKG_NAME"),
            "noreply@chart.rs",
            "Latest crates from GitLab",
        )?);

        // cache the built packfile for the next time this
        // function is called from this connection
        self.packfile_cache = Some(Arc::clone(&packfile));

        Ok(packfile)
    }
}

type AsyncHandlerFut<T, U> =
    dyn Future<Output = Result<T, <Handler<U> as thrussh::server::Handler>::Error>> + Send;

#[allow(clippy::type_complexity)]
impl<'a, U: UserProvider + PackageProvider + Send + Sync + 'static> thrussh::server::Handler
    for Handler<U>
{
    type Error = anyhow::Error;
    type FutureAuth = Pin<Box<AsyncHandlerFut<(Handler<U>, Auth), U>>>;
    type FutureUnit = Pin<Box<AsyncHandlerFut<(Handler<U>, Session), U>>>;
    type FutureBool = futures::future::Ready<anyhow::Result<(Self, Session, bool)>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        Box::pin(futures::future::ready(Ok((self, auth))))
    }

    fn finished_bool(self, b: bool, session: Session) -> Self::FutureBool {
        futures::future::ready(Ok((self, session, b)))
    }

    fn finished(self, session: Session) -> Self::FutureUnit {
        Box::pin(futures::future::ready(Ok((self, session))))
    }

    fn auth_publickey(mut self, user: &str, public_key: &PublicKey) -> Self::FutureAuth {
        let fingerprint = public_key.fingerprint();
        let user = user.to_string();
        let span = info_span!(parent: &self.span, "auth_publickey", ?fingerprint);

        Box::pin(
            capture_errors(async move {
                // username:password combo is used by CI to authenticate to us,
                // it does not allow users to authenticate directly. it's
                // technically the SSH username that contains both the username
                // and password as we don't want an interactive prompt or
                // anything like that
                let mut by_ssh_key = false;
                let mut user = self
                    .gitlab
                    .find_user_by_username_password_combo(&user)
                    .await?;

                // if there was no username:password combo given we'll lookup
                // the user by the SSH key they're connecting to us with
                if user.is_none() {
                    by_ssh_key = true;
                    user = self
                        .gitlab
                        .find_user_by_ssh_key(&util::format_fingerprint(&fingerprint))
                        .await?;
                }

                if let Some(user) = user {
                    info!(
                        "Successfully authenticated for GitLab user `{}` by {}",
                        &user.username,
                        if by_ssh_key { "SSH Key" } else { "Build Token" },
                    );
                    self.user = Some(Arc::new(user));
                    self.finished_auth(Auth::Accept).await
                } else {
                    info!("Public key rejected");
                    self.finished_auth(Auth::Reject).await
                }
            })
            .instrument(span),
        )
    }

    fn data(mut self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
        let span = info_span!(parent: &self.span, "data");

        self.input_bytes.extend_from_slice(data);

        Box::pin(
            capture_errors(async move {
                // build the packfile we're going to send to the user
                let (commit_hash, packfile_entries) = &*self.build_packfile().await?;

                while let Some(frame) = self.codec.decode(&mut self.input_bytes)? {
                    // if the client flushed without giving us a command, we're expected to close
                    // the connection or else the client will just hang
                    if frame.command.is_empty() {
                        session.exit_status_request(channel, 0);
                        session.eof(channel);
                        session.close(channel);
                        return Ok((self, session));
                    }

                    match frame.command.as_ref() {
                        b"command=ls-refs" => {
                            git_command_handlers::ls_refs::handle(
                                &mut self,
                                &mut session,
                                channel,
                                &frame.metadata,
                                commit_hash,
                            )?;
                        }
                        b"command=fetch" => {
                            git_command_handlers::fetch::handle(
                                &mut self,
                                &mut session,
                                channel,
                                &frame.metadata,
                                packfile_entries,
                            )?;
                        }
                        v => {
                            error!(
                                "Client sent unknown command, ignoring command {}",
                                std::str::from_utf8(v).unwrap_or("invalid utf8")
                            );
                        }
                    }
                }

                Ok((self, session))
            })
            .instrument(span),
        )
    }

    fn env_request(
        mut self,
        _channel: ChannelId,
        name: &str,
        value: &str,
        session: Session,
    ) -> Self::FutureUnit {
        #[allow(clippy::single_match)]
        match (name, value) {
            ("GIT_PROTOCOL", "version=2") => self.is_git_protocol_v2 = true,
            _ => {}
        }

        Box::pin(futures::future::ready(Ok((self, session))))
    }

    fn shell_request(mut self, channel: ChannelId, mut session: Session) -> Self::FutureUnit {
        let span = info_span!(parent: &self.span, "shell_request");

        Box::pin(capture_errors(async move {
            let user = Arc::clone(self.user()?);
            write!(
                &mut self.output_bytes,
                "Hi there, {}! You've successfully authenticated, but {} does not provide shell access.\r\n",
                user.username,
                env!("CARGO_PKG_NAME")
            )?;
            info!("Shell requested, dropping connection");
            self.flush(&mut session, channel);
            session.close(channel);
            Ok((self, session))
        }).instrument(span))
    }

    /// Initially when setting up the SSH connection, the remote Git client will send us an
    /// exec request (instead of the usual shell request that is sent when invoking `ssh`).
    ///
    /// The client will set `git-upload-pack` as the requested executable to run and also
    /// sends the path that was appended to the end of the connection string defined in
    /// cargo.
    fn exec_request(
        mut self,
        channel: ChannelId,
        data: &[u8],
        mut session: Session,
    ) -> Self::FutureUnit {
        let span = info_span!(parent: &self.span, "exec_request");

        let data = match std::str::from_utf8(data) {
            Ok(data) => data,
            Err(e) => {
                return Box::pin(capture_errors(futures::future::err(e.into())).instrument(span))
            }
        };
        // parses the given args in the same fashion as a POSIX shell
        let args = shlex::split(data);

        Box::pin(capture_errors(async move {
            // if the client didn't send `GIT_PROTOCOL=version=2` as an environment
            // variable when connecting, we'll just close the connection
            if !self.is_git_protocol_v2 {
                anyhow::bail!("not git protocol v2");
            }

            let mut args = args.into_iter().flat_map(Vec::into_iter);

            // check the executable requested to be ran is the `git-upload-pack` we
            // expect. we're not actually going to execute this, but we'll pretend
            // to be it instead in `data`.
            if args.next().as_deref() != Some("git-upload-pack") {
                anyhow::bail!("not git-upload-pack");
            }

            // parse the requested project from the given path (the argument
            // given to `git-upload-pack`)
            let arg = args.next();
            if let Some(project) = arg.as_deref()
                .filter(|v| *v != "/")
                .map(|project| project.trim_start_matches('/').trim_end_matches('/'))
                .filter(|project| project.contains('/'))
            {
                self.project = Some(Arc::from(project.to_string()));
            } else {
                session.extended_data(channel, 1, CryptoVec::from_slice(indoc::indoc! {b"
                    \r\nNo project was given in the path part of the SSH URI. A GitLab group and project should be defined in your .cargo/config.toml as follows:
                        [registries]
                        my-project = {{ index = \"ssh://domain.to.registry.com/my-group/my-project\" }}\r\n
                "}));
                session.close(channel);
            }

            // preamble, sending our capabilities and what have you
            self.write(PktLine::Data(b"version 2\n"))?;
            self.write(PktLine::Data(AGENT.as_bytes()))?;
            self.write(PktLine::Data(b"ls-refs=unborn\n"))?;
            self.write(PktLine::Data(b"fetch=shallow wait-for-done\n"))?;
            self.write(PktLine::Data(b"server-option\n"))?;
            self.write(PktLine::Data(b"object-info\n"))?;
            self.write(PktLine::Flush)?;
            self.flush(&mut session, channel);

            Ok((self, session))
        }).instrument(span))
    }
}

// a workaround for trussh swallowing errors
async fn capture_errors<T>(
    fut: impl Future<Output = Result<T, anyhow::Error>>,
) -> Result<T, anyhow::Error> {
    let res = fut.await;

    if let Err(e) = &res {
        error!("Error: {}", e);
    }

    res
}

#[derive(Hash, Debug, PartialEq, Eq)]
struct MetadataCacheKey<'a> {
    checksum: Cow<'a, str>,
    crate_name: Cow<'a, str>,
    crate_version: Cow<'a, str>,
}

impl MetadataCacheKey<'_> {
    pub fn into_owned(self) -> MetadataCacheKey<'static> {
        MetadataCacheKey {
            checksum: self.checksum.into_owned().into(),
            crate_name: self.crate_name.into_owned().into(),
            crate_version: self.crate_version.into_owned().into(),
        }
    }
}
