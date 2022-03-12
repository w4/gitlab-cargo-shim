#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

pub mod git_command_handlers;
pub mod metadata;
pub mod protocol;
pub mod providers;
pub mod util;

use crate::metadata::CargoIndexCrateMetadata;
use crate::protocol::low_level::{HashOutput, PackFileEntry};
use crate::providers::Group;
use crate::util::get_crate_folder;
use crate::{
    protocol::{
        codec::{Encoder, GitCodec},
        high_level::GitRepository,
        packet_line::PktLine,
    },
    providers::{gitlab::Gitlab, PackageProvider, Release, User, UserProvider},
};
use anyhow::anyhow;
use bytes::{BufMut, Bytes, BytesMut};
use futures::Future;
use parking_lot::RwLock;
use std::{borrow::Cow, collections::HashMap, fmt::Write, net::SocketAddr, pin::Pin, sync::Arc};
use thrussh::{
    server::{Auth, Session},
    ChannelId, CryptoVec,
};
use thrussh_keys::key::PublicKey;
use tokio_util::{codec::Decoder, codec::Encoder as CodecEncoder};
use tracing::error;

const AGENT: &str = concat!(
    "agent=",
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "\n"
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let ed25519_key = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();

    let thrussh_config = Arc::new(thrussh::server::Config {
        methods: thrussh::MethodSet::PUBLICKEY,
        keys: vec![ed25519_key],
        ..thrussh::server::Config::default()
    });

    let gitlab = Arc::new(Gitlab::new()?);

    thrussh::server::run(
        thrussh_config,
        "127.0.0.1:2210",
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
    metadata_cache: MetadataCache,
}

impl<U: UserProvider + PackageProvider + Send + Sync + 'static> thrussh::server::Server
    for Server<U>
{
    type Handler = Handler<U>;

    fn new(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        Handler {
            codec: GitCodec::default(),
            gitlab: Arc::clone(&self.gitlab),
            user: None,
            group: None,
            // fetcher_future: None,
            input_bytes: BytesMut::new(),
            output_bytes: BytesMut::new(),
            is_git_protocol_v2: false,
            metadata_cache: Arc::clone(&self.metadata_cache),
            packfile_cache: None,
        }
    }
}

pub struct Handler<U: UserProvider + PackageProvider + Send + Sync + 'static> {
    codec: GitCodec,
    gitlab: Arc<U>,
    user: Option<User>,
    group: Option<Group>,
    // fetcher_future: Option<JoinHandle<anyhow::Result<Vec<Release>>>>,
    input_bytes: BytesMut,
    output_bytes: BytesMut,
    is_git_protocol_v2: bool,
    metadata_cache: MetadataCache,
    // Cache of the packfile generated for this user in case it's requested
    // more than once
    packfile_cache: Option<Arc<(HashOutput, Vec<PackFileEntry>)>>,
}

impl<U: UserProvider + PackageProvider + Send + Sync + 'static> Handler<U> {
    fn user(&self) -> anyhow::Result<&User> {
        self.user.as_ref().ok_or(anyhow::anyhow!("no user set"))
    }

    fn group(&self) -> anyhow::Result<&Group> {
        self.group.as_ref().ok_or(anyhow::anyhow!("no group set"))
    }

    fn write(&mut self, packet: PktLine<'_>) -> Result<(), anyhow::Error> {
        Encoder.encode(packet, &mut self.output_bytes)
    }

    fn flush(&mut self, session: &mut Session, channel: ChannelId) {
        session.data(
            channel,
            CryptoVec::from_slice(self.output_bytes.split().as_ref()),
        );
    }

    async fn fetch_releases_by_crate(
        &self,
    ) -> anyhow::Result<HashMap<(U::CratePath, String), Vec<Release>>> {
        let user = self.user()?;
        let group = self.group()?;

        let mut res = HashMap::new();

        for (path, release) in Arc::clone(&self.gitlab)
            .fetch_releases_for_group(group, user)
            .await?
        {
            res.entry((path, release.name.clone()))
                .or_insert_with(Vec::new)
                .push(release);
        }

        Ok(res)
    }

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

        {
            let reader = self.metadata_cache.read();
            if let Some(cache) = reader.get(&key) {
                return Ok(Arc::clone(cache));
            }
        }

        let metadata = Arc::clone(&self.gitlab)
            .fetch_metadata_for_release(path, crate_version)
            .await?;

        // transform the `cargo metadata` output to the cargo index
        // format
        let cksum = checksum.to_string();
        let metadata = metadata::transform(metadata, crate_name, cksum)
            .map(Arc::new)
            .ok_or_else(|| anyhow!("the supplied metadata.json did contain the released crate"))?;

        {
            let mut writer = self.metadata_cache.write();
            writer.insert(key.into_owned(), Arc::clone(&metadata));
        }

        Ok(metadata)
    }

    async fn build_packfile(&mut self) -> anyhow::Result<Arc<(HashOutput, Vec<PackFileEntry>)>> {
        if let Some(packfile_cache) = &self.packfile_cache {
            return Ok(packfile_cache.clone());
        }

        let mut packfile = GitRepository::default();

        let user = self.user()?;
        let group = self.group()?;

        let token = self.gitlab.fetch_token_for_user(user).await?;

        let config_json = Bytes::from(format!(
            "{{\"dl\": \"{}\"}}",
            self.gitlab.cargo_dl_uri(group, &token)
        ));

        // write config.json to the root of the repo
        packfile.insert(vec![], "config.json".to_string(), config_json)?;

        // fetch the releases for every project within the given group
        let releases_by_crate = self.fetch_releases_by_crate().await?;

        let mut buffer = BytesMut::new();

        for ((crate_path, crate_name), releases) in &releases_by_crate {
            for release in releases {
                let checksum = &release.checksum;
                let version = &release.version;

                // parses the `cargo metadata` stored in the release, which
                // should be stored under `metadata.json`.
                let meta = self
                    .fetch_metadata(crate_path, checksum, crate_name, version)
                    .await?;

                buffer.extend_from_slice(&serde_json::to_vec(&*meta).unwrap());
                buffer.put_u8(b'\n');
            }

            packfile.insert(
                get_crate_folder(crate_name),
                crate_name.to_string(),
                buffer.split().freeze(),
            )?;
        }

        let packfile = Arc::new(packfile.commit(
            "test".to_string(),
            "test@test.com".to_string(),
            "test".to_string(),
        )?);

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

        Box::pin(async move {
            let mut user = self
                .gitlab
                .find_user_by_username_password_combo(&user)
                .await?;

            if user.is_none() {
                user = self
                    .gitlab
                    .find_user_by_ssh_key(&util::format_fingerprint(&fingerprint))
                    .await?;
            }

            if let Some(user) = user {
                self.user = Some(user);
                self.finished_auth(Auth::Accept).await
            } else {
                self.finished_auth(Auth::Reject).await
            }
        })
    }

    fn data(mut self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
        self.input_bytes.extend_from_slice(data);

        Box::pin(async move {
            // start building the packfile we're going to send to the user
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
        Box::pin(async move {
            let username = self.user()?.username.clone();
            write!(
                &mut self.output_bytes,
                "Hi there, {}! You've successfully authenticated, but {} does not provide shell access.\r\n",
                username,
                env!("CARGO_PKG_NAME")
            )?;
            self.flush(&mut session, channel);
            session.close(channel);
            Ok((self, session))
        })
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
        let data = match std::str::from_utf8(data) {
            Ok(data) => data,
            Err(e) => return Box::pin(futures::future::err(e.into())),
        };
        // parses the given args in the same fashion as a POSIX shell
        let args = shlex::split(data);

        Box::pin(async move {
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

            // parse the requested group from the given path (the argument
            // given to `git-upload-pack`)
            if let Some(group) = args.next().filter(|v| v.as_str() != "/") {
                let user = self.user()?;
                let group = group.trim_start_matches('/').trim_end_matches('/');

                match Arc::clone(&self.gitlab).fetch_group(group, user).await {
                    Ok(v) => self.group = Some(v),
                    Err(e) => {
                        session.extended_data(channel, 1, CryptoVec::from_slice(format!(indoc::indoc! {"
                            \r\nGitLab returned an error when attempting to query for group `{}` as `{}`:

                                {}

                            The group might not exist or you may not have permission to view it.\r\n
                        "}, group, user.username, e).as_bytes()));
                        session.close(channel);
                    }
                }
            } else {
                session.extended_data(channel, 1, CryptoVec::from_slice(indoc::indoc! {b"
                    \r\nNo group was given in the path part of the SSH URI. A GitLab group should be defined in your .cargo/config.toml as follows:
                        [registries]
                        chartered = {{ index = \"ssh://domain.to.registry.com/my-group\" }}\r\n
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
        })
    }
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
