pub mod protocol;
pub mod providers;
pub mod util;

use crate::{providers::{gitlab::Gitlab, PackageProvider, Release, User, UserProvider}, protocol::{codec::Encoder, packet_line::PktLine}};
use futures::Future;
use std::{net::SocketAddr, pin::Pin, sync::Arc, fmt::Write};
use bytes::BytesMut;
use thrussh::{server::{Auth, Session}, ChannelId, CryptoVec};
use thrussh_keys::key::PublicKey;
use tokio::task::JoinHandle;
use tokio_util::codec::Encoder as CodecEncoder;
use crate::protocol::high_level::GitRepository;

const AGENT: &str = concat!(
    "agent=",
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "\n"
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ed25519_key = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();

    let thrussh_config = Arc::new(thrussh::server::Config {
        methods: thrussh::MethodSet::PUBLICKEY,
        keys: vec![ed25519_key],
        ..thrussh::server::Config::default()
    });

    let gitlab = Arc::new(Gitlab::new()?);

    thrussh::server::run(thrussh_config, "127.0.0.1:2222", Server { gitlab }).await?;
    Ok(())
}

struct Server<U: UserProvider + PackageProvider + Send + Sync + 'static> {
    gitlab: Arc<U>,
}

impl<U: UserProvider + PackageProvider + Send + Sync + 'static> thrussh::server::Server
    for Server<U>
{
    type Handler = Handler<U>;

    fn new(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        Handler {
            gitlab: self.gitlab.clone(),
            user: None,
            group: None,
            fetcher_future: None,
            input_bytes: BytesMut::new(),
            output_bytes: BytesMut::new(),
            is_git_protocol_v2: false
        }
    }
}

struct Handler<U: UserProvider + PackageProvider + Send + Sync + 'static> {
    gitlab: Arc<U>,
    user: Option<User>,
    group: Option<String>,
    fetcher_future: Option<JoinHandle<anyhow::Result<Vec<Release>>>>,
    input_bytes: BytesMut,
    output_bytes: BytesMut,
    is_git_protocol_v2: bool,
}

impl<U: UserProvider + PackageProvider + Send + Sync + 'static> Handler<U> {
    fn user(&self) -> anyhow::Result<&User> {
        self.user.as_ref().ok_or(anyhow::anyhow!("no user set"))
    }

    fn group(&self) -> anyhow::Result<&str> {
        self.group.as_deref().ok_or(anyhow::anyhow!("no group set"))
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

    async fn fetch_releases(&self, group: &str) -> anyhow::Result<Vec<Release>> {
        let user = self.user()?;
        self.gitlab.clone().fetch_releases_for_group(group, user.clone()).await
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
                    .find_user_by_ssh_key(&util::format_fingerprint(&fingerprint)?)
                    .await?;
            }

            self.user = Some(user.ok_or(anyhow::anyhow!("failed to find user"))?);

            self.finished_auth(Auth::Accept).await
        })
    }

    fn data(mut self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
        self.input_bytes.extend_from_slice(data);

        Box::pin(
            async move {
                while let Some(frame) = self.codec.decode(&mut self.input_bytes)? {
                    // if the client flushed without giving us a command, we're expected to close
                    // the connection or else the client will just hang
                    if frame.command.is_empty() {
                        session.exit_status_request(channel, 0);
                        session.eof(channel);
                        session.close(channel);
                        return Ok((self, session));
                    }

                    let user = self.user()?;
                    let group = self.group()?;

                    // start building the packfile we're going to send to the user
                    let mut packfile = GitRepository::default();
                }

                Ok((self, session))
            }
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
                let group = group
                    .trim_start_matches('/')
                    .trim_end_matches('/')
                    .to_string();
                self.group = Some(group);
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
