use crate::{
    providers::{PackageProvider, UserProvider},
    Handler,
};
use anyhow::{bail, Context};
use thrussh::server::Session;
use thrussh::{ChannelId, CryptoVec};
use tracing::instrument;

#[instrument(skip_all, err)]
pub async fn handle<U: UserProvider + PackageProvider + Send + Sync + 'static>(
    handle: &mut Handler<U>,
    session: &mut Session,
    channel: ChannelId,
    mut params: impl Iterator<Item = String>,
) -> Result<(), anyhow::Error> {
    let (Some(project), Some(crate_name), Some(version)) =
        (params.next(), params.next(), params.next())
    else {
        bail!("usage: bust-cache [gitlab project] [crate name] [version]");
    };

    if !handle
        .gitlab
        .is_project_maintainer(handle.user()?, &project)
        .await
        .context("Failed to check project maintainer status")?
    {
        bail!("This command can only be ran by project maintainers");
    }

    handle
        .gitlab
        .bust_cache(&project, &crate_name, &version)
        .await?;

    session.data(
        channel,
        CryptoVec::from_slice("Successfully bust cache for release.".as_bytes()),
    );
    session.exit_status_request(channel, 0);
    session.close(channel);

    Ok(())
}
