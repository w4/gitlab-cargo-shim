use bytes::Bytes;
use thrussh::{server::Session, ChannelId};

use crate::{
    protocol::{
        low_level::{PackFile, PackFileEntry},
        packet_line::PktLine,
    },
    Handler, PackageProvider, UserProvider,
};

pub fn handle<U: UserProvider + PackageProvider + Send + Sync + 'static>(
    handle: &mut Handler<U>,
    session: &mut Session,
    channel: ChannelId,
    metadata: Vec<Bytes>,
    packfile_entries: Vec<PackFileEntry>,
) -> Result<(), anyhow::Error> {
    // the client sending us `done` in the metadata means they know there's no negotiation
    // required for which commits we need to send, they just want us to send whatever we
    // have.
    let done = metadata.iter().any(|v| v.as_ref() == b"done");

    // the client thinks we can negotiate some commits with them, but we don't want to so
    // we'll just say we've got nothing in common and continue on as we were.
    if !done {
        handle.write(PktLine::Data(b"acknowledgments\n"))?;
        handle.write(PktLine::Data(b"ready\n"))?;
        handle.write(PktLine::Delimiter)?;
    }

    // magic header
    handle.write(PktLine::Data(b"packfile\n"))?;

    // send the complete packfile
    let packfile = PackFile::new(packfile_entries);
    handle.write(PktLine::SidebandData(packfile))?;
    handle.write(PktLine::Flush)?;
    handle.flush(session, channel);

    // tell the client we exited successfully and close the channel
    session.exit_status_request(channel, 0);
    session.eof(channel);
    session.close(channel);

    Ok(())
}
