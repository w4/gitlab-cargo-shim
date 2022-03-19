//! A high-level interface for building packfiles. Wraps the `low_level` module
//! making a much easier interface for writing files and generating the root
//! commit.
//!
//! The output packfile will only have a single commit in it, which is fine
//! for our purposes because `cargo` will `git pull --force` from our Git
//! server, allowing us to ignore any history the client may have.

use crate::instrument;
use crate::util::ArcOrCowStr;
use bytes::Bytes;
use indexmap::IndexMap;

use super::low_level::{
    Commit, CommitUserInfo, HashOutput, PackFileEntry, TreeItem as LowLevelTreeItem, TreeItemKind,
};

/// The main way of interacting with the high level Packfile builder
///
/// Builds a whole packfile containing files, directories and commits - essentially
/// building out a full Git repository in memory.
#[derive(Default, Debug)]
pub struct GitRepository {
    /// A map containing all the blobs and their corresponding hashes so they're
    /// not inserted more than once for any files in the whole tree with the same
    /// content.
    packfile_entries: IndexMap<HashOutput, PackFileEntry>,
    /// An in-progress `Tree` currently being built out, the tree refers to items
    /// in `file_entries` by hash.
    tree: Tree,
}

impl GitRepository {
    /// Inserts a file into the repository, writing a file to the path
    /// `path/to/my-file` would require a `path` of `["path", "to"]`
    /// and a `file` of `"my-file"`.
    #[instrument(skip(self, file, content), err)]
    pub fn insert(
        &mut self,
        path: &[&'static str],
        file: ArcOrCowStr,
        content: Bytes,
    ) -> Result<(), anyhow::Error> {
        // we'll initialise the directory to the root of the tree, this means
        // if a path isn't specified we'll just write it to the root directory
        let mut directory = &mut self.tree;

        // loops through the parts in the path, recursing through the `directory`
        // `Tree` until we get to our target directory, creating any missing
        // directories along the way.
        for part in path {
            let tree_item = directory
                .0
                .entry((*part).into())
                .or_insert_with(|| Box::new(TreeItem::Tree(Tree::default())));

            if let TreeItem::Tree(d) = tree_item.as_mut() {
                directory = d;
            } else {
                // TODO: how should we handle this? one of items we tried to
                //  recurse into was a file.
                anyhow::bail!("attempted to use a file as a directory");
            }
        }

        // wrap the file in a Blob so it's ready for writing into the packfile, and also
        // allows us to grab the hash of the file for use in the tree
        let entry = PackFileEntry::Blob(content);
        let file_hash = entry.hash()?;

        // todo: what should we do on overwrite?
        directory
            .0
            .insert(file, Box::new(TreeItem::Blob(file_hash)));

        self.packfile_entries.insert(file_hash, entry);

        Ok(())
    }

    /// Finalises this `GitRepository` by writing a commit to the `packfile_entries`,
    /// all the files currently in the `tree`, returning all the packfile entries
    /// and also the commit hash so it can be referred to by `ls-ref`s.
    #[instrument(skip(self, name, email, message), err)]
    pub fn commit(
        mut self,
        name: &'static str,
        email: &'static str,
        message: &'static str,
    ) -> Result<(HashOutput, Vec<PackFileEntry>), anyhow::Error> {
        // gets the hash of the entire tree from the root
        let tree_hash = self
            .tree
            .into_packfile_entries(&mut self.packfile_entries)?;

        // build the commit using the given inputs
        let commit_user = CommitUserInfo {
            name,
            email,
            time: time::OffsetDateTime::now_utc(),
        };

        let commit = PackFileEntry::Commit(Commit {
            tree: tree_hash,
            author: commit_user,
            committer: commit_user,
            message,
        });

        // write the commit out to the packfile_entries
        let commit_hash = commit.hash()?;
        self.packfile_entries.insert(commit_hash, commit);

        Ok((
            commit_hash,
            self.packfile_entries.into_iter().map(|(_, v)| v).collect(),
        ))
    }
}

/// An in-progress tree builder, containing file hashes along with their names or nested trees
#[derive(Default, Debug)]
struct Tree(IndexMap<ArcOrCowStr, Box<TreeItem>>);

impl Tree {
    /// Recursively writes the the whole tree out to the given `pack_file`,
    /// the tree contains pointers to (hashes of) files contained within a
    /// directory, and pointers to other directories.
    #[instrument(skip(self, pack_file), err)]
    fn into_packfile_entries(
        self,
        pack_file: &mut IndexMap<HashOutput, PackFileEntry>,
    ) -> Result<HashOutput, anyhow::Error> {
        let mut tree = Vec::with_capacity(self.0.len());

        for (name, item) in self.0 {
            tree.push(match *item {
                TreeItem::Blob(hash) => LowLevelTreeItem {
                    kind: TreeItemKind::File,
                    sort_name: name.to_string(),
                    name,
                    hash,
                },
                TreeItem::Tree(tree) => LowLevelTreeItem {
                    kind: TreeItemKind::Directory,
                    sort_name: format!("{}/", name),
                    name,
                    // we're essentially working through our tree from the bottom up,
                    // so we can grab the hash of each directory along the way and
                    // reference it from the parent directory
                    hash: tree.into_packfile_entries(pack_file)?,
                },
            });
        }

        // we need to sort our tree alphabetically, otherwise Git will silently
        // stop parsing the rest of the tree once it comes across a non-sorted
        // tree entry.
        tree.sort_unstable_by(|a, b| a.sort_name.cmp(&b.sort_name));

        // gets the hash of the tree we've just worked on, and
        // pushes it to the packfile
        let tree = PackFileEntry::Tree(tree);
        let hash = tree.hash()?;
        pack_file.insert(hash, tree);

        Ok(hash)
    }
}

/// An item within a `Tree`, this could be a file blob or another directory.
#[derive(Debug)]
enum TreeItem {
    /// Refers to a file by hash
    Blob(HashOutput),
    /// Refers to a nested directory
    Tree(Tree),
}
