use arrayvec::ArrayVec;
use std::{
    borrow::Cow,
    fmt::{Debug, Display, Formatter},
    ops::Deref,
    sync::Arc,
};
use ustr::ustr;

#[must_use]
pub fn format_fingerprint(fingerprint: &str) -> String {
    format!("SHA256:{}", fingerprint)
}

/// Crates with a total of 1, 2 characters in the same are written out to directories named
/// 1, 2 respectively as per the cargo spec. With a total of 3 characters they're stored in a
/// directory named 3 and then a subdirectory named after the first letter of the crate's name.
/// Anything else we'll build out a normal tree for using the first four characters of the crate
/// name, 2 for the first directory and the other 2 for the second.
#[must_use]
pub fn get_crate_folder(crate_name: &str) -> ArrayVec<&'static str, 2> {
    let mut folders = ArrayVec::new();

    match crate_name.len() {
        0 => {}
        1 => folders.push("1"),
        2 => folders.push("2"),
        3 => {
            folders.push("3");
            folders.push(ustr(&crate_name[..1]).as_str());
        }
        _ => {
            folders.push(ustr(&crate_name[..2]).as_str());
            folders.push(ustr(&crate_name[2..4]).as_str());
        }
    }

    folders
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum ArcOrCowStr {
    Arc(Arc<str>),
    Cow(Cow<'static, str>),
}

impl From<Arc<str>> for ArcOrCowStr {
    fn from(v: Arc<str>) -> Self {
        Self::Arc(v)
    }
}

impl From<Cow<'static, str>> for ArcOrCowStr {
    fn from(v: Cow<'static, str>) -> Self {
        Self::Cow(v)
    }
}

impl From<&'static str> for ArcOrCowStr {
    fn from(v: &'static str) -> Self {
        Self::Cow(Cow::Borrowed(v))
    }
}

impl From<String> for ArcOrCowStr {
    fn from(v: String) -> Self {
        Self::Cow(Cow::Owned(v))
    }
}

impl AsRef<str> for ArcOrCowStr {
    fn as_ref(&self) -> &str {
        match self {
            Self::Arc(v) => v.as_ref(),
            Self::Cow(v) => v.as_ref(),
        }
    }
}

impl Deref for ArcOrCowStr {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl Display for ArcOrCowStr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_paths() {
        let result = get_crate_folder("dfu");
        let expected = ArrayVec::from(["3", "d"]);
        assert_eq!(result, expected);
        let result = get_crate_folder("df");
        let mut expected = ArrayVec::new();
        expected.push("2");
        assert_eq!(result, expected);

        let result = get_crate_folder("d");
        let mut expected = ArrayVec::new();
        expected.push("1");
        assert_eq!(result, expected);

        let result = get_crate_folder("longname");
        let expected = ArrayVec::from(["lo", "ng"]);
        assert_eq!(result, expected);
    }
}
