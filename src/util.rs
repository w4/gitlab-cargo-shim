pub fn format_fingerprint(fingerprint: &str) -> String {
    format!("SHA256:{}", fingerprint)
}

/// Crates with a total of 1, 2 or 3 characters in the same are written out to directories named
/// 1, 2 or 3 respectively as per the cargo spec. Anything else we'll build out a normal tree for
/// using the frist four characters of the crate name, 2 for the first directory and the other 2
/// for the second.
pub fn get_crate_folder(crate_name: &str) -> Vec<String> {
    let mut folders = Vec::new();

    match crate_name.len() {
        0 => {}
        1 => folders.push("1".to_string()),
        2 => folders.push("2".to_string()),
        3 => folders.push("3".to_string()),
        _ => {
            folders.push(crate_name[..2].to_string());
            folders.push(crate_name[2..4].to_string());
        }
    }

    folders
}
