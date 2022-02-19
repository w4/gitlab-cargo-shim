/// Retrieves the key fingerprint, encoded in hex and separated in two character chunks
/// with colons.
pub fn format_fingerprint(fingerprint: &str) -> Result<String, thrussh_keys::Error> {
    let raw_hex = hex::encode(
        base64::decode(&fingerprint).map_err(|_| thrussh_keys::Error::CouldNotReadKey)?,
    );
    let mut hex = String::with_capacity(raw_hex.len() + (raw_hex.len() / 2 - 1));

    for (i, c) in raw_hex.chars().enumerate() {
        if i != 0 && i % 2 == 0 {
            hex.push(':');
        }

        hex.push(c);
    }

    Ok(hex)
}
