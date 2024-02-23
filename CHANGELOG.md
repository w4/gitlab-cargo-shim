# Unreleased

- Fetch crate metadata concurrently.
- Handle missing invalid metadata non-fatally.
- Support env var `RUST_LOG` log filter configuration.
- Add info logs for release & metadata fetch latency.
- When fetching all releases handle 429 by backing off.
- Improve fetch error logging.

# v0.1.4

- Add optional `metadata-format` config. Options: `json` (default) & `json.zst`.
  When the latter selected the server will fetch `metadata.json.zst` files.

# v0.1.3

- Add `ssl-cert` configuration value under `gitlab` to allow self-signed
  certificates to be used (#50) - thanks @fdbastionamio for the
  contribution
- Update dependencies (#54) - thanks @alexheretic for the contribution
- Allow authentication using personal access tokens rather than admin
  tokens (#53) - thanks @momoson for the contribution
- Use thin LTO and strip release binaries (#56) - thanks @alexheretic
  for the contribution
- Make admin-token optional (#55) - thanks @alexheretic for the
  contribution

# v0.1.2

Add expires_at field to impersonation_tokens POST request to conform to
Gitlab breaking change in v16.1

# v0.1.1

Various bugfixes relating to interaction with Cargo - thanks @Eijebong
for the contribution.

# v0.1.0

Initial release


