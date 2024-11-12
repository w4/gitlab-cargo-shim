# gitlab-cargo-shim

[Example configuration][example-configuration]

Say goodbye to your Git dependencies, `gitlab-cargo-shim` is a stateless SSH server that serves crates like a standard Cargo registry but from a [GitLab package registry][gitlab-package-registry], allowing you to use your private dependencies like any other dependency. No more `git push --force`s breaking your builds & get proper versioning in one simple little binary.

Access controls work like they do in GitLab, builds are scoped to users - if they don't have permission to the dependency they can't build it, it's that simple.

Users are either identified by their SSH keys from GitLab when connecting to the server or by an Gitlab personal-token. If no token is given, an [impersonation token][imp-token] will be generated for that run in order to pull available versions. Doing so requires ad admin personal token.

To publish run `cargo package` and push the resulting `.crate` file to the GitLab package repository with a semver-compatible version string, to consume the package configure your `.cargo/config.toml`, `Cargo.toml` and, optionally, `.ssh/config` accordingly.

At time of writing, `libssh2`, which `cargo` implicitly uses for communicating with the registry by SSH, is incompatible with rust's `thrussh`, due to non-overlapping ciphers. Hence, activating `net.git-fetch-with-cli` is necessary.

```toml
# .cargo/config.toml
[registries]
my-gitlab-project = { index = "ssh://gitlab-cargo-shim.local/my-gitlab-group/my-gitlab-project/" }
[net]
git-fetch-with-cli = true

# Cargo.toml
[dependencies]
my-crate = { version = "0.1", registry = "my-gitlab-project" }
```
```ssh-config
# .ssh/config (only if authentication by personal token is requires)
Host gitlab-cargo-shim.local
    User personal-token:<your-personal-token>
```

In your CI build, setup a `before_script` step to replace the connection string with one containing the CI token:

```yaml
# .gitlab-ci.yml
before_script:
  - sed -i "s/(gitlab-cargo-shim.local)/gitlab-ci-token:$GITLAB-CI-TOKEN@\1/" .cargo/config.toml
```

(or add the corresponding [environment variable][envvar])

To release your package from CI, add a new pipeline step:

```yaml
release-crate:
  image: rust:latest
  stage: deploy
  only: # release when a tag is pushed
    - tags
  before_script:
    - cargo install cargo-get
    - export CRATE_NAME=$(cargo-get package.name) CRATE_VERSION=$(cargo-get package.version)
    - export CRATE_FILE=${CRATE_NAME}-${CRATE_VERSION}.crate
  script:
    - cargo package
    - cargo metadata --format-version 1 > metadata.json
    - 'curl --header "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file target/package/${CRATE_FILE} "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/${CRATE_NAME}/${CRATE_VERSION}/${CRATE_FILE}"'
    - 'curl --header "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file metadata.json "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/${CRATE_NAME}/${CRATE_VERSION}/metadata.json"'
```

It's that easy. Go forth and enjoy your newfound quality of life improvements, Rustacean.

[gitlab-package-registry]: https://docs.gitlab.com/ee/user/packages/package_registry/index.html
[imp-token]: https://docs.gitlab.com/ee/api/index.html#impersonation-tokens
[envvar]: https://doc.rust-lang.org/cargo/reference/registries.html#using-an-alternate-registry
[example-configuration]: https://github.com/w4/gitlab-cargo-shim/blob/main/config.toml

## Build requirements
* clang
* libsodium
* pkg-config

## Runtime requirement
* libsodium
