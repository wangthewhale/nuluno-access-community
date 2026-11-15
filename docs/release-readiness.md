# Prepare community artifacts for review

The `Access Community release readiness` workflow runs manually or on an existing matching `access-community-v<version>` tag. It has `contents: read` permission and no custom secret dependency. It does not create tags, GitHub Releases, npm publications or deployments.

The preparer reads exact committed blob bytes from `HEAD`, rejects links/private state/known credential patterns and noncommunity provider source, builds in a fresh isolated snapshot with empty npm configuration, and validates the actual packed file inventory, package identity and unique community CLI. Dirty/untracked local code is not labelled as that source commit. These safeguards are not a complete security audit.

Outputs are the npm tarball, full public source ZIP, `release-manifest.json` and `SHA256SUMS`. The manifest is unsigned; checksums establish integrity, not publisher authenticity. The workflow stores [GitHub Actions artifacts](https://docs.github.com/en/actions/tutorials/store-and-share-data) for deliberate maintainer review. It has no permission or step to publish a release.

Local preparation requires Node 24+, npm, Git and tar:

```sh
node scripts/prepare-release.mjs --version 0.1.0-alpha.2 --output /path/to/new-empty-output
```

The version must already match `package.json` and `src/version.ts`; the output directory must be empty. Commit reviewed changes before expecting them in an artifact. A maintainer separately reviews the exact commit, package/source inventories, hashes, version and prerelease status before publishing through any channel. Commercial extensions and private owner/agent state must stay outside the artifacts.
