# Releasing libmongocrypt

These steps describe releasing the libmongocrypt C library (not the language bindings).

## Version number scheme ##
Version numbers of libmongocrypt must follow the format 1.[0-9].[0-9] for releases and 1.[0-9].[0-9]-(alpha|beta|rc)[0-9] for pre-releases.  This ensures that Linux distribution packages built from each commit are published to the correct location.

## Steps to release ##
Do the following when releasing:
- Ensure `etc/purls.txt` is up-to-date. 
- If this is a feature release (e.g. `x.y.0` or `x.0.0`), follow these steps: [Creating SSDLC static analysis reports](https://docs.google.com/document/d/1rkFL8ymbkc0k8Apky9w5pTPbvKRm68wj17mPJt2_0yo/edit).
- Update CHANGELOG.md with the version being released.
- Check out the release branch. For a release `x.y.z`, the release branch is `rx.y`. If this is a new minor release (`x.y.0`), create the release branch.
- If this is a new minor release (e.g. `x.y.0`):
   - Update the Linux distribution package installation instructions in the below sections to refer to the new version `x.y`.
   - Update the [libmongocrypt-release](https://spruce.mongodb.com/project/libmongocrypt-release/settings/general) Evergreen project (requires auth) to set `Branch Name` to `rx.y`.
- Commit the changes on the `rx.y` branch with a message like "Update CHANGELOG.md for x.y.z".
- Tag the commit with `git tag -a <tag>`.
   - Push both the branch ref and tag ref in the same command: `git push origin master 1.8.0-alpha0` or `git push origin r1.8 1.8.4`
   - Pushing the branch ref and the tag ref in the same command eliminates the possibility of a race condition in Evergreen (for building resources based on the presence of a release tag)
   - Note that in the future (e.g., if we move to a PR-based workflow for releases, or if we simply want to take better advantage of advanced Evergreen features), it is possible to use Evergreen's "Trigger Versions With Git Tags" feature by updating both `config.yml` and the project's settings in Evergreen
- Ensure the version on Evergreen with the tagged commit is scheduled. The following tasks must pass to complete the release:
   - `upload-all`
   - `windows-upload-release`
   - All `publish-packages` tasks.
      - If the `publish-packages` tasks fail with an error like `[curator] 2024/01/02 13:56:17 [p=emergency]: problem submitting repobuilder job: 404 (Not Found)`, this suggests the published path does not yet exist. Barque (the Linux package publishing service) has protection to avoid unintentional publishes. File a DEVPROD ticket ([example](https://jira.mongodb.org/browse/DEVPROD-4053)) and assign to the team called Release Infrastructure to request the path be created. Then re-run the failing `publish-packages` task. Ask in the slack channel `#devprod-release-tools` for further help with `Barque` or `curator`.
- Create the release from the GitHub releases page from the new tag.
   - Attach the tarball and signature file from the Files tab of the `windows-upload-release` task. [Example](https://github.com/mongodb/libmongocrypt/releases/tag/1.10.0).
   - Attach the Augmented SBOM file. Download the Augmented SBOM using:
     ```bash
     ./.evergreen/earthly.sh \
        --secret silk_client_id=${silk_client_id} \
        --secret silk_client_secret=${silk_client_secret} \
        +sbom-download
     ```
     Secrets can be obtained from [AWS Secrets Manager](https://wiki.corp.mongodb.com/display/DRIVERS/Using+AWS+Secrets+Manager+to+Store+Testing+Secrets) under `drivers/libmongocrypt`.

- If this is a new minor release (e.g. `x.y.0`), file a DOCSP ticket to update the installation instructions on [Install libmongocrypt](https://www.mongodb.com/docs/manual/core/csfle/reference/libmongocrypt/). ([Example](https://jira.mongodb.org/browse/DOCSP-36863))
- Make a PR to apply the "Update CHANGELOG.md for x.y.z" commit to the `master` branch.
- Update the release on the [Jira releases page](https://jira.mongodb.org/projects/MONGOCRYPT/versions).
- Record the release on [C/C++ Release Info](https://docs.google.com/spreadsheets/d/1yHfGmDnbA5-Qt8FX4tKWC5xk9AhzYZx1SKF4AD36ecY/edit?usp=sharing). This is done to meet SSDLC reporting requirements.

## Homebrew steps ##
Submit a PR to update the Homebrew package https://github.com/mongodb/homebrew-brew/blob/master/Formula/libmongocrypt.rb. ([Example](https://github.com/mongodb/homebrew-brew/pull/208)). If not on macOS, request a team member to do this step.

## Debian steps ##
Refer to the [Debian](https://docs.google.com/document/d/1ItyBC7VN383zNXu3oUOQJYR7adfYI8ECjLMJ5kqA9X8/edit#heading=h.wqad0pesgfc6) steps. If you are not a Debian maintainer on the team, request a team member to do this step.
