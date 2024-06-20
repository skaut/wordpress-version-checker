# WordPress version checker

[![GitHub Release](https://img.shields.io/github/v/release/skaut/wordpress-version-checker?logo=github)](https://github.com/marketplace/actions/wordpress-version-checker)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/skaut/wordpress-version-checker/CI.yml?branch=master&logo=github)](https://github.com/skaut/wordpress-version-checker/actions)
[![Codecov (with branch)](https://img.shields.io/codecov/c/github/skaut/wordpress-version-checker/master?logo=codecov)](https://app.codecov.io/gh/skaut/wordpress-version-checker)
[![GitHub License](https://img.shields.io/github/license/skaut/wordpress-version-checker)](https://github.com/skaut/wordpress-version-checker/blob/master/LICENSE)

A GitHub action to automatically create issues when a plugin "tested up to" version doesn't match the latest WordPress version.

## Usage

This action fires on every push to `master` and once every day if you use this recommended config:

```yaml
name: "WordPress version checker"
on:
  push:
    branches:
      - master
  schedule:
    - cron: '0 0 * * *'

permissions:
  issues: write

jobs:
  wordpress-version-checker:
    runs-on: ubuntu-latest
    steps:
      - name: WordPress version checker
        uses: skaut/wordpress-version-checker@v1.0.0
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
```

## Configuration

The app doesn't stricly require any configuration, however you can configure some aspects of its function by placing a file named `.wordpress-version-checker.json` in the root of your repository. The file may contain any of the following configuration options:

### Plugin readme location

By default, the app checks for readme in `readme.txt` and `plugin/readme.txt`. If the readme of your plugin is not in one of these locations, you can configure the app to look somewhere else with the `readme` value in the configuration. The value can be either a single location or an array of locations to check - if multiple locations are provided, they will be checked in the given order until the first match.

#### Examples

```json
{
    "readme": "path/to/your/readme.txt"
}
```

```json
{
    "readme": ["path/to/first/readme.txt", "path/to/second/readme.txt"]
}
```

### WordPress release channel

By default, the app will notify you once an upcoming WordPress version reaches the release candidate stage of development. By setting the `channel` value to one of `stable`, `rc` or `beta`, you can choose to be notified when the new version is fully released, is in the release candidate (RC) stage of development, or when the first beta versions are released respectively.

#### Example

```json
{
    "channel": "beta"
}
```

### Issue assignees

By default, the issue will have no assignees. If you want the issues to be automatically assigned to someone, you can put their GitHub usernames in the config as the `assignees` value.

#### Example

```json
{
    "assignees": ["alice", "bob"]
}
```
