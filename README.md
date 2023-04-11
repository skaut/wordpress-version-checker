# WordPress version checker

[![GitHub CI](https://img.shields.io/github/actions/workflow/status/skaut/wordpress-version-checker/CI.yml?label=CI&logo=github)](https://github.com/skaut/wordpress-version-checker/actions?query=branch%3Amaster)
[![Codecov](https://img.shields.io/codecov/c/gh/skaut/wordpress-version-checker?logo=codecov)](https://app.codecov.io/gh/skaut/wordpress-version-checker)

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

### Plugin readme location.

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

By default, the app will only notify you once the new WordPress version is released (**This will change** - starting from version 2.0, the default value will be changed to `rc`). By setting the `channel` value to one of `stable` or `rc`, you can choose to be notified when the new version is fully release, is in the release candidate (RC) stage of development or when the first beta versions are released.

#### Example

```json
{
    "channel": "rc"
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
