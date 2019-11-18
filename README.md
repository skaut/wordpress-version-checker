# WordPress version checker

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

jobs:
  wordpress-version-checker:
    runs-on: ubuntu-latest
    steps:
      - name: WordPress version checker
        uses: marekdedic/wordpress-version-checker@0.8.0
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
```

By default, the app checks for readme in `readme.txt` and `plugin/readme.txt`. If the readme of your plugin is not in one of these locations, you can configure the app to look somewhere else by creating a file called `.wordpress-version-checker.json` in the root of your repo with the contents:

```json
{
	"readme": "path/to/your/readme.txt"
}
```
