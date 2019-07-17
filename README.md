# WordPress version checker

A GitHub app to automatically create issues when a plugin "tested up to" version doesn't match the latest WordPress version. Made with [Probot](https://probot.github.io/).

This app is deployed for this organization only at [Glitch](https://glitch.com/edit/#!/skaut-wordpress-version-checker).

## Deployment

- Deploy the app to the GitHub marketplace as it isn't deployed publicly
- Run the application somewhere, e. g. Glitch.
- Install the app on the desired repos

## Configuration

By default, the app checks for readme in `readme.txt` and `plugin/readme.txt`. If the readme of your plugin is not in one of these locations, you can configure the app to look somewhere else by creating a file called `.wordpress-version-checker.json` in the root of your repo with the contents:

```json
{
	"readme": "path/to/your/readme.txt"
}
```
