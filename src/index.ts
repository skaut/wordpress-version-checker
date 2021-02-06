import * as core from '@actions/core';
import * as github from '@actions/github';
import compareVersions from 'compare-versions';
import * as https from 'https';

const octokit = github.getOctokit(core.getInput('repo-token'));
const repo = github.context.repo;
const repoName = repo.owner + '/' + repo.repo;

interface Config {
	readme: string
}

function isConfig(config: Record<string, unknown>): config is Record<string, unknown> & Config {
	if(!config.readme)
	{
		return false;
	}
	return true;
}

function hasStatus(obj: Record<string, unknown>): obj is Record<"status", unknown> {
	return Object.prototype.hasOwnProperty.call(obj, "status")
}

function createIssue(testedVersion: string, latestVersion: string): void
{
	const args = {
		...repo,
		title: "The plugin hasn't been tested with the latest version of WordPress",
		body: 'There is a new WordPress version that the plugin hasn\'t been tested with. Please test it and then change the "Tested up to" field in the plugin readme.\n\n**Tested up to:** ' + testedVersion + '\n**Latest version:** ' + latestVersion + '\n\nThis issue will be closed automatically when the versions match.',
		labels: ['wpvc']
	};
	octokit.issues.create(args).catch(function(e): void {
		console.log('Couldn\'t create an issue for repository ' + repoName + '. Error message: ' + String(e));
	});
}

function updateIssue(issue: number, _: string) {
	void octokit.issues.get({...repo, issue_number: issue}).then(function(result) { // TODO: catch
		const line = result.data.body.split('\n').find(function(line) {
			return line.startsWith('**Latest vesion:**');
		})
		console.log(line);
	});
}

function outdated(testedVersion: string, latestVersion: string): void
{
	octokit.issues.listForRepo({...repo, creator: 'github-actions[bot]', labels: 'wpvc'}).then(function(result): void {
		if(result.data.length === 0)
		{
			createIssue(testedVersion, latestVersion);
		} else {
			updateIssue(result.data[0].number, latestVersion);
		}
	}).catch(function(e): void {
		console.log('Couldn\'t list repository issues for repository ' + repoName + '. Error message: ' + String(e));
	});
}

function upToDate(): void
{
	octokit.issues.listForRepo({...repo, creator: 'github-actions[bot]', labels: 'wpvc'}).then(function(result): void {
		for (const issue of result.data) {
			void octokit.issues.update({...repo, issue_number: issue.number, state: 'closed'});
		}
	}).catch(function(e): void {
		console.log('Couldn\'t list repository issues for repository ' + repoName + '. Error message: ' + String(e));
	});
}

function getReadme(): Promise<string>
{
	function tryLocations(resolve: (value: string | PromiseLike<string>) => void, reject: () => void, locations: Array<string>): void
	{
		octokit.repos.getContent({...repo, path: locations[0]}).then(function(result): void {
			const encodedContent = (result.data as {content?: string}).content;
			if(!encodedContent) {
				console.log('Couldn\'t get the readme of repository ' + repoName + ' at path ' + locations[0] +  '. Reason: GitHub failed to fetch the config file.');
				reject();
				return;
			}
			resolve(Buffer.from(encodedContent, 'base64').toString());
		}).catch(function(e): void {
			if(hasStatus(e) && e.status === 404) {
				tryLocations(resolve, reject, locations.slice(1));
			} else {
				console.log('Couldn\'t get the readme of repository ' + repoName + ' at path ' + locations[0] +  '. Reason: No config file was found in repo and all usual locations were exhausted. Error message: ' + String(e));
				reject();
			}
		});
	}

	return new Promise(function(resolve, reject): void {
		octokit.repos.getContent({...repo, path: '.wordpress-version-checker.json'}).then(function(result): void {
			const encodedContent = (result.data as {content?: string}).content;
			if(!encodedContent) {
				console.log('Couldn\'t get the config file. Reason: GitHub failed to fetch the config file.');
				reject();
				return;
			}
			let config: Record<string, unknown> = {};
			try {
				config = JSON.parse(Buffer.from(encodedContent, 'base64').toString()) as Record<string, unknown>;
			} catch(e) {
				console.log('Failed to parse config file. Exception: ' + (e as SyntaxError).message);
				reject();
			}
			if(!isConfig(config))
			{
				console.log('Invalid config file - doesn\'t contain the readme field.');
				reject();
			}
			octokit.repos.getContent({...repo, path: config.readme as string}).then(function(result): void {
				const encodedContent = (result.data as {content?: string}).content;
				if(!encodedContent) {
					console.log('Couldn\'t get the config file. Reason: GitHub failed to fetch the config file.');
					reject();
					return;
				}
				resolve(Buffer.from(encodedContent, 'base64').toString());
			}).catch(function(e): void {
				console.log('Couldn\'t get the readme of repository ' + repoName + ' at path ' + (config.readme as string) +  '. Reason: The readme file location provided in the config file doesn\'t exist. Error message: ' + String(e));
				reject();
			});
		}).catch(function(e): void {
			if(hasStatus(e) && e.status === 404) {
				// No config file, try usual locations
				tryLocations(resolve, reject, ['readme.txt', 'plugin/readme.txt']);
			} else {
				console.log('Couldn\'t get the config file of repository ' + repoName + '. Reason: Unknown error when fetching config file. Error message: ' + String(e));
				reject();
			}
		});
	});
}

function checkRepo(latest: string): void
{
	getReadme().then(function(readme): void {
		for(const line of readme.split('\n'))
		{
			if(line.startsWith('Tested up to:'))
			{
				const matches = line.match(/[^:\s]+/g);
				if(!matches)
				{
					console.log('Repository ' + repoName + ' doesn\'t have a valid readme.')
					return;
				}
				const version = matches.pop();
				if(!version)
				{
					console.log('Repository ' + repoName + ' doesn\'t have a valid readme.')
					return;
				}
				if(compareVersions.compare(version, latest, '<'))
				{
					outdated(version, latest);
				} else {
					upToDate();
				}
				return;
			}
		}
		console.log('Repository ' + repoName + ' doesn\'t have a valid readme.');
	}).catch(function(): void {
		console.log('Couldn\'t check repository ' + repoName + '.');
	});
}

function run(): void
{
	const options = {
		host: 'api.wordpress.org',
		path: '/core/stable-check/1.0/'
	};
	https.get(options, function(response): void {
		if(response.statusCode !== 200)
		{
			console.log('Failed to fetch latest WordPress version. Request status code: ' + String(response.statusCode));
			return;
		}
		response.setEncoding('utf8');
		let rawData = '';
		response.on('data', (chunk): void => { rawData += chunk; });
		response.on('end', (): void => {
			let list: Record<string, unknown> = {};
			try {
				list = JSON.parse(rawData) as Record<string, unknown>;
			} catch(e) {
				console.log('Failed to fetch latest WordPress version. Exception: ' + (e as SyntaxError).message);
				return;
			}
			let latest = Object.keys(list).find((key): boolean => list[key] === 'latest');
			if(!latest)
			{
				console.log('Failed to fetch latest WordPress version. Couldn\'t find latest version');
				return;
			}
			latest = latest.split('.').slice(0, 2).join('.'); // Discard patch version
			checkRepo(latest);
		});
	}).on('error', function(e): void {
		console.log('Failed to fetch latest WordPress version. Exception: ' + e.message);
	});
}

run();
