import compareVersions from 'compare-versions';
import { CustomError } from 'ts-custom-error';

import { isConfig } from './interfaces/Config';
import { octokit } from './octokit';
import { repo, repoName } from './repo';
import { createIssue, updateIssue } from './issue-management'
import {latestWordPressVersion} from './latest-version';

function hasStatus(obj: Record<string, unknown>): obj is Record<"status", unknown> {
	return Object.prototype.hasOwnProperty.call(obj, "status")
}

function outdated(testedVersion: string, latestVersion: string): void
{
	octokit.issues.listForRepo({...repo, creator: 'github-actions[bot]', labels: 'wpvc'}).then(function(result): void {
		if(result.data.length === 0)
		{
			createIssue(testedVersion, latestVersion);
		} else {
			updateIssue(result.data[0].number, testedVersion, latestVersion);
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

async function run(): Promise<void>
{
	try {
		const latest = await latestWordPressVersion();
		checkRepo(latest);
	} catch(e) {
		console.log((e as CustomError).message); // TODO
	}
}

void run();
