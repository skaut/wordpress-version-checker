import compareVersions from 'compare-versions';

import { octokit } from './octokit';
import { repo, repoName } from './repo'

function issueBody(testedVersion: string, latestVersion: string): string {
	return 'There is a new WordPress version that the plugin hasn\'t been tested with. Please test it and then change the "Tested up to" field in the plugin readme.\n\n**Tested up to:** ' + testedVersion + '\n**Latest version:** ' + latestVersion + '\n\nThis issue will be closed automatically when the versions match.';
}

export function createIssue(testedVersion: string, latestVersion: string): void
{
	const args = {
		...repo,
		title: "The plugin hasn't been tested with the latest version of WordPress",
		body: issueBody(testedVersion, latestVersion),
		labels: ['wpvc']
	};
	octokit.issues.create(args).catch(function(e): void {
		console.log('Couldn\'t create an issue for repository ' + repoName + '. Error message: ' + String(e));
	});
}

export function updateIssue(issue: number, testedVersion: string, latestVersion: string): void {
	octokit.issues.get({...repo, issue_number: issue}).then(function(result) {
		const matchingLine = result.data.body.split('\r\n').find(function(line) {
			return line.startsWith('**Latest version:**');
		})
		if(!matchingLine) {
			console.log('Existing issue for repository ' + repoName + ' doesn\'t have the correct format.');
			return;
		}
		const latestVersionInIssue = matchingLine.slice(20);
		if(compareVersions.compare(latestVersionInIssue, latestVersion, '<')) {
			octokit.issues.update({...repo, issue_number: issue, body: issueBody(testedVersion, latestVersion)}).catch(function(e) {
				console.log('Couldn\'t update existing issue for repository ' + repoName + '. Error message: ' + String(e));
			});
		}
	}).catch(function(e): void {
		console.log('Couldn\'t get existing issue for repository ' + repoName + '. Error message: ' + String(e));
	});
}
