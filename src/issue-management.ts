import compareVersions from 'compare-versions';

import { octokit } from './octokit';
import { repo } from './repo'

import {ExistingIssueFormatError} from './exceptions/ExistingIssueFormatError'
import {GetIssueError} from './exceptions/GetIssueError'
import {IssueCreationError} from './exceptions/IssueCreationError'
import {IssueUpdateError} from './exceptions/IssueUpdateError'

function issueBody(testedVersion: string, latestVersion: string): string {
	return 'There is a new WordPress version that the plugin hasn\'t been tested with. Please test it and then change the "Tested up to" field in the plugin readme.\n' +
		'\n' +
		'**Tested up to:** ' + testedVersion + '\n' +
		'**Latest version:** ' + latestVersion + '\n' +
		'\n' +
		'This issue will be closed automatically when the versions match.';
}

export async function createIssue(testedVersion: string, latestVersion: string): Promise<void>
{
	await octokit.issues.create({
		...repo,
		title: "The plugin hasn't been tested with the latest version of WordPress",
		body: issueBody(testedVersion, latestVersion),
		labels: ['wpvc']
	}).catch(function(e): never {
		throw new IssueCreationError(String(e));
	});
}

export async function updateIssue(issueNumber: number, testedVersion: string, latestVersion: string): Promise<void> {
	const issue = await octokit.issues.get({...repo, issue_number: issueNumber}).catch(function(e): never {
		throw new GetIssueError(String(e));
	});
	const matchingLine = issue.data.body.split('\r\n').find(function(line) {
		return line.startsWith('**Latest version:**');
	});
	if(!matchingLine) {
		throw new ExistingIssueFormatError();
	}
	const latestVersionInIssue = matchingLine.slice(20);
	if(compareVersions.compare(latestVersionInIssue, latestVersion, '<')) {
		octokit.issues.update({...repo, issue_number: issueNumber, body: issueBody(testedVersion, latestVersion)}).catch(function(e): never {
			throw new IssueUpdateError(String(e));
		});
	}
}
