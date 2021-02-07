import compareVersions from 'compare-versions';

import { octokit } from './octokit';
import { repo } from './repo';
import { createIssue, updateIssue } from './issue-management'
import {latestWordPressVersion} from './latest-version';
import {getTestedVersion} from './tested-version';

import {IssueListError} from './exceptions/IssueListError';
import {WPVCError} from './exceptions/WPVCError';

async function outdated(testedVersion: string, latestVersion: string): Promise<void>
{
	const issues = await octokit.issues.listForRepo({...repo, creator: 'github-actions[bot]', labels: 'wpvc'}).catch(function(e): never {
		throw new IssueListError(String(e));
	});
	if(issues.data.length === 0) {
		await createIssue(testedVersion, latestVersion);
	} else {
		await updateIssue(issues.data[0].number, testedVersion, latestVersion);
	}
}

async function upToDate(): Promise<void>
{
	const issues = await octokit.issues.listForRepo({...repo, creator: 'github-actions[bot]', labels: 'wpvc'}).catch(function(e): never {
		throw new IssueListError(String(e));
	});
	for (const issue of issues.data) {
		void octokit.issues.update({...repo, issue_number: issue.number, state: 'closed'});
	}
}

async function run(): Promise<void>
{
	try {
		const testedVersion = await getTestedVersion();
		const latestVersion = await latestWordPressVersion();
		if(compareVersions.compare(testedVersion, latestVersion, '<')) {
			await outdated(testedVersion, latestVersion);
		} else {
			await upToDate();
		}
	} catch(e) {
		console.log((e as WPVCError).message);
	}
}

void run();
