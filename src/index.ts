import compareVersions from 'compare-versions';
import { CustomError } from 'ts-custom-error';

import { octokit } from './octokit';
import { repo, repoName } from './repo';
import { createIssue, updateIssue } from './issue-management'
import {latestWordPressVersion} from './latest-version';
import {getTestedVersion} from './tested-version';

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

async function checkRepo(latest: string): Promise<void>
{
	const testedVersion = await getTestedVersion();
	if(compareVersions.compare(testedVersion, latest, '<'))
	{
		outdated(testedVersion, latest);
	} else {
		upToDate();
	}
}

async function run(): Promise<void>
{
	try {
		const latest = await latestWordPressVersion();
		await checkRepo(latest);
	} catch(e) {
		console.log((e as CustomError).message); // TODO
	}
}

void run();
