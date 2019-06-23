import { Application } from 'probot';
import * as createScheduler from 'probot-scheduler';
import * as https from 'https';

const repos = [{
	owner: 'marekdedic',
	repo: 'test-wpvc',
	path: 'plugin/readme.txt'
}];

function createIssue(context, repo, testedVersion, latestVersion)
{
	context.github.issues.create({
		owner: repo.owner,
		repo: repo.repo,
		title: "The plugin hasn't been tested with the latest version of WordPress",
		body: 'There is a new WordPress version that the plugin hasn\'t been tested with. Please test it and then change the "Tested up to" field in the plugin readme.\n\n**Tested up to:** ' + testedVersion + '\n**Latest version:** ' + latestVersion + '\n\nYou may then close this issue as it won\'t be done automatically.'
	});
}

function outdated(context, repo, testedVersion, latestVersion)
{
	context.github.issues.listForRepo({
		owner: repo.owner,
		repo: repo.repo,
		creator: 'wordpress-version-checker[bot]'
	}).then(function(result) {
		if(result.data.length === 0)
		{
			createIssue(context, repo, testedVersion, latestVersion);
		}
	}); // TODO: Error handling
}

function checkRepo(context, repo, latest)
{
	context.github.repos.getContents(repo).then(function(result) {
		const readme = Buffer.from(result.data.content, 'base64').toString();
		for(let line of readme.split('\n'))
		{
			if(line.startsWith('Tested up to:'))
			{
				const version = line.match(/\S+/g).pop()
				if(latest.startsWith(version)) // TODO: invert
				{
					outdated(context, repo, version, latest);
				}
			}
		}
	}); // TODO: Error handling
}

function checkRepos(context, latest)
{
	checkRepo(context, repos[0], latest);
}

function schedule(context)
{
	const options = {
		host: 'api.wordpress.org',
		path: '/core/stable-check/1.0/'
	};
	https.get(options, function(response) {
		response.setEncoding('utf8'); // TODO: Error handling
		let rawData = '';
		response.on('data', (chunk) => { rawData += chunk; });
		response.on('end', () => {
			const list = JSON.parse(rawData);
			const latest = Object.keys(list).find(key => list[key] === 'latest');
			checkRepos(context, latest);
		});
	});
}

module.exports = app => {
	createScheduler(app, {
		delay: false // TODO: interval
	});
	app.on('schedule.repository', schedule);
};

