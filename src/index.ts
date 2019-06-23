import { Application } from 'probot';
import * as createScheduler from 'probot-scheduler';
import * as https from 'https';

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
	}).catch(function(e) {
		context.log('Couldn\'t list repository issues for repository ' + repo.owner + '/' + repo.repo + '. Error message: ' + e);
	});
}

function checkRepo(context, repo, latest)
{
	context.github.repos.getContents(repo).then(function(result) {
		const readme = Buffer.from(result.data.content, 'base64').toString();
		for(let line of readme.split('\n'))
		{
			if(line.startsWith('Tested up to:'))
			{
				const matches = line.match(/[^:\s]+/g);
				if(!matches)
				{
					context.log('Repository ' + repo.owner + '/' + repo.repo + ' doesn\'t have a valid readme at path ' + repo.path + '.')
					return;
				}
				const version = matches.pop();
				if(!version)
				{
					context.log('Repository ' + repo.owner + '/' + repo.repo + ' doesn\'t have a valid readme at path ' + repo.path + '.')
					return;
				}
				if(!latest.startsWith(version))
				{
					outdated(context, repo, version, latest);
					return;
				}
			}
		}
		context.log('Repository ' + repo.owner + '/' + repo.repo + ' doesn\'t have a valid readme at path ' + repo.path + '.')
	}).catch(function(e) {
		context.log('Couldn\'t get the readme of repository ' + repo.owner + '/' + repo.repo + ' at path ' + repo.path +  '. Error message: ' + e);
	});
}

function checkRepos(context, latest)
{
	const repos = require('../data/repos.json');
	for(var repo of repos)
	{
		checkRepo(context, repo, latest);
	}
}

function schedule(context)
{
	const options = {
		host: 'api.wordpress.org',
		path: '/core/stable-check/1.0/'
	};
	https.get(options, function(response) {
		if(response.statusCode !== 200)
		{
			context.log('Failed to fetch latest WordPress version. Request status code: ' + response.statusCode);
			return;
		}
		response.setEncoding('utf8');
		let rawData = '';
		response.on('data', (chunk) => { rawData += chunk; });
		response.on('end', () => {
			try {
				const list = JSON.parse(rawData);
				const latest = Object.keys(list).find(key => list[key] === 'latest');
				if(!latest)
				{
					context.log('Failed to fetch latest WordPress version. Couldn\'t find latest version');
					return;
				}
				checkRepos(context, latest);
			} catch(e) {
				context.log('Failed to fetch latest WordPress version. Exception: ' + e.message);
			}
		});
	}).on('error', function(e) {
		context.log('Failed to fetch latest WordPress version. Exception: ' + e.message);
	});
}

module.exports = app => {
	createScheduler(app, {
		delay: false,
		interval: 1000 * 60 * 60 * 24 // 1 day
	});
	app.on('schedule.repository', schedule);
};

