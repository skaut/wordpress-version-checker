import { Application } from 'probot';
import * as createScheduler from 'probot-scheduler';
import * as https from 'https';

function createIssue(context, testedVersion: string, latestVersion: string): void
{
	const repo = context.repo({
		title: "The plugin hasn't been tested with the latest version of WordPress",
		body: 'There is a new WordPress version that the plugin hasn\'t been tested with. Please test it and then change the "Tested up to" field in the plugin readme.\n\n**Tested up to:** ' + testedVersion + '\n**Latest version:** ' + latestVersion + '\n\nYou may then close this issue as it won\'t be done automatically.'
	});
	context.github.issues.create(repo);
}

function outdated(context, testedVersion: string, latestVersion: string): void
{
	const repo = context.repo({creator: 'wordpress-version-checker[bot]'});
	context.github.issues.listForRepo(repo).then(function(result): void {
		if(result.data.length === 0)
		{
			createIssue(context, testedVersion, latestVersion);
		}
	}).catch(function(e): void {
		context.log('Couldn\'t list repository issues for repository ' + repo.owner + '/' + repo.repo + '. Error message: ' + e);
	});
}

function getReadme(context): Promise<string>
{
	function tryLocations(context, resolve, reject, locations): void
	{
		const repo = context.repo({path: 'readme.txt'});
		context.github.repos.getContents(repo).then(function(result): void {
			resolve(Buffer.from(result.data.content, 'base64').toString());
		}).catch(function(e): void {
			if(e.status === 404) {
				tryLocations(context, resolve, reject, locations.slice(1));
			} else {
				context.log('Couldn\'t get the readme of repository ' + repo.owner + '/' + repo.repo + ' at path ' + repo.path +  '. Reason: No config file was found in repo and all usual locations were exhausted. Error message: ' + e);
				reject();
			}
		});
	}

	return new Promise(function(resolve, reject): void {
		const repo = context.repo({path: '.wordpress-version-checker.json'});
		context.github.repos.getContents(repo).then(function(result): void {
			try {
				const config = JSON.parse(Buffer.from(result.data.content, 'base64').toString());
				if(!config.readme)
				{
					context.log('Invalid config file - doesn\'t contain the readme field.');
					reject();
				}
				const repo = context.repo({path: config.readme});
				context.github.repos.getContents(repo).then(function(result): void {
					resolve(Buffer.from(result.data.content, 'base64').toString());
				}).catch(function(e): void {
					context.log('Couldn\'t get the readme of repository ' + repo.owner + '/' + repo.repo + ' at path ' + repo.path +  '. Reason: The readme file location provided in the config file doesn\'t exist. Error message: ' + e);
					reject();
				});
			} catch(e) {
				context.log('Failed to parse config file. Exception: ' + e.message);
				reject();
			}
		}).catch(function(e): void {
			if(e.status === 404) {
				// No config file, try usual locations
				tryLocations(context, resolve, reject, ['readme.txt', 'plugin/readme.txt']);
			} else {
				context.log('Couldn\'t get the config file of repository ' + repo.owner + '/' + repo.repo + '. Reason: Unknown error when fetching config file. Error message: ' + e);
				reject();
			}
		});
	});
}

function checkRepo(context, latest: string): void
{
	const repo = context.repo();
	getReadme(context).then(function(readme): void {
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
					outdated(context, version, latest);
					return;
				}
				return;
			}
		}
		context.log('Repository ' + repo.owner + '/' + repo.repo + ' doesn\'t have a valid readme at path ' + repo.path + '.');
	}).catch(function(): void {
		context.log('Couldn\'t check repository ' + repo.owner + '/' + repo.repo + '.');
	});
}

function schedule(context): Promise<void>
{
	const options = {
		host: 'api.wordpress.org',
		path: '/core/stable-check/1.0/'
	};
	https.get(options, function(response): void {
		if(response.statusCode !== 200)
		{
			context.log('Failed to fetch latest WordPress version. Request status code: ' + response.statusCode);
			return;
		}
		response.setEncoding('utf8');
		let rawData = '';
		response.on('data', (chunk): void => { rawData += chunk; });
		response.on('end', (): void => {
			try {
				const list = JSON.parse(rawData);
				const latest = Object.keys(list).find((key): boolean => list[key] === 'latest');
				if(!latest)
				{
					context.log('Failed to fetch latest WordPress version. Couldn\'t find latest version');
					return;
				}
				checkRepo(context, latest);
			} catch(e) {
				context.log('Failed to fetch latest WordPress version. Exception: ' + e.message);
			}
		});
	}).on('error', function(e): void {
		context.log('Failed to fetch latest WordPress version. Exception: ' + e.message);
	});
	return Promise.resolve();
}

module.exports = (app: Application): void => {
	createScheduler(app, {
		delay: false,
		interval: 1000 * 60 * 60 * 24 // 1 day
	});
	app.on('schedule.repository', schedule);
};

