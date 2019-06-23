import { Application } from 'probot';
import * as createScheduler from 'probot-scheduler';
import * as https from 'https';

function schedule(context)
{
	const readme = context.github.repos.getContents({
		owner: "marekdedic",
		repo: "test-wpvc",
		path: "plugin/readme.txt"
	}).then(function(result) {
		const readme = Buffer.from(result.data.content, 'base64').toString()
		//context.log(readme);
	}); // TODO: Error handling
	const options = {
		host: "api.wordpress.org",
		path: "/core/stable-check/1.0/"
	};
	https.get(options, function(response) {
		response.setEncoding('utf8'); // TODO: Error handling
		let rawData = '';
		response.on('data', (chunk) => { rawData += chunk; });
		response.on('end', () => {
			const list = JSON.parse(rawData);
			const latest = Object.keys(list).find(key => list[key] === "latest");
			context.log(latest);
		});
	});
}

module.exports = app => {
	createScheduler(app, {
		delay: false
	});
	app.on("schedule.repository", schedule);
};

