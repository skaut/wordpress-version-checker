import { Application } from 'probot';
import * as createScheduler from 'probot-scheduler';
import * as http from 'http';

module.exports = app => {
	createScheduler(app);
	app.on("schedule.repository", function(context) {
		const options = {
			host: "api.wordpress.org",
			port: 443,
			path: "/core/stable-check/1.0/"
		};
		const readme = context.repos.getContents({
			owner: "skaut",
			repo: "skaut-google-drive-gallery",
			path: "plugin/readme.txt"
		});
		context.log(readme);
		http.get(options, function(response) {
			//const list = JSON.parse(response);
			//const latest = Object.keys(list).find(key => list[key] === "latest");
		});
	});
};

