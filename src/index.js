import { Application } from 'probot';
import createScheduler from 'probot-scheduler';

export default app => {
	createScheduler(app);
	app.on('schedule.repository', context => {
	});
};

