declare module 'probot-scheduler' {
	export = (app: Application, options: {delay: boolean; interval: number}): (() => void) => {
	};
}
