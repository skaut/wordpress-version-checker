import { CustomError } from 'ts-custom-error';

export class LatestVersionError extends CustomError {
	public constructor(e?: string) {
		if(!e) {
			super('Failed to fetch latest WordPress version.');
		} else {
			super('Failed to fetch latest WordPress version. Exception: ' + e);
		}
	}
}
