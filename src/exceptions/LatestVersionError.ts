import { CustomError } from 'ts-custom-error';

export class LatestVersionError extends CustomError {
	public constructor(e?: string) {
		if(!e) {
			super('Failed to fetch the latest WordPress version.');
		} else {
			super('Failed to fetch the latest WordPress version. Error message: ' + e);
		}
	}
}
