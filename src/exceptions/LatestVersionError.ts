import {WPVCError} from './WPVCError';

export class LatestVersionError extends WPVCError {
	public constructor(e?: string) {
		if(!e) {
			super('Failed to fetch the latest WordPress version.');
		} else {
			super('Failed to fetch the latest WordPress version. Error message: ' + e);
		}
	}
}
