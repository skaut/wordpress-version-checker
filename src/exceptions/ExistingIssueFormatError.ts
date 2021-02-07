import {WPVCError} from './WPVCError';

export class ExistingIssueFormatError extends WPVCError {
	public constructor(issueNumber: number) {
		super('The existing issue #' + String(issueNumber) + ' doesn\'t have the correct format.');
	}
}
