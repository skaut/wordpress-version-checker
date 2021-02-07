import { CustomError } from 'ts-custom-error';

export class ExistingIssueFormatError extends CustomError {
	public constructor(issueNumber: number) {
		super('The existing issue #' + String(issueNumber) + ' doesn\'t have the correct format.');
	}
}
