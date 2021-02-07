import { CustomError } from 'ts-custom-error';

export class IssueUpdateError extends CustomError {
	public constructor(issueNumber: number, e: string) {
		super('Couldn\'t update the existing issue #' + String(issueNumber) + '. Error message: ' + e);
	}
}
