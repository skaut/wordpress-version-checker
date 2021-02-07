import { CustomError } from 'ts-custom-error';

export class GetIssueError extends CustomError {
	public constructor(issueNumber: number, e: string) {
		super('Couldn\'t get the already existing issue #' + String(issueNumber) + '. Error message: ' + e);
	}
}
