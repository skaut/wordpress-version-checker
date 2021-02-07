import { CustomError } from 'ts-custom-error';

export class IssueListError extends CustomError {
	public constructor(e: string) {
		super('Couldn\'t list issues. Error message: ' + e);
	}
}
