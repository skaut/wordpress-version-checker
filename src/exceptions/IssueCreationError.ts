import { CustomError } from 'ts-custom-error';

export class IssueCreationError extends CustomError {
	public constructor(e: string) {
		super('Couldn\'t create an issue. Error message: ' + e);
	}
}
