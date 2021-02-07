import { CustomError } from 'ts-custom-error';

export class InvalidReadmeError extends CustomError {
	public constructor() {
		super('The repository has an invalid readme.')
	}
}
