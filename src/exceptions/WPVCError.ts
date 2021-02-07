import { CustomError } from 'ts-custom-error';

export class WPVCError extends CustomError {
	public constructor(e: string) {
		super(e);
	}
}
