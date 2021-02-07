import { CustomError } from 'ts-custom-error';

import {repoName} from '../repo'

export class InvalidReadmeError extends CustomError {
	public constructor() {
		super('Repository ' + repoName + ' doesn\'t have a valid readme.')
	}
}
