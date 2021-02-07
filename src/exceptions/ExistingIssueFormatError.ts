import { CustomError } from 'ts-custom-error';

import {repoName} from '../repo'

export class ExistingIssueFormatError extends CustomError {
	public constructor() {
		super('Existing issue for repository ' + repoName + ' doesn\'t have the correct format.');
	}
}
