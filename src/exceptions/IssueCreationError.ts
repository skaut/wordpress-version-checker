import { CustomError } from 'ts-custom-error';

import {repoName} from '../repo'

export class IssueCreationError extends CustomError {
	public constructor(e: string) {
		super('Couldn\'t create an issue for repository ' + repoName + '. Error message: ' + e);
	}
}
