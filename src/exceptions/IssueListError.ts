import { CustomError } from 'ts-custom-error';

import {repoName} from '../repo'

export class IssueListError extends CustomError {
	public constructor(e: string) {
		super('Couldn\'t list repository issues for repository ' + repoName + '. Error message: ' + e);
	}
}
