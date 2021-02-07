import { CustomError } from 'ts-custom-error';

import {repoName} from '../repo'

export class IssueUpdateError extends CustomError {
	public constructor(e: any) {
		super('Couldn\'t update existing issue for repository ' + repoName + '. Error message: ' + String(e));
	}
}
