import { CustomError } from 'ts-custom-error';

import {repoName} from '../repo'

export class ConfigError extends CustomError {
	public constructor(e: string) {
		super('Couldn\'t get the config file of repository ' + repoName + '. Exception: ' + e);
	}
}
