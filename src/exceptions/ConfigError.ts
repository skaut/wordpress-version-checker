import { CustomError } from 'ts-custom-error';

export class ConfigError extends CustomError {
	public constructor(e: string) {
		super('Couldn\'t get the wordpress-version-checker config file. Error message: ' + e);
	}
}
