import { Config, isConfig } from './interfaces/Config'
import { octokit } from './octokit';
import { repo } from './repo';

import {ConfigError} from './exceptions/ConfigError';
import {InvalidReadmeError} from './exceptions/InvalidReadmeError';

function hasStatus(obj: Record<string, unknown>): obj is Record<"status", unknown> {
	return Object.prototype.hasOwnProperty.call(obj, "status")
}

async function WPVCConfig(): Promise<Config|null> {
	const file = await octokit.repos.getContent({...repo, path: '.wordpress-version-checker.json'}).catch(function(e): null|never {
		if(hasStatus(e) && e.status === 404) {
			return null;
		} else {
			throw new ConfigError(String(e));
		}
	});
	if(file === null) {
		return null;
	}
	const encodedContent = (file.data as {content?: string}).content;
	if(!encodedContent) {
		throw new ConfigError('Failed to decode the file.');
	}
	let config: Record<string, unknown> = {};
	try {
		config = JSON.parse(Buffer.from(encodedContent, 'base64').toString()) as Record<string, unknown>;
	} catch(e) {
		throw new ConfigError((e as SyntaxError).message);
	}
	if(!isConfig(config))
	{
		throw new ConfigError('Invalid config file.');
	}
	return config;
}

async function readme(): Promise<string>
{
	let readmeLocations = ['readme.txt', 'plugin/readme.txt'];
	const config = await WPVCConfig();
	if(config !== null) {
		readmeLocations = [config.readme];
	}
	for(const readmeLocation of readmeLocations) {
		const result = await octokit.repos.getContent({...repo, path: readmeLocation}).catch(function(e): null|never {
			if(hasStatus(e) && e.status === 404) {
				return null;
			} else {
				throw new ConfigError('No config file was found in repo and all usual locations were exhausted. Error message: ' + String(e));
			}
		});
		if(result === null) {
			continue;
		}
		const encodedContent = (result.data as {content?: string}).content;
		if(!encodedContent) {
			throw new ConfigError('No config file was found in repo and all usual locations were exhausted.');
		}
		return Buffer.from(encodedContent, 'base64').toString();
	}
	throw new ConfigError('No config file was found in repo and all usual locations were exhausted.');
}

export async function testedVersion(): Promise<string> {
	const readmeContents = await readme();
	for(const line of readmeContents.split('\n'))
	{
		if(!line.startsWith('Tested up to:'))
		{
			continue;
		}
		const matches = line.match(/[^:\s]+/g);
		if(!matches)
		{
			throw new InvalidReadmeError();
		}
		const version = matches.pop();
		if(!version)
		{
			throw new InvalidReadmeError();
		}
		return version;
	}
	throw new InvalidReadmeError();
}
