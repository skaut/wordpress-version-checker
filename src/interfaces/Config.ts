interface Config {
	readme: string
}

export function isConfig(config: Record<string, unknown>): config is Record<string, unknown> & Config {
	if(!config.readme)
	{
		return false;
	}
	return true;
}
