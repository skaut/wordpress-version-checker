"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const core = __importStar(require("@actions/core"));
const github = __importStar(require("@actions/github"));
const https = __importStar(require("https"));
const octokit = github.getOctokit(core.getInput('repo-token'));
const repo = github.context.repo;
const repoName = repo.owner + '/' + repo.repo;
function createIssue(testedVersion, latestVersion) {
    const args = Object.assign(Object.assign({}, repo), { title: "[wpvc] The plugin hasn't been tested with the latest version of WordPress", body: 'There is a new WordPress version that the plugin hasn\'t been tested with. Please test it and then change the "Tested up to" field in the plugin readme.\n\n**Tested up to:** ' + testedVersion + '\n**Latest version:** ' + latestVersion + '\n\nYou may then close this issue as it won\'t be done automatically.' });
    octokit.issues.create(args);
}
function outdated(testedVersion, latestVersion) {
    octokit.issues.listForRepo(Object.assign(Object.assign({}, repo), { creator: 'github-actions[bot]' })).then(function (result) {
        const wpvcIssues = result.data.filter(function (issue) {
            return issue.title.startsWith('[wpvc]');
        });
        if (wpvcIssues.length === 0) {
            createIssue(testedVersion, latestVersion);
        }
    }).catch(function (e) {
        console.log('Couldn\'t list repository issues for repository ' + repoName + '. Error message: ' + e);
    });
}
function getReadme() {
    function tryLocations(resolve, reject, locations) {
        octokit.repos.getContent(Object.assign(Object.assign({}, repo), { path: locations[0] })).then(function (result) {
            const encodedContent = result.data.content;
            if (!encodedContent) {
                console.log('Couldn\'t get the readme of repository ' + repoName + ' at path ' + locations[0] + '. Reason: GitHub failed to fetch the config file.');
                reject();
                return;
            }
            resolve(Buffer.from(encodedContent, 'base64').toString());
        }).catch(function (e) {
            if (e.status === 404) {
                tryLocations(resolve, reject, locations.slice(1));
            }
            else {
                console.log('Couldn\'t get the readme of repository ' + repoName + ' at path ' + locations[0] + '. Reason: No config file was found in repo and all usual locations were exhausted. Error message: ' + e);
                reject();
            }
        });
    }
    return new Promise(function (resolve, reject) {
        octokit.repos.getContent(Object.assign(Object.assign({}, repo), { path: '.wordpress-version-checker.json' })).then(function (result) {
            try {
                const encodedContent = result.data.content;
                if (!encodedContent) {
                    console.log('Couldn\'t get the config file. Reason: GitHub failed to fetch the config file.');
                    reject();
                    return;
                }
                const config = JSON.parse(Buffer.from(encodedContent, 'base64').toString());
                if (!config.readme) {
                    console.log('Invalid config file - doesn\'t contain the readme field.');
                    reject();
                }
                octokit.repos.getContent(Object.assign(Object.assign({}, repo), { path: config.readme })).then(function (result) {
                    const encodedContent = result.data.content;
                    if (!encodedContent) {
                        console.log('Couldn\'t get the config file. Reason: GitHub failed to fetch the config file.');
                        reject();
                        return;
                    }
                    resolve(Buffer.from(encodedContent, 'base64').toString());
                }).catch(function (e) {
                    console.log('Couldn\'t get the readme of repository ' + repoName + ' at path ' + config.readme + '. Reason: The readme file location provided in the config file doesn\'t exist. Error message: ' + e);
                    reject();
                });
            }
            catch (e) {
                console.log('Failed to parse config file. Exception: ' + e.message);
                reject();
            }
        }).catch(function (e) {
            if (e.status === 404) {
                // No config file, try usual locations
                tryLocations(resolve, reject, ['readme.txt', 'plugin/readme.txt']);
            }
            else {
                console.log('Couldn\'t get the config file of repository ' + repoName + '. Reason: Unknown error when fetching config file. Error message: ' + e);
                reject();
            }
        });
    });
}
function checkRepo(latest) {
    getReadme().then(function (readme) {
        for (const line of readme.split('\n')) {
            if (line.startsWith('Tested up to:')) {
                const matches = line.match(/[^:\s]+/g);
                if (!matches) {
                    console.log('Repository ' + repoName + ' doesn\'t have a valid readme.');
                    return;
                }
                const version = matches.pop();
                if (!version) {
                    console.log('Repository ' + repoName + ' doesn\'t have a valid readme.');
                    return;
                }
                if (!latest.startsWith(version)) {
                    outdated(version, latest);
                    return;
                }
                return;
            }
        }
        console.log('Repository ' + repoName + ' doesn\'t have a valid readme.');
    }).catch(function () {
        console.log('Couldn\'t check repository ' + repoName + '.');
    });
}
function run() {
    const options = {
        host: 'api.wordpress.org',
        path: '/core/stable-check/1.0/'
    };
    https.get(options, function (response) {
        if (response.statusCode !== 200) {
            console.log('Failed to fetch latest WordPress version. Request status code: ' + response.statusCode);
            return;
        }
        response.setEncoding('utf8');
        let rawData = '';
        response.on('data', (chunk) => { rawData += chunk; });
        response.on('end', () => {
            try {
                const list = JSON.parse(rawData);
                const latest = Object.keys(list).find((key) => list[key] === 'latest');
                if (!latest) {
                    console.log('Failed to fetch latest WordPress version. Couldn\'t find latest version');
                    return;
                }
                checkRepo(latest);
            }
            catch (e) {
                console.log('Failed to fetch latest WordPress version. Exception: ' + e.message);
            }
        });
    }).on('error', function (e) {
        console.log('Failed to fetch latest WordPress version. Exception: ' + e.message);
    });
}
run();
