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
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const compare_versions_1 = __importDefault(require("compare-versions"));
const https = __importStar(require("https"));
const Config_1 = require("./interfaces/Config");
const octokit_1 = require("./octokit");
const repo_1 = require("./repo");
const issue_management_1 = require("./issue-management");
function hasStatus(obj) {
    return Object.prototype.hasOwnProperty.call(obj, "status");
}
function outdated(testedVersion, latestVersion) {
    octokit_1.octokit.issues.listForRepo(Object.assign(Object.assign({}, repo_1.repo), { creator: 'github-actions[bot]', labels: 'wpvc' })).then(function (result) {
        if (result.data.length === 0) {
            issue_management_1.createIssue(testedVersion, latestVersion);
        }
        else {
            issue_management_1.updateIssue(result.data[0].number, testedVersion, latestVersion);
        }
    }).catch(function (e) {
        console.log('Couldn\'t list repository issues for repository ' + repo_1.repoName + '. Error message: ' + String(e));
    });
}
function upToDate() {
    octokit_1.octokit.issues.listForRepo(Object.assign(Object.assign({}, repo_1.repo), { creator: 'github-actions[bot]', labels: 'wpvc' })).then(function (result) {
        for (const issue of result.data) {
            void octokit_1.octokit.issues.update(Object.assign(Object.assign({}, repo_1.repo), { issue_number: issue.number, state: 'closed' }));
        }
    }).catch(function (e) {
        console.log('Couldn\'t list repository issues for repository ' + repo_1.repoName + '. Error message: ' + String(e));
    });
}
function getReadme() {
    function tryLocations(resolve, reject, locations) {
        octokit_1.octokit.repos.getContent(Object.assign(Object.assign({}, repo_1.repo), { path: locations[0] })).then(function (result) {
            const encodedContent = result.data.content;
            if (!encodedContent) {
                console.log('Couldn\'t get the readme of repository ' + repo_1.repoName + ' at path ' + locations[0] + '. Reason: GitHub failed to fetch the config file.');
                reject();
                return;
            }
            resolve(Buffer.from(encodedContent, 'base64').toString());
        }).catch(function (e) {
            if (hasStatus(e) && e.status === 404) {
                tryLocations(resolve, reject, locations.slice(1));
            }
            else {
                console.log('Couldn\'t get the readme of repository ' + repo_1.repoName + ' at path ' + locations[0] + '. Reason: No config file was found in repo and all usual locations were exhausted. Error message: ' + String(e));
                reject();
            }
        });
    }
    return new Promise(function (resolve, reject) {
        octokit_1.octokit.repos.getContent(Object.assign(Object.assign({}, repo_1.repo), { path: '.wordpress-version-checker.json' })).then(function (result) {
            const encodedContent = result.data.content;
            if (!encodedContent) {
                console.log('Couldn\'t get the config file. Reason: GitHub failed to fetch the config file.');
                reject();
                return;
            }
            let config = {};
            try {
                config = JSON.parse(Buffer.from(encodedContent, 'base64').toString());
            }
            catch (e) {
                console.log('Failed to parse config file. Exception: ' + e.message);
                reject();
            }
            if (!Config_1.isConfig(config)) {
                console.log('Invalid config file - doesn\'t contain the readme field.');
                reject();
            }
            octokit_1.octokit.repos.getContent(Object.assign(Object.assign({}, repo_1.repo), { path: config.readme })).then(function (result) {
                const encodedContent = result.data.content;
                if (!encodedContent) {
                    console.log('Couldn\'t get the config file. Reason: GitHub failed to fetch the config file.');
                    reject();
                    return;
                }
                resolve(Buffer.from(encodedContent, 'base64').toString());
            }).catch(function (e) {
                console.log('Couldn\'t get the readme of repository ' + repo_1.repoName + ' at path ' + config.readme + '. Reason: The readme file location provided in the config file doesn\'t exist. Error message: ' + String(e));
                reject();
            });
        }).catch(function (e) {
            if (hasStatus(e) && e.status === 404) {
                // No config file, try usual locations
                tryLocations(resolve, reject, ['readme.txt', 'plugin/readme.txt']);
            }
            else {
                console.log('Couldn\'t get the config file of repository ' + repo_1.repoName + '. Reason: Unknown error when fetching config file. Error message: ' + String(e));
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
                    console.log('Repository ' + repo_1.repoName + ' doesn\'t have a valid readme.');
                    return;
                }
                const version = matches.pop();
                if (!version) {
                    console.log('Repository ' + repo_1.repoName + ' doesn\'t have a valid readme.');
                    return;
                }
                if (compare_versions_1.default.compare(version, latest, '<')) {
                    outdated(version, latest);
                }
                else {
                    upToDate();
                }
                return;
            }
        }
        console.log('Repository ' + repo_1.repoName + ' doesn\'t have a valid readme.');
    }).catch(function () {
        console.log('Couldn\'t check repository ' + repo_1.repoName + '.');
    });
}
function run() {
    const options = {
        host: 'api.wordpress.org',
        path: '/core/stable-check/1.0/'
    };
    https.get(options, function (response) {
        if (response.statusCode !== 200) {
            console.log('Failed to fetch latest WordPress version. Request status code: ' + String(response.statusCode));
            return;
        }
        response.setEncoding('utf8');
        let rawData = '';
        response.on('data', (chunk) => { rawData += chunk; });
        response.on('end', () => {
            let list = {};
            try {
                list = JSON.parse(rawData);
            }
            catch (e) {
                console.log('Failed to fetch latest WordPress version. Exception: ' + e.message);
                return;
            }
            let latest = Object.keys(list).find((key) => list[key] === 'latest');
            if (!latest) {
                console.log('Failed to fetch latest WordPress version. Couldn\'t find latest version');
                return;
            }
            latest = latest.split('.').slice(0, 2).join('.'); // Discard patch version
            checkRepo(latest);
        });
    }).on('error', function (e) {
        console.log('Failed to fetch latest WordPress version. Exception: ' + e.message);
    });
}
run();
