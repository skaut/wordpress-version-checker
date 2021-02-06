"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.updateIssue = exports.createIssue = void 0;
const compare_versions_1 = __importDefault(require("compare-versions"));
const octokit_1 = require("./octokit");
const repo_1 = require("./repo");
function issueBody(testedVersion, latestVersion) {
    return 'There is a new WordPress version that the plugin hasn\'t been tested with. Please test it and then change the "Tested up to" field in the plugin readme.\n\n**Tested up to:** ' + testedVersion + '\n**Latest version:** ' + latestVersion + '\n\nThis issue will be closed automatically when the versions match.';
}
function createIssue(testedVersion, latestVersion) {
    const args = Object.assign(Object.assign({}, repo_1.repo), { title: "The plugin hasn't been tested with the latest version of WordPress", body: issueBody(testedVersion, latestVersion), labels: ['wpvc'] });
    octokit_1.octokit.issues.create(args).catch(function (e) {
        console.log('Couldn\'t create an issue for repository ' + repo_1.repoName + '. Error message: ' + String(e));
    });
}
exports.createIssue = createIssue;
function updateIssue(issue, testedVersion, latestVersion) {
    octokit_1.octokit.issues.get(Object.assign(Object.assign({}, repo_1.repo), { issue_number: issue })).then(function (result) {
        const matchingLine = result.data.body.split('\r\n').find(function (line) {
            return line.startsWith('**Latest version:**');
        });
        if (!matchingLine) {
            console.log('Existing issue for repository ' + repo_1.repoName + ' doesn\'t have the correct format.');
            return;
        }
        const latestVersionInIssue = matchingLine.slice(20);
        if (compare_versions_1.default.compare(latestVersionInIssue, latestVersion, '<')) {
            octokit_1.octokit.issues.update(Object.assign(Object.assign({}, repo_1.repo), { issue_number: issue, body: issueBody(testedVersion, latestVersion) })).catch(function (e) {
                console.log('Couldn\'t update existing issue for repository ' + repo_1.repoName + '. Error message: ' + String(e));
            });
        }
    }).catch(function (e) {
        console.log('Couldn\'t get existing issue for repository ' + repo_1.repoName + '. Error message: ' + String(e));
    });
}
exports.updateIssue = updateIssue;
