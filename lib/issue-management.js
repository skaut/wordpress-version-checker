"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.updateIssue = exports.createIssue = void 0;
const compare_versions_1 = __importDefault(require("compare-versions"));
const octokit_1 = require("./octokit");
const repo_1 = require("./repo");
const ExistingIssueFormatError_1 = require("./exceptions/ExistingIssueFormatError");
const GetIssueError_1 = require("./exceptions/GetIssueError");
const IssueCreationError_1 = require("./exceptions/IssueCreationError");
const IssueUpdateError_1 = require("./exceptions/IssueUpdateError");
function issueBody(testedVersion, latestVersion) {
    return 'There is a new WordPress version that the plugin hasn\'t been tested with. Please test it and then change the "Tested up to" field in the plugin readme.\n' +
        '\n' +
        '**Tested up to:** ' + testedVersion + '\n' +
        '**Latest version:** ' + latestVersion + '\n' +
        '\n' +
        'This issue will be closed automatically when the versions match.';
}
function createIssue(testedVersion, latestVersion) {
    return __awaiter(this, void 0, void 0, function* () {
        yield octokit_1.octokit.issues.create(Object.assign(Object.assign({}, repo_1.repo), { title: "The plugin hasn't been tested with the latest version of WordPress", body: issueBody(testedVersion, latestVersion), labels: ['wpvc'] })).catch(function (e) {
            throw new IssueCreationError_1.IssueCreationError(String(e));
        });
    });
}
exports.createIssue = createIssue;
function updateIssue(issueNumber, testedVersion, latestVersion) {
    return __awaiter(this, void 0, void 0, function* () {
        const issue = yield octokit_1.octokit.issues.get(Object.assign(Object.assign({}, repo_1.repo), { issue_number: issueNumber })).catch(function (e) {
            throw new GetIssueError_1.GetIssueError(issueNumber, String(e));
        });
        const matchingLine = issue.data.body.split('\r\n').find(function (line) {
            return line.startsWith('**Latest version:**');
        });
        if (!matchingLine) {
            throw new ExistingIssueFormatError_1.ExistingIssueFormatError(issueNumber);
        }
        const latestVersionInIssue = matchingLine.slice(20);
        if (compare_versions_1.default.compare(latestVersionInIssue, latestVersion, '<')) {
            octokit_1.octokit.issues.update(Object.assign(Object.assign({}, repo_1.repo), { issue_number: issueNumber, body: issueBody(testedVersion, latestVersion) })).catch(function (e) {
                throw new IssueUpdateError_1.IssueUpdateError(issueNumber, String(e));
            });
        }
    });
}
exports.updateIssue = updateIssue;
