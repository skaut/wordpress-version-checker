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
const compare_versions_1 = __importDefault(require("compare-versions"));
const octokit_1 = require("./octokit");
const repo_1 = require("./repo");
const issue_management_1 = require("./issue-management");
const latest_version_1 = require("./latest-version");
const tested_version_1 = require("./tested-version");
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
function checkRepo(latest) {
    return __awaiter(this, void 0, void 0, function* () {
        const testedVersion = yield tested_version_1.getTestedVersion();
        if (compare_versions_1.default.compare(testedVersion, latest, '<')) {
            outdated(testedVersion, latest);
        }
        else {
            upToDate();
        }
    });
}
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const latest = yield latest_version_1.latestWordPressVersion();
            yield checkRepo(latest);
        }
        catch (e) {
            console.log(e.message); // TODO
        }
    });
}
void run();
