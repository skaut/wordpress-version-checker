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
const wpvc_config_1 = require("./wpvc-config");
const IssueListError_1 = require("./exceptions/IssueListError");
function outdated(config, testedVersion, latestVersion) {
    return __awaiter(this, void 0, void 0, function* () {
        const issues = yield octokit_1.octokit.rest.issues
            .listForRepo(Object.assign(Object.assign({}, repo_1.repo), { creator: "github-actions[bot]", labels: "wpvc" }))
            .catch((e) => {
            throw new IssueListError_1.IssueListError(String(e));
        });
        if (issues.data.length === 0) {
            yield issue_management_1.createIssue(config, testedVersion, latestVersion);
        }
        else {
            yield issue_management_1.updateIssue(issues.data[0].number, testedVersion, latestVersion);
        }
    });
}
function upToDate() {
    return __awaiter(this, void 0, void 0, function* () {
        const issues = yield octokit_1.octokit.rest.issues
            .listForRepo(Object.assign(Object.assign({}, repo_1.repo), { creator: "github-actions[bot]", labels: "wpvc" }))
            .catch((e) => {
            throw new IssueListError_1.IssueListError(String(e));
        });
        for (const issue of issues.data) {
            void octokit_1.octokit.rest.issues.update(Object.assign(Object.assign({}, repo_1.repo), { issue_number: issue.number, state: "closed" }));
        }
    });
}
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const config = yield wpvc_config_1.WPVCConfig();
            const readmeVersion = yield tested_version_1.testedVersion(config);
            const latestVersion = yield latest_version_1.latestWordPressVersion();
            if (compare_versions_1.default.compare(readmeVersion, latestVersion, "<")) {
                yield outdated(config, readmeVersion, latestVersion);
            }
            else {
                yield upToDate();
            }
        }
        catch (e) {
            console.log(e.message);
        }
    });
}
void run();
