"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssueListError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
const repo_1 = require("../repo");
class IssueListError extends ts_custom_error_1.CustomError {
    constructor(e) {
        super('Couldn\'t list repository issues for repository ' + repo_1.repoName + '. Error message: ' + e);
    }
}
exports.IssueListError = IssueListError;
