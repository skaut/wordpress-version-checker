"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GetIssueError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
const repo_1 = require("../repo");
class GetIssueError extends ts_custom_error_1.CustomError {
    constructor(e) {
        super('Couldn\'t get existing issue for repository ' + repo_1.repoName + '. Error message: ' + String(e));
    }
}
exports.GetIssueError = GetIssueError;
