"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExistingIssueFormatError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
const repo_1 = require("../repo");
class ExistingIssueFormatError extends ts_custom_error_1.CustomError {
    constructor() {
        super('Existing issue for repository ' + repo_1.repoName + ' doesn\'t have the correct format.');
    }
}
exports.ExistingIssueFormatError = ExistingIssueFormatError;
