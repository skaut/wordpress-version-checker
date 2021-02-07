"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GetIssueError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
class GetIssueError extends ts_custom_error_1.CustomError {
    constructor(issueNumber, e) {
        super('Couldn\'t get the already existing issue #' + String(issueNumber) + '. Error message: ' + e);
    }
}
exports.GetIssueError = GetIssueError;
