"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GetIssueError = void 0;
const WPVCError_1 = require("./WPVCError");
class GetIssueError extends WPVCError_1.WPVCError {
    constructor(issueNumber, e) {
        super('Couldn\'t get the already existing issue #' + String(issueNumber) + '. Error message: ' + e);
    }
}
exports.GetIssueError = GetIssueError;
