"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssueUpdateError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
class IssueUpdateError extends ts_custom_error_1.CustomError {
    constructor(issueNumber, e) {
        super('Couldn\'t update the existing issue #' + String(issueNumber) + '. Error message: ' + e);
    }
}
exports.IssueUpdateError = IssueUpdateError;
