"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExistingIssueFormatError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
class ExistingIssueFormatError extends ts_custom_error_1.CustomError {
    constructor(issueNumber) {
        super('The existing issue #' + String(issueNumber) + ' doesn\'t have the correct format.');
    }
}
exports.ExistingIssueFormatError = ExistingIssueFormatError;
