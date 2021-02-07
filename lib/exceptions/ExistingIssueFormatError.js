"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExistingIssueFormatError = void 0;
const WPVCError_1 = require("./WPVCError");
class ExistingIssueFormatError extends WPVCError_1.WPVCError {
    constructor(issueNumber) {
        super("The existing issue #" +
            String(issueNumber) +
            " doesn't have the correct format.");
    }
}
exports.ExistingIssueFormatError = ExistingIssueFormatError;
