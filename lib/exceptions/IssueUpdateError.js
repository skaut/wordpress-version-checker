"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssueUpdateError = void 0;
const WPVCError_1 = require("./WPVCError");
class IssueUpdateError extends WPVCError_1.WPVCError {
    constructor(issueNumber, e) {
        super("Couldn't update the existing issue #" +
            String(issueNumber) +
            ". Error message: " +
            e);
    }
}
exports.IssueUpdateError = IssueUpdateError;
