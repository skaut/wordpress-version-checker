"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssueListError = void 0;
const WPVCError_1 = require("./WPVCError");
class IssueListError extends WPVCError_1.WPVCError {
    constructor(e) {
        super('Couldn\'t list issues. Error message: ' + e);
    }
}
exports.IssueListError = IssueListError;
