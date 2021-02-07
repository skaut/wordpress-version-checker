"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssueCreationError = void 0;
const WPVCError_1 = require("./WPVCError");
class IssueCreationError extends WPVCError_1.WPVCError {
    constructor(e) {
        super('Couldn\'t create an issue. Error message: ' + e);
    }
}
exports.IssueCreationError = IssueCreationError;
