"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssueCreationError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
class IssueCreationError extends ts_custom_error_1.CustomError {
    constructor(e) {
        super('Couldn\'t create an issue. Error message: ' + e);
    }
}
exports.IssueCreationError = IssueCreationError;
