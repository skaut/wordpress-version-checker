"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssueListError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
class IssueListError extends ts_custom_error_1.CustomError {
    constructor(e) {
        super('Couldn\'t list issues. Error message: ' + e);
    }
}
exports.IssueListError = IssueListError;
