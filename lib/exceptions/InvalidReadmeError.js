"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidReadmeError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
const repo_1 = require("../repo");
class InvalidReadmeError extends ts_custom_error_1.CustomError {
    constructor() {
        super('Repository ' + repo_1.repoName + ' doesn\'t have a valid readme.');
    }
}
exports.InvalidReadmeError = InvalidReadmeError;
