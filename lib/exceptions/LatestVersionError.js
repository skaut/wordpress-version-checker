"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LatestVersionError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
class LatestVersionError extends ts_custom_error_1.CustomError {
    constructor(e) {
        if (!e) {
            super('Failed to fetch the latest WordPress version.');
        }
        else {
            super('Failed to fetch the latest WordPress version. Error message: ' + e);
        }
    }
}
exports.LatestVersionError = LatestVersionError;
