"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LatestVersionError = void 0;
const WPVCError_1 = require("./WPVCError");
class LatestVersionError extends WPVCError_1.WPVCError {
    constructor(e) {
        if (e === undefined) {
            super("Failed to fetch the latest WordPress version.");
        }
        else {
            super("Failed to fetch the latest WordPress version. Error message: " + e);
        }
    }
}
exports.LatestVersionError = LatestVersionError;
