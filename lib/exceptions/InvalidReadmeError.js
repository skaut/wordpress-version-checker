"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidReadmeError = void 0;
const WPVCError_1 = require("./WPVCError");
class InvalidReadmeError extends WPVCError_1.WPVCError {
    constructor(e) {
        super("Couldn't get the repository readme. Error message: " + e);
    }
}
exports.InvalidReadmeError = InvalidReadmeError;
