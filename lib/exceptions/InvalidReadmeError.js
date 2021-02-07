"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidReadmeError = void 0;
const WPVCError_1 = require("./WPVCError");
class InvalidReadmeError extends WPVCError_1.WPVCError {
    constructor() {
        super('The repository has an invalid readme.');
    }
}
exports.InvalidReadmeError = InvalidReadmeError;
