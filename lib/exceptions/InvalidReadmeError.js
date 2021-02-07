"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidReadmeError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
class InvalidReadmeError extends ts_custom_error_1.CustomError {
    constructor() {
        super('The repository has an invalid readme.');
    }
}
exports.InvalidReadmeError = InvalidReadmeError;
