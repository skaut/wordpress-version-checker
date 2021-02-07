"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WPVCError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
class WPVCError extends ts_custom_error_1.CustomError {
    constructor(e) {
        super(e);
    }
}
exports.WPVCError = WPVCError;
