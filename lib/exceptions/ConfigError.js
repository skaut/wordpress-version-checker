"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConfigError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
class ConfigError extends ts_custom_error_1.CustomError {
    constructor(e) {
        super('Couldn\'t get the wordpress-version-checker config file. Error message: ' + e);
    }
}
exports.ConfigError = ConfigError;
