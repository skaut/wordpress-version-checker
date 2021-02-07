"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConfigError = void 0;
const ts_custom_error_1 = require("ts-custom-error");
const repo_1 = require("../repo");
class ConfigError extends ts_custom_error_1.CustomError {
    constructor(e) {
        super('Couldn\'t get the config file of repository ' + repo_1.repoName + '. Exception: ' + e);
    }
}
exports.ConfigError = ConfigError;
