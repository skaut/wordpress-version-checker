"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConfigError = void 0;
const WPVCError_1 = require("./WPVCError");
class ConfigError extends WPVCError_1.WPVCError {
    constructor(e) {
        super("Couldn't get the wordpress-version-checker config file. Error message: " +
            e);
    }
}
exports.ConfigError = ConfigError;
