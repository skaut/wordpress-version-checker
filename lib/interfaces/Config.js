"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isConfig = void 0;
function isConfig(config) {
    if (!config.readme) {
        return false;
    }
    return true;
}
exports.isConfig = isConfig;
