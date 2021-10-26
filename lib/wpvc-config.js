"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.WPVCConfig = void 0;
const octokit_1 = require("./octokit");
const repo_1 = require("./repo");
const has_status_1 = require("./has-status");
const ConfigError_1 = require("./exceptions/ConfigError");
function isConfig(config) {
    if ("readme" in config) {
        return true;
    }
    return false;
}
function WPVCConfig() {
    return __awaiter(this, void 0, void 0, function* () {
        const file = yield octokit_1.octokit.rest.repos
            .getContent(Object.assign(Object.assign({}, repo_1.repo), { path: ".wordpress-version-checker.json" }))
            .catch(function (e) {
            if ((0, has_status_1.hasStatus)(e) && e.status === 404) {
                return null;
            }
            else {
                throw new ConfigError_1.ConfigError(String(e));
            }
        });
        if (file === null) {
            return null;
        }
        const encodedContent = file.data.content;
        if (encodedContent === undefined) {
            throw new ConfigError_1.ConfigError("Failed to decode the file.");
        }
        let config = {};
        try {
            config = JSON.parse(Buffer.from(encodedContent, "base64").toString());
        }
        catch (e) {
            throw new ConfigError_1.ConfigError(e.message);
        }
        if (!isConfig(config)) {
            throw new ConfigError_1.ConfigError("Invalid config file.");
        }
        return config;
    });
}
exports.WPVCConfig = WPVCConfig;
