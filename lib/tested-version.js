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
exports.getTestedVersion = void 0;
const Config_1 = require("./interfaces/Config");
const octokit_1 = require("./octokit");
const repo_1 = require("./repo");
const ConfigError_1 = require("./exceptions/ConfigError");
const InvalidReadmeError_1 = require("./exceptions/InvalidReadmeError");
function hasStatus(obj) {
    return Object.prototype.hasOwnProperty.call(obj, "status");
}
function getWPVCConfig() {
    return __awaiter(this, void 0, void 0, function* () {
        const file = yield octokit_1.octokit.repos.getContent(Object.assign(Object.assign({}, repo_1.repo), { path: '.wordpress-version-checker.json' })).catch(function (e) {
            if (hasStatus(e) && e.status === 404) {
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
        if (!encodedContent) {
            throw new ConfigError_1.ConfigError('Failed to decode the file.');
        }
        let config = {};
        try {
            config = JSON.parse(Buffer.from(encodedContent, 'base64').toString());
        }
        catch (e) {
            throw new ConfigError_1.ConfigError(e.message);
        }
        if (!Config_1.isConfig(config)) {
            throw new ConfigError_1.ConfigError('Invalid config file.');
        }
        return config;
    });
}
function getReadme() {
    return __awaiter(this, void 0, void 0, function* () {
        let readmeLocations = ['readme.txt', 'plugin/readme.txt'];
        const config = yield getWPVCConfig();
        if (config !== null) {
            readmeLocations = [config.readme];
        }
        for (const readmeLocation of readmeLocations) {
            const result = yield octokit_1.octokit.repos.getContent(Object.assign(Object.assign({}, repo_1.repo), { path: readmeLocation })).catch(function (e) {
                if (hasStatus(e) && e.status === 404) {
                    return null;
                }
                else {
                    throw new ConfigError_1.ConfigError('No config file was found in repo and all usual locations were exhausted. Error message: ' + String(e));
                }
            });
            if (result === null) {
                continue;
            }
            const encodedContent = result.data.content;
            if (!encodedContent) {
                throw new ConfigError_1.ConfigError('No config file was found in repo and all usual locations were exhausted.');
            }
            return Buffer.from(encodedContent, 'base64').toString();
        }
        throw new ConfigError_1.ConfigError('No config file was found in repo and all usual locations were exhausted.');
    });
}
function getTestedVersion() {
    return __awaiter(this, void 0, void 0, function* () {
        const readme = yield getReadme();
        for (const line of readme.split('\n')) {
            if (!line.startsWith('Tested up to:')) {
                continue;
            }
            const matches = line.match(/[^:\s]+/g);
            if (!matches) {
                throw new InvalidReadmeError_1.InvalidReadmeError();
            }
            const version = matches.pop();
            if (!version) {
                throw new InvalidReadmeError_1.InvalidReadmeError();
            }
            return version;
        }
        throw new InvalidReadmeError_1.InvalidReadmeError();
    });
}
exports.getTestedVersion = getTestedVersion;
