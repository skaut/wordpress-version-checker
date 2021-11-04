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
exports.testedVersion = void 0;
const octokit_1 = require("./octokit");
const repo_1 = require("./repo");
const has_status_1 = require("./has-status");
const ConfigError_1 = require("./exceptions/ConfigError");
const InvalidReadmeError_1 = require("./exceptions/InvalidReadmeError");
function readme(config) {
    return __awaiter(this, void 0, void 0, function* () {
        let readmeLocations = ["readme.txt", "plugin/readme.txt"];
        if (config !== null) {
            readmeLocations = [config.readme];
        }
        for (const readmeLocation of readmeLocations) {
            const result = yield (0, octokit_1.octokit)()
                .rest.repos.getContent(Object.assign(Object.assign({}, (0, repo_1.repo)()), { path: readmeLocation }))
                .catch(function (e) {
                if ((0, has_status_1.hasStatus)(e) && e.status === 404) {
                    return null;
                }
                else {
                    throw new ConfigError_1.ConfigError("No config file was found in repo and all usual locations were exhausted. Error message: " +
                        String(e));
                }
            });
            if (result === null) {
                continue;
            }
            const encodedContent = result.data.content;
            if (encodedContent === undefined) {
                throw new ConfigError_1.ConfigError("No config file was found in repo and all usual locations were exhausted.");
            }
            return Buffer.from(encodedContent, "base64").toString();
        }
        throw new ConfigError_1.ConfigError("No config file was found in repo and all usual locations were exhausted.");
    });
}
function testedVersion(config) {
    return __awaiter(this, void 0, void 0, function* () {
        const readmeContents = yield readme(config);
        for (const line of readmeContents.split("\n")) {
            if (!line.startsWith("Tested up to:")) {
                continue;
            }
            const matches = line.match(/[^:\s]+/g);
            if (!matches) {
                throw new InvalidReadmeError_1.InvalidReadmeError();
            }
            const version = matches.pop();
            if (version === undefined) {
                throw new InvalidReadmeError_1.InvalidReadmeError();
            }
            return version;
        }
        throw new InvalidReadmeError_1.InvalidReadmeError();
    });
}
exports.testedVersion = testedVersion;
