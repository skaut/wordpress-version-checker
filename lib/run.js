"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.run = void 0;
const compare_versions_1 = __importDefault(require("compare-versions"));
const core = __importStar(require("@actions/core"));
const issue_management_1 = require("./issue-management");
const latest_version_1 = require("./latest-version");
const tested_version_1 = require("./tested-version");
const wpvc_config_1 = require("./wpvc-config");
function outdated(config, testedVersion, latestVersion) {
    return __awaiter(this, void 0, void 0, function* () {
        const existingIssue = yield (0, issue_management_1.getIssue)();
        if (existingIssue !== null) {
            yield (0, issue_management_1.updateIssue)(existingIssue, testedVersion, latestVersion);
        }
        else {
            yield (0, issue_management_1.createIssue)(config, testedVersion, latestVersion);
        }
    });
}
function upToDate() {
    return __awaiter(this, void 0, void 0, function* () {
        const existingIssue = yield (0, issue_management_1.getIssue)();
        if (existingIssue !== null) {
            yield (0, issue_management_1.closeIssue)(existingIssue);
        }
    });
}
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const config = yield (0, wpvc_config_1.WPVCConfig)();
            const readmeVersion = yield (0, tested_version_1.testedVersion)(config);
            const latestVersion = yield (0, latest_version_1.latestWordPressVersion)();
            if (compare_versions_1.default.compare(readmeVersion, latestVersion, "<")) {
                yield outdated(config, readmeVersion, latestVersion);
            }
            else {
                yield upToDate();
            }
        }
        catch (e) {
            core.setFailed(e.message);
        }
    });
}
exports.run = run;
