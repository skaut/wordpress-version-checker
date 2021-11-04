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
Object.defineProperty(exports, "__esModule", { value: true });
exports.latestWordPressVersion = void 0;
const https = __importStar(require("https"));
const LatestVersionError_1 = require("./exceptions/LatestVersionError");
function httpsRequest(options) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise(function (resolve, reject) {
            https
                .get(options, function (response) {
                let data = "";
                response.setEncoding("utf8");
                response.on("data", (chunk) => {
                    data += chunk;
                });
                response.on("end", function () {
                    if (response.statusCode === 200) {
                        resolve(data);
                    }
                    else {
                        reject();
                    }
                });
            })
                .on("error", (e) => {
                reject(e);
            });
        });
    });
}
function latestWordPressVersion() {
    return __awaiter(this, void 0, void 0, function* () {
        const rawData = yield httpsRequest({
            host: "api.wordpress.org",
            path: "/core/stable-check/1.0/",
        }).catch(function (e) {
            throw new LatestVersionError_1.LatestVersionError(e);
        });
        let list = {};
        try {
            list = JSON.parse(rawData);
        }
        catch (e) {
            throw new LatestVersionError_1.LatestVersionError(e.message);
        }
        const latest = Object.keys(list).find((key) => list[key] === "latest");
        if (latest === undefined) {
            throw new LatestVersionError_1.LatestVersionError("Couldn't find the latest version");
        }
        return latest.split(".").slice(0, 2).join("."); // Discard patch version
    });
}
exports.latestWordPressVersion = latestWordPressVersion;
