"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.octokit = void 0;
const auth_action_1 = require("@octokit/auth-action");
const octokit_1 = require("octokit");
let octokitInstance = undefined;
function octokit() {
    if (octokitInstance === undefined) {
        octokitInstance = new octokit_1.Octokit({ auth: auth_action_1.createActionAuth });
    }
    return octokitInstance;
}
exports.octokit = octokit;
