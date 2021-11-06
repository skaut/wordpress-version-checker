"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.octokit = void 0;
const action_1 = require("@octokit/action");
let octokitInstance = undefined;
function octokit() {
    if (octokitInstance === undefined) {
        octokitInstance = new action_1.Octokit();
    }
    return octokitInstance;
}
exports.octokit = octokit;
