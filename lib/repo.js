"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.repo = void 0;
const ActionError_1 = require("./exceptions/ActionError");
let repoInstance = undefined;
function repo() {
    if (repoInstance === undefined) {
        if (process.env.GITHUB_REPOSITORY === undefined) {
            throw new ActionError_1.ActionError('No "GITHUB_REPOSITORY" environment variable found');
        }
        const split = process.env.GITHUB_REPOSITORY.split("/");
        if (split.length !== 2) {
            throw new ActionError_1.ActionError('The "GITHUB_REPOSITORY" environment variable is not in the correct format');
        }
        repoInstance = {
            owner: split[0],
            repo: split[1],
        };
    }
    return repoInstance;
}
exports.repo = repo;
