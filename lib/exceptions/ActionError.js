"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ActionError = void 0;
const WPVCError_1 = require("./WPVCError");
class ActionError extends WPVCError_1.WPVCError {
    constructor(e) {
        super("Couldn't run the wordpress-version-checker action. Error message: " + e);
    }
}
exports.ActionError = ActionError;
