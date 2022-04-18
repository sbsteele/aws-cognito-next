"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var cookie_1 = __importDefault(require("cookie"));
var unauthenticatedCookies = {
    lastUser: null,
    idToken: null,
    accessToken: null,
};
// use same algorithm as js-cookie which is used in aws-amplify/auth@4.20
function userIdToTokenKey(key) {
    return encodeURIComponent(key)
        .replace(/%(2[346B]|5E|60|7C)/g, decodeURIComponent)
        .replace(/[()]/g, escape);
}
// returns all auth cookies
function getCognitoCookieInfo(cookieString, userPoolWebClientId) {
    if (!userPoolWebClientId)
        // To fix this issue, call
        // Amplify.configure({ Auth: { userPoolWebClientId: <userPoolClientId> } })
        throw new Error("Missing configuration value for userPoolWebClientId in Amplify's Auth");
    if (!cookieString)
        return unauthenticatedCookies;
    var cookieData = cookie_1.default.parse(cookieString);
    var prefix = "CognitoIdentityServiceProvider." + userPoolWebClientId;
    var lastUserKey = prefix + ".LastAuthUser";
    var lastUser = cookieData[lastUserKey] ? cookieData[lastUserKey] : null;
    var idTokenKey = lastUser
        ? prefix + "." + userIdToTokenKey(lastUser) + ".idToken"
        : null;
    var idToken = idTokenKey && cookieData[idTokenKey] ? cookieData[idTokenKey] : null;
    var accessTokenKey = lastUser
        ? prefix + "." + userIdToTokenKey(lastUser) + ".accessToken"
        : null;
    var accessToken = accessTokenKey && cookieData[accessTokenKey]
        ? cookieData[accessTokenKey]
        : null;
    return { lastUser: lastUser, idToken: idToken, accessToken: accessToken };
}
exports.getCognitoCookieInfo = getCognitoCookieInfo;
