"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var react_1 = __importDefault(require("react"));
var auth_1 = __importDefault(require("@aws-amplify/auth"));
var cognito_1 = require("./cognito");
var jsonwebtoken_1 = __importStar(require("jsonwebtoken"));
var base_64_1 = __importDefault(require("base-64"));
var AUTH_SYNC_KEY = "auth_sync_key";
// Notify other tabs after signing the user in/out
function sync(action) {
    localStorage.setItem(AUTH_SYNC_KEY, action);
}
exports.sync = sync;
function getMatchingPem(pems, token) {
    if (!token)
        return undefined;
    var config = auth_1.default.configure(null);
    if (!config.region || !config.userPoolId)
        return undefined;
    if (!pems[config.region])
        return undefined;
    if (!pems[config.region][config.userPoolId])
        return undefined;
    var header = JSON.parse(base_64_1.default.decode(token.split(".")[0]));
    return pems[config.region][config.userPoolId][header.kid];
}
function verifyToken(_a) {
    var pems = _a.pems, token = _a.token, validate = _a.validate;
    if (!token)
        return null;
    try {
        var pem = getMatchingPem(pems, token);
        if (!pem)
            return null;
        var data = jsonwebtoken_1.default.verify(token, pem, { algorithms: ["RS256"] });
        if (!data)
            return null;
        if (validate ? !validate(data) : false)
            return null;
        return data;
    }
    catch (e) {
        if (!(e instanceof jsonwebtoken_1.TokenExpiredError)) {
            console.log(e);
        }
        return null;
    }
}
function getAuthFromCookies(pems, cookie) {
    if (!cookie)
        return null;
    var userPoolWebClientId = auth_1.default.configure(null).userPoolWebClientId;
    var _a = cognito_1.getCognitoCookieInfo(cookie, userPoolWebClientId), idToken = _a.idToken, accessToken = _a.accessToken;
    if (!idToken || !accessToken)
        return null;
    var idTokenData = verifyToken({
        pems: pems,
        token: idToken,
        validate: function (data) { return data.aud === userPoolWebClientId; },
    });
    var accessTokenData = verifyToken({
        pems: pems,
        token: accessToken,
        validate: function (data) { return data.client_id === userPoolWebClientId; },
    });
    if (!idTokenData || !accessTokenData)
        return null;
    return { accessTokenData: accessTokenData, idTokenData: idTokenData, idToken: idToken, accessToken: accessToken };
}
function createGetServerSideAuth(_a) {
    var pems = _a.pems;
    return function getServerSideAuth(req) {
        return getAuthFromCookies(pems, req.headers.cookie);
    };
}
exports.createGetServerSideAuth = createGetServerSideAuth;
// auto-login in case auth cookies have been added
function useAutoLogin(auth, userPoolWebClientId) {
    if (!userPoolWebClientId)
        // To fix this issue, call
        // Amplify.configure({ Auth: { userPoolWebClientId: <userPoolClientId> } })
        throw new Error("Missing configuration value for userPoolWebClientId in Amplify's Auth");
    // check on window activation
    react_1.default.useEffect(function () {
        // use localStorage to sync auth state across tabs
        var storageListener = function (event) {
            // When event is unrelated, or when sync key was cleared
            if (event.key !== AUTH_SYNC_KEY || event.newValue === null)
                return;
            // clear localStorage item since we only needed it to sync across tabs
            localStorage.removeItem(AUTH_SYNC_KEY);
            var idToken = cognito_1.getCognitoCookieInfo(document.cookie, userPoolWebClientId).idToken;
            // login when user was not signed in before, or when the idToken changed
            if (idToken && (!auth || auth.idToken !== idToken)) {
                // do not log in on the token page since we could be loading
                // the cookies currently
                var pathname = window.location.pathname;
                if (pathname === "/token" || pathname.startsWith("/token/"))
                    return;
                window.location.reload();
            }
        };
        // check on write to localStorage
        window.addEventListener("storage", storageListener);
        return function () {
            window.removeEventListener("storage", storageListener);
        };
    }, [auth]);
}
function useAutoLogout(auth, userPoolWebClientId) {
    if (!userPoolWebClientId)
        // To fix this issue, call
        // Amplify.configure({ Auth: { userPoolWebClientId: <userPoolClientId> } })
        throw new Error("Missing configuration value for userPoolWebClientId in Amplify's Auth");
    var isAuthenticated = Boolean(auth);
    // auto-logout in case loginsub cookie has been removed
    react_1.default.useEffect(function () {
        var listener = function () {
            var idToken = cognito_1.getCognitoCookieInfo(document.cookie, userPoolWebClientId).idToken;
            // User signed out locally, but server-side props still contain cookies.
            // This means the user signed out through a different tab.
            if (!idToken && isAuthenticated) {
                // do not log out on the token page since we could be loading
                // the cookies currently
                var pathname = window.location.pathname;
                if (pathname === "/token" || pathname.startsWith("/token/"))
                    return;
                if (idToken) {
                    // user signed out through another another application, so sign
                    // user out completely to remove all auth cookies
                    var redirectAfterSignOut = window.location.href;
                    // Reconfigure oauth to add the uri of the page which should open
                    // after the sign out
                    //
                    // Calling Auth.configure with null returns the current config
                    var config = auth_1.default.configure(null);
                    auth_1.default.configure({ oauth: __assign(__assign({}, config.oauth), { redirectAfterSignOut: redirectAfterSignOut }) });
                    auth_1.default.signOut();
                }
                else {
                    // user signed out through another tab, so reload to
                    // refresh server-side props
                    window.location.reload();
                }
            }
        };
        window.addEventListener("focus", listener);
        // check on write to localStorage
        window.addEventListener("storage", listener);
        return function () {
            window.removeEventListener("focus", listener);
            window.removeEventListener("storage", listener);
        };
    }, [isAuthenticated]);
}
// TODO sync this across multiple invocations?
// If you are using server-side rendering, pass "initialAuth" to this hook.
// If you are using static rendering, pass "null” to this hook.
//
// This hook is expected to be only called once per page at the moment.
// Pass the auth-state down to components using props if they need it.
function createUseAuth(_a) {
    var pems = _a.pems;
    return function useAuth(initialAuth) {
        var _a = react_1.default.useState(initialAuth), auth = _a[0], setAuth = _a[1];
        var userPoolWebClientId = auth_1.default.configure(null).userPoolWebClientId;
        useAutoLogin(auth, userPoolWebClientId);
        useAutoLogout(auth, userPoolWebClientId);
        react_1.default.useEffect(function () {
            // When there is a cookie, this takes ~100ms since it's verifying the cookie
            // When we decode only, it goes down to ~5ms.
            //
            // To speed up the client-side renders, we could decode only on the client.
            // But we'd probably need to verify the timestamp anyhow?
            //
            // Note that getAuthFromCookies also runs on the server, so improvements
            // can not have caching-problems.
            var cookieAuth = getAuthFromCookies(pems, document.cookie);
            setAuth(cookieAuth);
        }, []);
        return auth;
    };
}
exports.createUseAuth = createUseAuth;
function useAuthFunctions() {
    var login = react_1.default.useCallback(function () { return auth_1.default.federatedSignIn(); }, []);
    var logout = react_1.default.useCallback(function () { return auth_1.default.signOut().then(function (res) { return sync("logout"); }); }, []);
    return { login: login, logout: logout };
}
exports.useAuthFunctions = useAuthFunctions;
// When a user comes back from authenticating, the url looks like this:
//   /token#id_token=....
// At this point, there will be no cookies yet. If we would render any page on
// the server now, it would seem as-if the user is not authenticated yet.
//
// We therefore wait until Amplify has set its cookies. It does this
// automatically because the id_token hash is present. Then we redirect the
// user back to the main page. That page can now use SSR as the user will have
// the necessary cookies ready.
function useAuthRedirect(onToken) {
    var _a = react_1.default.useState(false), triggeredReload = _a[0], setTriggeredReload = _a[1];
    react_1.default.useEffect(function () {
        // only check when #id_token is in the hash, otherwise cookies can't appear
        // anyways
        if (triggeredReload)
            return;
        if (!window.location.hash.includes("id_token=") && !window.location.search.includes("code=")) {
            onToken(null);
            return;
        }
        function refreshOnAuthCookies() {
            if (triggeredReload)
                return;
            var userPoolWebClientId = auth_1.default.configure(null).userPoolWebClientId;
            var cognitoCookieInfo = cognito_1.getCognitoCookieInfo(document.cookie, userPoolWebClientId);
            if (cognitoCookieInfo.idToken) {
                setTriggeredReload(true);
                sync("login");
                onToken(cognitoCookieInfo.idToken);
            }
        }
        refreshOnAuthCookies();
        var interval = setInterval(refreshOnAuthCookies, 100);
        return function () {
            clearInterval(interval);
        };
    }, [triggeredReload, setTriggeredReload, onToken]);
    return null;
}
exports.useAuthRedirect = useAuthRedirect;
