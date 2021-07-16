"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.clearWebSocketCookie = exports.clearCredentialrefCookie = exports.setWebSocketCookie = exports.setCredentialrefCookie = exports.webSocketCookieKey = exports.credentialrefCookieKey = void 0;
exports.credentialrefCookieKey = 'tw_credentialref';
const credentialrefCookieKeyMaxAge = 365 * 24 * 60 * 60 * 1000;
exports.webSocketCookieKey = 'tw_ws';
const webSocketCookieKeyMaxAge = 365 * 24 * 60 * 60 * 1000;
const setCookie = (cookieKey, maxAge) => (reply, value) => reply.setCookie(cookieKey, value, {
    maxAge,
    signed: true,
    httpOnly: true,
    path: '/',
    sameSite: 'strict',
    secure: true,
});
exports.setCredentialrefCookie = setCookie(exports.credentialrefCookieKey, credentialrefCookieKeyMaxAge);
exports.setWebSocketCookie = setCookie(exports.webSocketCookieKey, webSocketCookieKeyMaxAge);
const clearCookie = (cookieKey) => (reply) => reply.clearCookie(cookieKey);
exports.clearCredentialrefCookie = clearCookie(exports.credentialrefCookieKey);
exports.clearWebSocketCookie = clearCookie(exports.credentialrefCookieKey);
//# sourceMappingURL=cookies.js.map