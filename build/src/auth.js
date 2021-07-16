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
exports.getWebsocketToken = exports.verifyWebsocketToken = exports.getCredentialref = exports.verifyCredentialref = void 0;
const Credentialrefs_1 = require("@server/entities/Credentialrefs");
const cookies_1 = require("@server/cookies");
const verifyCredentialref = (req, reply) => __awaiter(void 0, void 0, void 0, function* () {
    const signedCookie = req.cookies[cookies_1.credentialrefCookieKey];
    if (!signedCookie)
        throw new Error('Not authorized to interact with credential');
    const { valid, value: credentialrefId } = reply.unsignCookie(signedCookie);
    if (!valid)
        throw new Error('Cookie is invalid');
    if (!credentialrefId)
        throw new Error('Not authorized to interact with credential');
    const credentialref = yield Credentialrefs_1.Credentialrefs.getRepo().findOne({ where: { id: credentialrefId } });
    if (!credentialref)
        throw new Error('credential ref does not exist');
    req.credentialref = credentialref;
});
exports.verifyCredentialref = verifyCredentialref;
const getCredentialref = (req) => {
    const { credentialref } = req;
    if (typeof credentialref === 'undefined')
        throw new Error('Credential ref  not attached to request');
    return credentialref;
};
exports.getCredentialref = getCredentialref;
const verifyWebsocketToken = (req, reply) => __awaiter(void 0, void 0, void 0, function* () {
    const signedCookie = req.cookies[cookies_1.webSocketCookieKey];
    if (!signedCookie)
        throw new Error('No websocket token');
    const { valid, value: wsToken } = reply.unsignCookie(signedCookie);
    if (!valid)
        throw new Error('Cookie is invalid');
    if (!wsToken)
        throw new Error('No websocket token');
    req.wsToken = wsToken;
});
exports.verifyWebsocketToken = verifyWebsocketToken;
const getWebsocketToken = (req) => {
    const { wsToken } = req;
    if (typeof wsToken === 'undefined')
        throw new Error('Web socket token not attached to request');
    return wsToken;
};
exports.getWebsocketToken = getWebsocketToken;
//# sourceMappingURL=auth.js.map